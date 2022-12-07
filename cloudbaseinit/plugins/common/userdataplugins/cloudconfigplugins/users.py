# Copyright 2019 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import datetime
import os
import pytz
import six

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common.userdataplugins.cloudconfigplugins import (
    base
)

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class UsersPlugin(base.BaseCloudConfigPlugin):
    """Creates users given in the cloud-config format."""

    def _get_groups(self, data):
        """Retuns all the group names that the user should be added to.

        :rtype: list
        """
        groups = data.get('groups', None)
        primary_group = data.get('primary_group', None)
        user_groups = []
        if isinstance(groups, six.string_types):
                user_groups.extend(groups.split(', '))
        elif isinstance(groups, (list, tuple)):
                user_groups.extend(groups)
        if isinstance(primary_group, six.string_types):
                user_groups.extend(primary_group.split(', '))
        elif isinstance(primary_group, (list, tuple)):
                user_groups.extend(primary_group)
        return user_groups

    def _get_password(self, data, osutils):
        password = data.get('passwd', None)
        max_size = osutils.get_maximum_password_length()

        if password and len(password) > max_size:
            raise Exception("Password has more than %d characters" % max_size)

        if not password:
            password = osutils.generate_random_password(
                CONF.user_password_length)

        return password

    def _get_expire_interval(self, data):
        expiredate = data.get('expiredate', None)
        expire_interval = None

        if isinstance(expiredate, six.string_types):
            year, month, day = map(int, expiredate.split('-'))
            expiredate = datetime.datetime(year=year, month=month, day=day,
                                           tzinfo=pytz.utc)
            # Py2.7 does not support timestamps, this is the
            # only way to compute the seconds passed since the unix epoch
            unix_time = datetime.datetime(year=1970, month=1, day=1,
                                          tzinfo=pytz.utc)
            expire_interval = (expiredate - unix_time).total_seconds()

        return expire_interval

    @staticmethod
    def _create_user_logon(user_name, password, osutils):
        try:
            token = osutils.create_user_logon_session(user_name,
                                                      password)
            osutils.close_user_logon_session(token)
        except Exception:
            LOG.exception('Cannot create a user logon session for user: "%s"',
                          user_name)

    @staticmethod
    def _set_ssh_public_keys(user_name, public_keys, osutils):
        user_home = osutils.get_user_home(user_name)
        if not user_home:
            raise exception.CloudbaseInitException("User profile not found!")

        user_ssh_dir = os.path.join(user_home, '.ssh')
        if not os.path.exists(user_ssh_dir):
            os.makedirs(user_ssh_dir)

        authorized_keys_path = os.path.join(user_ssh_dir, "authorized_keys")
        LOG.info("Writing SSH public keys in: %s" % authorized_keys_path)
        with open(authorized_keys_path, 'w') as f:
            for public_key in public_keys:
                f.write(public_key + "\n")

    def _create_user(self, item, osutils):
            user_name = item.get('name', None)
            password = self._get_password(item, osutils)
            user_full_name = item.get('gecos', None)
            user_expire_interval = self._get_expire_interval(item)
            user_disabled = item.get('inactive', False)

            public_keys = item.get('ssh_authorized_keys', [])
            should_create_home = (public_keys or
                                  not item.get('no_create_home', False))
            if user_disabled and should_create_home:
                raise exception.CloudbaseInitException(
                    "The user is required to be enabled if public_keys "
                    "or create_home are set")

            groups = self._get_groups(item)

            if osutils.user_exists(user_name):
                LOG.warning("User '%s' already exists " % user_name)
                osutils.set_user_password(user_name, password)
            else:
                osutils.create_user(user_name, password)

            osutils.set_user_info(user_name, full_name=user_full_name,
                                  expire_interval=user_expire_interval,
                                  disabled=user_disabled)

            for group in groups:
                try:
                    osutils.add_user_to_local_group(user_name, group)
                except Exception:
                    LOG.exception('Cannot add user "%s" to group "%s"' %
                                  (user_name, group))

            if not user_disabled and should_create_home:
                self._create_user_logon(user_name, password, osutils)

            if public_keys:
                self._set_ssh_public_keys(user_name, public_keys, osutils)

    def process(self, data):
        """Process the given data received from the cloud-config userdata.

        It knows to process only lists and dicts.
        """
        if not isinstance(data, (list, dict)):
            raise exception.CloudbaseInitException(
                "Can't process the type of data %r" % type(data))

        osutils = osutils_factory.get_os_utils()
        for item in data:
            if not isinstance(item, dict):
                continue
            if not {'name'}.issubset(set(item)):
                LOG.warning("Missing name key from user information %s",
                            item)
                continue
            user_name = item.get('name', None)
            if not user_name:
                LOG.warning("Username cannot be empty")
                continue

            try:
                self._create_user(item, osutils)
            except Exception as ex:
                LOG.warning("An error occurred during user '%s' creation: '%s"
                            % (user_name, ex))

        return False
