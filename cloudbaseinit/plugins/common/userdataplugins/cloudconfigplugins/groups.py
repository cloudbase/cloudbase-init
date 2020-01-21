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


class GroupsPlugin(base.BaseCloudConfigPlugin):
    """Creates groups given in cloud-config for the underlying platform."""

    def process(self, data):
        """Process the given data received from the cloud-config userdata.

        It knows to process only lists and dicts.
        """
        if not isinstance(data, (list, dict)):
            raise exception.CloudbaseInitException(
                "Can't process the type of data %r" % type(data))

        osutils = osutils_factory.get_os_utils()

        for item in data:
            group_name = None
            group_users = []

            if isinstance(item, six.string_types):
                group_name = item
            elif isinstance(item, dict):
                try:
                    group_name = list(item.keys())[0]
                    group_users = item.get(group_name, [])
                except Exception:
                    LOG.error("Group details could not be parsed")
                    raise
            else:
                raise exception.CloudbaseInitException(
                    "Unrecognized type '%r' in group definition" % type(item))

            if not group_name:
                LOG.warning("Group name cannot be empty")
                continue

            try:
                if not osutils.group_exists(group_name):
                    osutils.create_group(group_name)
                else:
                    LOG.warning("Group '%s' already exists" % group_name)
                for group_user in group_users:
                    osutils.add_user_to_local_group(group_user, group_name)
            except Exception as exc:
                raise exception.CloudbaseInitException(
                    "Group '%s' could not be configured. Exception code: %s"
                    % (group_name, exc))

        return False
