# Copyright 2015 Cloudbase Solutions Srl
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

from oslo_log import log as oslo_logging

from cloudbaseinit.plugins.common import createuser


LOG = oslo_logging.getLogger(__name__)


class CreateUserPlugin(createuser.BaseCreateUserPlugin):

    @staticmethod
    def _create_user_logon(user_name, password, osutils):
        try:
            # Create a user profile in order for other plugins
            # to access the user home, etc
            token = osutils.create_user_logon_session(user_name,
                                                      password,
                                                      True)
            osutils.close_user_logon_session(token)
        except Exception:
            LOG.exception('Cannot create a user logon session for user: "%s"',
                          user_name)

    def create_user(self, username, password, osutils):
        osutils.create_user(username, password)

    def post_create_user(self, user_name, password, osutils):
        self._create_user_logon(user_name, password, osutils)
