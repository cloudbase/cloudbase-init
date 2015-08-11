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

from oslo_config import cfg

from cloudbaseinit.osutils import factory
from cloudbaseinit.plugins.common import setuserpassword

CLEAR_TEXT_INJECTED_ONLY = 'clear_text_injected_only'
ALWAYS_CHANGE = 'always'
NEVER_CHANGE = 'no'
LOGON_PASSWORD_CHANGE_OPTIONS = [
    CLEAR_TEXT_INJECTED_ONLY,
    NEVER_CHANGE,
    ALWAYS_CHANGE,
]

opts = [
    cfg.StrOpt('first_logon_behaviour',
               default=CLEAR_TEXT_INJECTED_ONLY,
               choices=LOGON_PASSWORD_CHANGE_OPTIONS,
               help='Control the behaviour of what happens at '
                    'next logon. If this option is set to `always`, '
                    'then the user will be forced to change the password '
                    'at next logon. If it is set to '
                    '`clear_text_injected_only`, '
                    'then the user will have to change the password only if '
                    'the password is a clear text password, coming from the '
                    'metadata. The last option is `no`, when the user is '
                    'never forced to change the password.'),

]

CONF = cfg.CONF
CONF.register_opts(opts)


class SetUserPasswordPlugin(setuserpassword.SetUserPasswordPlugin):
    """Plugin for changing the password, tailored to Windows."""

    def post_set_password(self, username, _, password_injected=False):
        """Post set password logic

        If the option is activated, force the user to change the
        password at next logon.
        """
        if CONF.first_logon_behaviour == NEVER_CHANGE:
            return

        clear_text = CONF.first_logon_behaviour == CLEAR_TEXT_INJECTED_ONLY
        always = CONF.first_logon_behaviour == ALWAYS_CHANGE
        if always or (clear_text and password_injected):
            osutils = factory.get_os_utils()
            osutils.change_password_next_logon(username)
