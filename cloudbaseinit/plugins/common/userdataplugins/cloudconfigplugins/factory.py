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

import collections

from cloudbaseinit.utils import classloader


# TODO(cpopa): replace the static list of plugins with something
# discovered at runtime.
PLUGINS = collections.OrderedDict([
    ('write_files', 'cloudbaseinit.plugins.common.userdataplugins.'
                    'cloudconfigplugins.write_files.WriteFilesPlugin'),
    ('set_timezone', 'cloudbaseinit.plugins.common.userdataplugins.'
                     'cloudconfigplugins.set_timezone.SetTimezonePlugin'),
    ('timezone', 'cloudbaseinit.plugins.common.userdataplugins.'
                 'cloudconfigplugins.set_timezone.SetTimezonePlugin'),
    ('set_hostname', 'cloudbaseinit.plugins.common.userdataplugins.'
                     'cloudconfigplugins.set_hostname.SetHostnamePlugin'),
    ('hostname', 'cloudbaseinit.plugins.common.userdataplugins.'
                 'cloudconfigplugins.set_hostname.SetHostnamePlugin'),
    ('ntp', 'cloudbaseinit.plugins.common.userdataplugins.'
            'cloudconfigplugins.set_ntp.SetNtpPlugin'),
    ('groups', 'cloudbaseinit.plugins.common.userdataplugins.'
               'cloudconfigplugins.groups.GroupsPlugin'),
    ('users', 'cloudbaseinit.plugins.common.userdataplugins.'
              'cloudconfigplugins.users.UsersPlugin'),
    ('runcmd', 'cloudbaseinit.plugins.common.userdataplugins.'
               'cloudconfigplugins.runcmd.RunCmdPlugin'),
])


def load_plugins():
    loader = classloader.ClassLoader()
    return {section: loader.load_class(class_path)().process
            for section, class_path in PLUGINS.items()}
