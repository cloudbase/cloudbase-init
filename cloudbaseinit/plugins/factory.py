# Copyright 2012 Cloudbase Solutions Srl
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

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.utils import classloader


CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)

# Some plugins were moved to plugins.common, in order to
# better reflect the fact that they are not platform specific.
# Unfortunately, there are a lot of users out there with old
# config files which are using the old plugin names.
# So in order not to crash cloudbaseinit for their cases,
# we provide this explicit mapping. This will be removed
# when we'll reach 1.0 though.

OLD_PLUGINS = {
    'cloudbaseinit.plugins.windows.mtu.MTUPlugin':
    'cloudbaseinit.plugins.common.mtu.MTUPlugin',

    'cloudbaseinit.plugins.windows.sethostname.SetHostNamePlugin':
    'cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin',

    'cloudbaseinit.plugins.windows.networkconfig.NetworkConfigPlugin':
    'cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin',

    'cloudbaseinit.plugins.windows.sshpublickeys.SetUserSSHPublicKeysPlugin':
    'cloudbaseinit.plugins.common.sshpublickeys.SetUserSSHPublicKeysPlugin',

    'cloudbaseinit.plugins.windows.userdata.UserDataPlugin':
    'cloudbaseinit.plugins.common.userdata.UserDataPlugin',

    'cloudbaseinit.plugins.windows.setuserpassword.SetUserPasswordPlugin':
    'cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin',

    'cloudbaseinit.plugins.windows.localscripts.LocalScriptsPlugin':
    'cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin',
}


def load_plugins(stage):
    plugins = []
    cl = classloader.ClassLoader()
    for class_path in CONF.plugins:
        if class_path in OLD_PLUGINS:
            new_class_path = OLD_PLUGINS[class_path]
            LOG.warn("Old plugin module %r was found. The new name is %r. "
                     "The old name will not be supported starting with "
                     "cloudbaseinit 1.0", class_path, new_class_path)
            class_path = new_class_path

        try:
            plugin_cls = cl.load_class(class_path)
            if not stage or plugin_cls.execution_stage == stage:
                plugin = plugin_cls()
                plugins.append(plugin)
        except ImportError:
            LOG.error("Could not import plugin module %r", class_path)
            continue
    return plugins
