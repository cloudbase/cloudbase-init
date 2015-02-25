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

from oslo.config import cfg

from cloudbaseinit.utils import classloader

opts = [
    cfg.ListOpt(
        'plugins',
        default=[
            'cloudbaseinit.plugins.common.mtu.MTUPlugin',
            'cloudbaseinit.plugins.windows.ntpclient.NTPClientPlugin',
            'cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin',
            'cloudbaseinit.plugins.common.createuser.CreateUserPlugin',
            'cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin',
            'cloudbaseinit.plugins.windows.licensing.WindowsLicensingPlugin',
            'cloudbaseinit.plugins.common.sshpublickeys.'
            'SetUserSSHPublicKeysPlugin',
            'cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin',
            'cloudbaseinit.plugins.common.userdata.UserDataPlugin',
            'cloudbaseinit.plugins.common.setuserpassword.'
            'SetUserPasswordPlugin',
            'cloudbaseinit.plugins.windows.winrmlistener.'
            'ConfigWinRMListenerPlugin',
            'cloudbaseinit.plugins.windows.winrmcertificateauth.'
            'ConfigWinRMCertificateAuthPlugin',
            'cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin',
        ],
        help='List of enabled plugin classes, '
        'to executed in the provided order'),
]

CONF = cfg.CONF
CONF.register_opts(opts)


def load_plugins():
    plugins = []
    cl = classloader.ClassLoader()
    for class_path in CONF.plugins:
        plugins.append(cl.load_class(class_path)())
    return plugins
