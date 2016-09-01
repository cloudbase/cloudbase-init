# Copyright 2013 Cloudbase Solutions Srl
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

import itertools
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins import factory
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF

STAGE = {
    base.PLUGIN_STAGE_PRE_NETWORKING: [
        'cloudbaseinit.plugins.windows.ntpclient.NTPClientPlugin'
    ],
    base.PLUGIN_STAGE_PRE_METADATA_DISCOVERY: [
        'cloudbaseinit.plugins.common.mtu.MTUPlugin'
    ],
    base.PLUGIN_STAGE_MAIN: [
        'cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin',
        'cloudbaseinit.plugins.windows.createuser.CreateUserPlugin',
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
    ]
}


class TestPluginFactory(unittest.TestCase):

    @mock.patch('cloudbaseinit.utils.classloader.ClassLoader.load_class')
    def _test_load_plugins(self, mock_load_class, stage=None):
        if stage:
            expected_plugins = STAGE.get(stage, [])
        else:
            expected_plugins = list(itertools.chain(*STAGE.values()))
        expected_load = [mock.call(path) for path in CONF.plugins]
        side_effect = []
        for path in expected_plugins:
            plugin = mock.Mock()
            plugin.execution_stage = (stage if stage in STAGE.keys() else
                                      None)
            plugin.return_value = path
            side_effect.append(plugin)
        mock_load_class.side_effect = (
            side_effect + [mock.Mock() for _ in range(len(expected_load) -
                                                      len(side_effect))])

        response = factory.load_plugins(stage)
        self.assertEqual(expected_load, mock_load_class.call_args_list)
        self.assertEqual(sorted(expected_plugins), sorted(response))

    def test_load_plugins(self):
        self._test_load_plugins()

    def test_load_plugins_main(self):
        self._test_load_plugins(stage=base.PLUGIN_STAGE_MAIN)

    def test_load_plugins_networking(self):
        self._test_load_plugins(stage=base.PLUGIN_STAGE_PRE_NETWORKING)

    def test_load_plugins_metadata(self):
        self._test_load_plugins(stage=base.PLUGIN_STAGE_PRE_METADATA_DISCOVERY)

    def test_load_plugins_empty(self):
        self._test_load_plugins(stage=mock.Mock())

    @testutils.ConfPatcher('plugins', ['missing.plugin'])
    def test_load_plugins_plugin_failed(self):
        with testutils.LogSnatcher('cloudbaseinit.plugins.'
                                   'factory') as snatcher:
            plugins = factory.load_plugins(None)

        self.assertEqual([], plugins)
        self.assertEqual(["Could not import plugin module 'missing.plugin'"],
                         snatcher.output)

    @testutils.ConfPatcher('plugins', ["cloudbaseinit.plugins.windows."
                                       "localscripts.LocalScriptsPlugin"])
    @mock.patch('cloudbaseinit.utils.classloader.ClassLoader.load_class')
    def test_old_plugin_mapping(self, mock_load_class):
        with testutils.LogSnatcher('cloudbaseinit.plugins.'
                                   'factory') as snatcher:
            factory.load_plugins(None)

        expected = [
            "Old plugin module 'cloudbaseinit.plugins.windows."
            "localscripts.LocalScriptsPlugin' was found. "
            "The new name is 'cloudbaseinit.plugins.common."
            "localscripts.LocalScriptsPlugin'. The old name will not "
            "be supported starting with cloudbaseinit 1.0",
        ]
        expected_call = mock.call('cloudbaseinit.plugins.common.'
                                  'localscripts.LocalScriptsPlugin')
        self.assertEqual(expected, snatcher.output)
        called = mock_load_class.mock_calls[0]
        self.assertEqual(expected_call, called)
