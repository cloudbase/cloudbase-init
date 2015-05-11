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

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock
from oslo.config import cfg

from cloudbaseinit.plugins.common import factory
from cloudbaseinit.tests import testutils

CONF = cfg.CONF


class PluginFactoryTests(unittest.TestCase):

    @mock.patch('cloudbaseinit.utils.classloader.ClassLoader.load_class')
    def test_load_plugins(self, mock_load_class):
        expected = []
        for path in CONF.plugins:
            expected.append(mock.call(path))
        response = factory.load_plugins()
        self.assertEqual(expected, mock_load_class.call_args_list)
        self.assertTrue(response is not None)

    @testutils.ConfPatcher('plugins', ['missing.plugin'])
    def test_load_plugins_plugin_failed(self):
        with testutils.LogSnatcher('cloudbaseinit.plugins.'
                                   'common.factory') as snatcher:
            plugins = factory.load_plugins()

        self.assertEqual([], plugins)
        self.assertEqual(["Could not import plugin module 'missing.plugin'"],
                         snatcher.output)
