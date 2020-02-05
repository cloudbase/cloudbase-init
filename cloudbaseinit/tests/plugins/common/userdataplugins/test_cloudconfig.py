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

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.plugins.common.userdataplugins import cloudconfig
from cloudbaseinit.tests import testutils

CONF = cloudbaseinit_conf.CONF


class CloudConfigPluginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plugin = cloudconfig.CloudConfigPlugin()

    def test_priority(self):
        orig = CONF.cloud_config_plugins
        CONF.cloud_config_plugins = ['write_file', 'dummy', 'dummy1']
        expected = [
            ('write_file', 0),
            ('dummy', 1),
            ('dummy1', 2),
            ('invalid', 3),
        ]

        try:
            executor = cloudconfig.CloudConfigPluginExecutor(
                dummy=1,
                dummy1=2,
                invalid=3,
                write_file=0)
            self.assertEqual(expected, executor._expected_plugins)
        finally:
            CONF.cloud_config_plugins = orig

    def test_default_priority(self):
        expected = [
            ('write_files', 0),
            ('hostname', 3),
            ('runcmd', 1),
            ('invalid1', 1),
            ('invalid2', 2),
        ]

        executor = cloudconfig.CloudConfigPluginExecutor(
            runcmd=1,
            invalid1=1,
            hostname=3,
            invalid2=2,
            write_files=0)
        self.assertEqual(expected, executor._expected_plugins)

    def test_executor_from_yaml(self):
        for invalid in (mock.sentinel.yaml, None, 1, int, '{}'):
            with self.assertRaises(cloudconfig.CloudConfigError):
                cloudconfig.CloudConfigPluginExecutor.from_yaml(invalid)

        executor = cloudconfig.CloudConfigPluginExecutor.from_yaml('{f: 1}')
        self.assertIsInstance(executor, cloudconfig.CloudConfigPluginExecutor)

    def _test_invalid_type(self, part, err_msg):
        with testutils.LogSnatcher('cloudbaseinit.plugins.common.'
                                   'userdataplugins.cloudconfig') as snatcher:
            self.plugin.process_non_multipart(part)

        expected = ("Could not process part type %(type)r: %(err)r"
                    % {'type': type(part), 'err': err_msg})
        self.assertEqual([expected], snatcher.output)

    def test_invalid_type(self):
        self._test_invalid_type({'unsupported'},
                                "Invalid yaml stream provided.")

    def test_invalid_type_empty(self):
        self._test_invalid_type('#comment',
                                'Empty yaml stream provided.')
