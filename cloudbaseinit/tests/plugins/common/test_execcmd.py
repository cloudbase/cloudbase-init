# Copyright 2014 Cloudbase Solutions Srl
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


import os
import textwrap
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import execcmd
from cloudbaseinit.tests import testutils


def _remove_file(filepath):
    if not filepath:
        return
    try:
        os.remove(filepath)
    except OSError:
        pass


@mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
class TestExecCmd(unittest.TestCase):

    def test_from_data(self, _):
        command = execcmd.BaseCommand.from_data(b"test")

        self.assertIsInstance(command, execcmd.BaseCommand)

        # Not public API, though.
        self.assertTrue(os.path.exists(command._target_path),
                        command._target_path)
        self.addCleanup(_remove_file, command._target_path)

        with open(command._target_path) as stream:
            data = stream.read()

        self.assertEqual("test", data)
        command._cleanup()
        self.assertFalse(os.path.exists(command._target_path),
                         command._target_path)

    def test_args(self, _):
        class FakeCommand(execcmd.BaseCommand):
            command = mock.sentinel.command

        with testutils.create_tempfile() as tmp:
            fake_command = FakeCommand(tmp)
            self.assertEqual([mock.sentinel.command, tmp],
                             fake_command.args)

            fake_command = execcmd.BaseCommand(tmp)
            self.assertEqual([tmp], fake_command.args)

    def test_from_data_extension(self, _):
        class FakeCommand(execcmd.BaseCommand):
            command = mock.sentinel.command
            extension = ".test"

        command = FakeCommand.from_data(b"test")
        self.assertIsInstance(command, FakeCommand)

        self.addCleanup(os.remove, command._target_path)
        self.assertTrue(command._target_path.endswith(".test"))

    def test_execute_normal_command(self, mock_get_os_utils):
        mock_osutils = mock_get_os_utils()

        with testutils.create_tempfile() as tmp:
            command = execcmd.BaseCommand(tmp)
            command.execute()

            mock_osutils.execute_process.assert_called_once_with(
                [command._target_path],
                shell=command.shell)

            # test __call__ API.
            mock_osutils.execute_process.reset_mock()
            command()

            mock_osutils.execute_process.assert_called_once_with(
                [command._target_path],
                shell=command.shell)

    def test_execute_powershell_command(self, mock_get_os_utils):
        mock_osutils = mock_get_os_utils()

        with testutils.create_tempfile() as tmp:
            command = execcmd.Powershell(tmp)
            command.execute()

            mock_osutils.execute_powershell_script.assert_called_once_with(
                command._target_path, command.sysnative)

    def test_execute_cleanup(self, _):
        with testutils.create_tempfile() as tmp:
            cleanup = mock.Mock()
            command = execcmd.BaseCommand(tmp, cleanup=cleanup)
            command.execute()

            cleanup.assert_called_once_with()

    @mock.patch("cloudbaseinit.plugins.common.execcmd.PowershellSysnative")
    @mock.patch("cloudbaseinit.plugins.common.execcmd.Shell")
    def _test_process_ec2(self, mock_shell, mock_psnative, tag=None):
        if tag:
            content = textwrap.dedent("""
            <{0}>mocked</{0}>

            <{0}>second</{0}>
            <abc>1</abc>
            <{0}>third
            </{0}>
            <{0}></{0}> # empty
            <{0}></{0} # invalid
            """.format(tag)).encode()
        else:
            content = textwrap.dedent("""
            <powershell>p1</powershell>
            <script>s1</script>
            <script>s2</script>
            <powershell>p2</powershell>
            <script>s3</script>
            """).encode()

        def ident(value):
            ident_func = mock.MagicMock()
            ident_func.return_value = (value, b"", 0)
            return ident_func

        mock_shell.from_data = ident
        mock_psnative.from_data = ident

        ec2conf = execcmd.EC2Config.from_data(content)
        out, _, _ = ec2conf()

        if tag:
            self.assertEqual(b"mocked\nsecond\nthird", out)
        else:
            self.assertEqual(b"s1\ns2\ns3\np1\np2", out)

    def test_process_ec2_script(self, _):
        self._test_process_ec2(tag="script")

    def test_process_ec2_powershell(self, _):
        self._test_process_ec2(tag="powershell")

    def test_process_ec2_order(self, _):
        self._test_process_ec2()

    def test_get_plugin_return_value(self, _):
        ret_val_map = {
            0: (base.PLUGIN_EXECUTION_DONE, False),
            1: (base.PLUGIN_EXECUTION_DONE, False),
            "invalid": (base.PLUGIN_EXECUTION_DONE, False),
            1001: (base.PLUGIN_EXECUTION_DONE, True),
            1002: (base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False),
            1003: (base.PLUGIN_EXECUTE_ON_NEXT_BOOT, True),
        }
        for ret_val, expect in ret_val_map.items():
            self.assertEqual(expect, execcmd.get_plugin_return_value(ret_val))
