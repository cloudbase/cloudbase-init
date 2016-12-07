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

import importlib
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import conf as cloudbaseinit_conf

CONF = cloudbaseinit_conf.CONF


class SerialPortHandlerTests(unittest.TestCase):

    def setUp(self):
        self._serial = mock.MagicMock()
        self._stream = mock.MagicMock()
        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'serial': self._serial})

        self._module_patcher.start()

        self.log = importlib.import_module("cloudbaseinit.utils.log")

        self.log.serial = self._serial
        self._old_value = CONF.get('logging_serial_port_settings')
        CONF.set_override('logging_serial_port_settings', "COM1,115200,N,8")
        self._serial_port_handler = self.log.SerialPortHandler()
        self._serial_port_handler.stream = mock.MagicMock()

    def tearDown(self):
        self._module_patcher.stop()
        CONF.set_override('logging_serial_port_settings', self._old_value)

    @mock.patch('oslo_log.log.setup')
    @mock.patch('oslo_log.log.getLogger')
    @mock.patch('cloudbaseinit.utils.log.SerialPortHandler')
    @mock.patch('oslo_log.formatters.ContextFormatter')
    def test_setup(self, mock_ContextFormatter, mock_SerialPortHandler,
                   mock_getLogger, mock_setup):

        self.log.setup(product_name='fake name')

        mock_setup.assert_called_once_with(self.log.CONF, 'fake name')
        mock_getLogger.assert_called_once_with('fake name')
        mock_getLogger().logger.addHandler.assert_called_once_with(
            mock_SerialPortHandler())

        mock_ContextFormatter.assert_called_once_with(
            project='fake name', datefmt=CONF.log_date_format)

        mock_SerialPortHandler().setFormatter.assert_called_once_with(
            mock_ContextFormatter())
