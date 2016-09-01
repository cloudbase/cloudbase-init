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
import six

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
        self._unicode_stream = self._serial_port_handler._UnicodeToBytesStream(
            self._stream)
        self._serial_port_handler._port = mock.MagicMock()

    def tearDown(self):
        self._module_patcher.stop()
        CONF.set_override('logging_serial_port_settings', self._old_value)

    def test_init(self):
        mock_Serial = self._serial.Serial
        mock_Serial.return_value.isOpen.return_value = False

        self.log.SerialPortHandler()

        mock_Serial.assert_called_with(bytesize=8, baudrate=115200,
                                       port='COM1', parity='N')
        mock_Serial.return_value.isOpen.assert_called_with()
        mock_Serial.return_value.open.assert_called_once_with()

    def test_close(self):
        self._serial_port_handler._port.isOpen.return_value = True

        self._serial_port_handler.close()

        self._serial_port_handler._port.isOpen.assert_called_once_with()
        self._serial_port_handler._port.close.assert_called_once_with()

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

    def _test_unicode_write(self, is_six_instance=False):
        self._stream.isOpen.return_value = False
        if is_six_instance:
            fake_data = mock.MagicMock(spec=six.text_type)
            fake_data.encode = mock.MagicMock()
        else:
            fake_data = mock.MagicMock()

        self._unicode_stream.write(fake_data)

        self._stream.isOpen.assert_called_once_with()
        self._stream.open.assert_called_once_with()
        if is_six_instance:
            self._stream.write.assert_called_once_with(
                fake_data.encode.return_value)
            fake_data.encode.assert_called_once_with('utf-8')
        else:
            self._stream.write.assert_called_once_with(fake_data)

    def test_unicode_write(self):
        self._test_unicode_write()

    def test_unicode_write_with_encode(self):
        self._test_unicode_write(is_six_instance=True)
