# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import mock
import unittest

from oslo.config import cfg

from cloudbaseinit.utils import log

CONF = cfg.CONF


class SerialPortHandlerTests(unittest.TestCase):
    @mock.patch('serial.Serial')
    def setUp(self, mock_Serial):
        CONF.set_override('logging_serial_port_settings', "COM1,115200,N,8")
        self._serial_port_handler = log.SerialPortHandler()
        self._serial_port_handler._port = mock.MagicMock()

    @mock.patch('serial.Serial')
    def test_init(self, mock_Serial):
        mock_Serial().isOpen.return_value = False
        log.SerialPortHandler()
        print mock_Serial.mock_calls
        mock_Serial.assert_called_with(bytesize=8, baudrate=115200,
                                       port='COM1', parity='N')
        mock_Serial().isOpen.assert_called_once_with()
        mock_Serial().open.assert_called_once_with()

    def test_close(self):
        self._serial_port_handler._port.isOpen.return_value = True
        self._serial_port_handler.close()
        self._serial_port_handler._port.isOpen.assert_called_once_with()
        self._serial_port_handler._port.close.assert_called_once_with()


@mock.patch('cloudbaseinit.openstack.common.log.setup')
@mock.patch('cloudbaseinit.openstack.common.log.getLogger')
@mock.patch('cloudbaseinit.utils.log.SerialPortHandler')
@mock.patch('cloudbaseinit.openstack.common.log.ContextFormatter')
def test_setup(mock_ContextFormatter, mock_SerialPortHandler, mock_getLogger,
               mock_setup):
    log.setup(product_name='fake name')
    mock_setup.assert_called_once_with('fake name')
    mock_getLogger.assert_called_once_with('fake name')
    mock_getLogger().logger.addHandler.assert_called_once_with(
        mock_SerialPortHandler())
    mock_ContextFormatter.assert_called_once_with(
        project='fake name', datefmt=CONF.log_date_format)
    mock_SerialPortHandler().setFormatter.assert_called_once_with(
        mock_ContextFormatter())
