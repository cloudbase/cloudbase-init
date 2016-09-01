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

import logging
import serial
import six

from oslo_log import formatters
from oslo_log import log

from cloudbaseinit import conf as cloudbaseinit_conf

CONF = cloudbaseinit_conf.CONF
LOG = log.getLogger(__name__)


class SerialPortHandler(logging.StreamHandler):

    class _UnicodeToBytesStream(object):

        def __init__(self, stream):
            self._stream = stream

        def write(self, data):
            if self._stream and not self._stream.isOpen():
                    self._stream.open()

            if isinstance(data, six.text_type):
                self._stream.write(data.encode("utf-8"))
            else:
                self._stream.write(data)

    def __init__(self):
        self._port = None
        if CONF.logging_serial_port_settings:
            settings = CONF.logging_serial_port_settings.split(',')

            try:
                self._port = serial.Serial(port=settings[0],
                                           baudrate=int(settings[1]),
                                           parity=settings[2],
                                           bytesize=int(settings[3]))
                if not self._port.isOpen():
                    self._port.open()
            except serial.SerialException as ex:
                # Log to other handlers
                LOG.exception(ex)

        # Unicode strings are not properly handled by the serial module
        super(SerialPortHandler, self).__init__(
            self._UnicodeToBytesStream(self._port))

    def close(self):
        if self._port and self._port.isOpen():
            self._port.close()


def setup(product_name):
    log.setup(CONF, product_name)

    if CONF.logging_serial_port_settings:
        log_root = log.getLogger(product_name).logger

        serialportlog = SerialPortHandler()
        log_root.addHandler(serialportlog)

        datefmt = CONF.log_date_format
        serialportlog.setFormatter(
            formatters.ContextFormatter(project=product_name,
                                        datefmt=datefmt))
