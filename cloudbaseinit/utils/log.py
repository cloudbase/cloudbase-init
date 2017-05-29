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


def _safe_write(function):
    """Avoid issues related to unicode strings handling."""
    def _wrapper(message):
        # Unicode strings are not properly handled by the serial module
        if isinstance(message, six.text_type):
            function(message.encode("utf-8"))
        else:
            function(message)
    return _wrapper


def release_logging_handlers(product_name):
    """Closes any currently used logging port handlers.

    Resulting in the stream, file and serial port handler being closed
    and removed from the logging object.
    """
    log_root = log.getLogger(product_name).logger
    for handler in log_root.handlers:
        log_root.removeHandler(handler)
        handler.close()


class SerialPortHandler(logging.StreamHandler):

    def __init__(self):
        super(SerialPortHandler, self).__init__(None)
        self.stream = self._open()

    @staticmethod
    def _open():
        serial_port = None
        if CONF.logging_serial_port_settings:
            settings = CONF.logging_serial_port_settings.split(',')
            serial_port = serial.Serial(port=settings[0],
                                        baudrate=int(settings[1]),
                                        parity=settings[2],
                                        bytesize=int(settings[3]))
            if not serial_port.isOpen():
                serial_port.open()
            serial_port.write = _safe_write(serial_port.write)
        return serial_port

    def emit(self, record):
        """Emit a record."""
        if self.stream is None:
            self.stream = self._open()

        super(SerialPortHandler, self).emit(record)

    def close(self):
        """Closes the serial port."""
        self.acquire()
        try:
            serial_port = self.stream
            if serial_port and serial_port.isOpen():
                self.stream = None
                serial_port.close()
            logging.Handler.close(self)
        finally:
            self.release()


def setup(product_name):
    log.setup(CONF, product_name)

    if CONF.logging_serial_port_settings:
        try:
            serialportlog = SerialPortHandler()
            log_root = log.getLogger(product_name).logger
            log_root.addHandler(serialportlog)

            datefmt = CONF.log_date_format
            serialportlog.setFormatter(
                formatters.ContextFormatter(project=product_name,
                                            datefmt=datefmt))
        except serial.SerialException:
            LOG.warn("Serial port: {0} could not be opened".format(
                     CONF.logging_serial_port_settings))
