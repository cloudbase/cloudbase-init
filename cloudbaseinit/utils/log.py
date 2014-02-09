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

from cloudbaseinit.openstack.common import cfg
from cloudbaseinit.openstack.common import log as openstack_logging

opts = [
    cfg.StrOpt('logging_serial_port_settings', default=None,
               help='Serial port logging settings. Format: '
               '"port,baudrate,parity,bytesize", e.g.: "COM1,115200,N,8". '
               'Set to None (default) to disable.'),
]

CONF = cfg.CONF
CONF.register_opts(opts)
CONF.import_opt('default_log_levels', 'cloudbaseinit.openstack.common.log')
CONF.import_opt('log_date_format', 'cloudbaseinit.openstack.common.log')
CONF.import_opt('log_format', 'cloudbaseinit.openstack.common.log')


class SerialPortHandler(logging.StreamHandler):
    def __init__(self):
        if CONF.logging_serial_port_settings:
            settings = CONF.logging_serial_port_settings.split(',')

            self._port = serial.Serial(port=settings[0],
                                       baudrate=int(settings[1]),
                                       parity=settings[2],
                                       bytesize=int(settings[3]))
            if not self._port.isOpen():
                self._port.open()

            super(SerialPortHandler, self).__init__(self._port)

    def close(self):
        if self._port and self._port.isOpen():
            self._port.close()


def setup(product_name):
    openstack_logging.setup(product_name)

    if CONF.logging_serial_port_settings:
        log_root = openstack_logging.getLogger(product_name).logger

        serialportlog = SerialPortHandler()
        log_root.addHandler(serialportlog)

        datefmt = CONF.log_date_format
        if CONF.log_format:
            serialportlog.setFormatter(logging.Formatter(fmt=CONF.log_format,
                                                         datefmt=datefmt))
        serialportlog.setFormatter(
            openstack_logging.LegacyFormatter(datefmt=datefmt))

        for pair in CONF.default_log_levels:
            mod, _sep, level_name = pair.partition('=')
            logger = logging.getLogger(mod)
            logger.addHandler(serialportlog)
