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

import datetime
import netifaces
import random
import socket
import struct
import time

from oslo_log import log as oslo_logging

from cloudbaseinit.utils import network

_DHCP_COOKIE = b'\x63\x82\x53\x63'
_OPTION_END = b'\xff'

OPTION_MTU = 26
OPTION_NTP_SERVERS = 42

LOG = oslo_logging.getLogger(__name__)


def _get_dhcp_request_data(id_req, mac_address, requested_options,
                           vendor_id):

    mac_address_b = bytearray.fromhex(mac_address.replace(':', ''))
    # See: http://www.ietf.org/rfc/rfc2131.txt
    data = b'\x01'
    data += b'\x01'
    data += b'\x06'
    data += b'\x00'
    data += struct.pack('!L', id_req)
    data += b'\x00\x00'
    data += b'\x00\x00'
    data += b'\x00\x00\x00\x00'
    data += b'\x00\x00\x00\x00'
    data += b'\x00\x00\x00\x00'
    data += b'\x00\x00\x00\x00'
    data += mac_address_b
    data += b'\x00' * 10
    data += b'\x00' * 64
    data += b'\x00' * 128
    data += _DHCP_COOKIE
    data += b'\x35\x01\x01'

    if vendor_id:
        vendor_id_b = vendor_id.encode('ascii')
        data += b'\x3c' + struct.pack('B', len(vendor_id_b)) + vendor_id_b

    data += b'\x3d\x07\x01' + mac_address_b
    data += b'\x37' + struct.pack('B', len(requested_options))

    for option in requested_options:
        data += struct.pack('B', option)

    data += _OPTION_END
    return data


def _parse_dhcp_reply(data, id_req):
    message_type = struct.unpack('B', data[0:1])[0]

    if message_type != 2:
        return False, {}

    id_reply = struct.unpack('!L', data[4:8])[0]
    if id_reply != id_req:
        return False, {}

    if data[236:240] != _DHCP_COOKIE:
        return False, {}

    options = {}

    i = 240
    data_len = len(data)
    while i < data_len and data[i:i + 1] != _OPTION_END:
        id_option = struct.unpack('B', data[i:i + 1])[0]
        option_data_len = struct.unpack('B', data[i + 1:i + 2])[0]
        i += 2
        options[id_option] = data[i: i + option_data_len]
        i += option_data_len

    return True, options


def _get_mac_address_by_local_ip(ip_addr):
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        for addr in addrs.get(netifaces.AF_INET, []):
            if addr['addr'] == ip_addr:
                return addrs[netifaces.AF_LINK][0]['addr']


def _bind_dhcp_client_socket(s, max_bind_attempts, bind_retry_interval):
    bind_attempts = 1
    while True:
        try:
            s.bind(('', 68))
            break
        except socket.error as ex:
            if (bind_attempts >= max_bind_attempts or
                    ex.errno not in [48, 10048]):
                raise
            bind_attempts += 1
            LOG.exception(ex)
            LOG.info("Retrying to bind DHCP client port in %s seconds" %
                     bind_retry_interval)
            time.sleep(bind_retry_interval)


def get_dhcp_options(dhcp_host=None, requested_options=[], timeout=5.0,
                     vendor_id='cloudbase-init', max_bind_attempts=10,
                     bind_retry_interval=3):
    id_req = random.randint(0, 2 ** 32 - 1)
    options = None

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if not dhcp_host:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        _bind_dhcp_client_socket(s, max_bind_attempts, bind_retry_interval)

        s.settimeout(timeout)

        local_ip_addr = network.get_local_ip(dhcp_host)
        mac_address = _get_mac_address_by_local_ip(local_ip_addr)

        data = _get_dhcp_request_data(id_req, mac_address, requested_options,
                                      vendor_id)

        s.sendto(data, (dhcp_host or "<broadcast>", 67))

        start = datetime.datetime.now()
        now = start
        replied = False
        while (not replied and
                now - start < datetime.timedelta(seconds=timeout)):
            data = s.recv(1024)
            (replied, options) = _parse_dhcp_reply(data, id_req)
            now = datetime.datetime.now()
    except socket.timeout:
        pass
    finally:
        s.close()

    return options
