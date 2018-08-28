# Copyright (c) 2017 Cloudbase Solutions Srl
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

from oslo_log import log as oslo_logging
from six.moves import winreg

from cloudbaseinit import exception
from cloudbaseinit.utils.windows import wmi_loader

wmi = wmi_loader.wmi()
LOG = oslo_logging.getLogger(__name__)


def get_rdp_certificate_thumbprint():
    conn = wmi.WMI(moniker='//./root/cimv2/TerminalServices')
    tsSettings = conn.Win32_TSGeneralSetting()
    if not tsSettings:
        raise exception.ItemNotFoundException("No RDP certificate found")
    return tsSettings[0].SSLCertificateSHA1Hash


def set_rdp_keepalive(enable, interval=1):
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                        'SOFTWARE\\Policies\\Microsoft\\'
                        'Windows NT\\Terminal Services',
                        0, winreg.KEY_ALL_ACCESS) as key:
        LOG.debug("Setting RDP KeepAliveEnabled: %s", enable)
        winreg.SetValueEx(
            key, 'KeepAliveEnable', 0, winreg.REG_DWORD, 1 if enable else 0)
        LOG.debug("Setting RDP keepAliveInterval (minutes): %s", interval)
        winreg.SetValueEx(
            key, 'keepAliveInterval', 0, winreg.REG_DWORD, interval)
