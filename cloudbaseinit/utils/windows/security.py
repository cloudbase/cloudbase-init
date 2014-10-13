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

from six.moves import winreg


class WindowsSecurityUtils(object):
    _SYSTEM_POLICIES_KEY = ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                            "Policies\\System")
    _LATFP_VALUE_NAME = "LocalAccountTokenFilterPolicy"

    # https://support.microsoft.com/kb/951016
    def set_uac_remote_restrictions(self, enable=True):
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,
                              self._SYSTEM_POLICIES_KEY) as key_name:
            winreg.SetValueEx(key_name, self._LATFP_VALUE_NAME, 0,
                              winreg.REG_DWORD, int(not enable))

    def get_uac_remote_restrictions(self):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                self._SYSTEM_POLICIES_KEY) as key:
                (value, regtype) = winreg.QueryValueEx(key,
                                                       self._LATFP_VALUE_NAME)
                return not bool(value)
        except WindowsError as e:
            if e.errno == 0x2:
                return True
            else:
                raise
