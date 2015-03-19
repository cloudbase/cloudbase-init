# Copyright 2015 Cloudbase Solutions Srl
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

import contextlib

import win32process
import win32security


@contextlib.contextmanager
def acquire_privilege(privilege):
    process = win32process.GetCurrentProcess()
    token = win32security.OpenProcessToken(
        process,
        win32security.TOKEN_ADJUST_PRIVILEGES |
        win32security.TOKEN_QUERY)
    priv_luid = win32security.LookupPrivilegeValue(None, privilege)
    privilege_enable = [(priv_luid, win32security.SE_PRIVILEGE_ENABLED)]
    privilege_disable = [(priv_luid, win32security.SE_PRIVILEGE_REMOVED)]
    win32security.AdjustTokenPrivileges(token, False, privilege_enable)

    try:
        yield
    finally:
        win32security.AdjustTokenPrivileges(token, False, privilege_disable)
