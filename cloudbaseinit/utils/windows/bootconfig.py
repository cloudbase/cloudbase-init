# Copyright 2017 Cloudbase Solutions Srl
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

from cloudbaseinit import constant
from cloudbaseinit import exception
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.utils.windows import wmi_loader

wmi = wmi_loader.wmi()

LOG = oslo_logging.getLogger(__name__)


STORE_CURRENT = "{fa926493-6f1c-4193-a414-58f0b2456d1e}"


BCDOSLOADER_DEVICE_OSDEVICE = 0x21000001
BCDLIBRARY_DEVICE_APPLICATION_DEVICE = 0x11000001
BCDLIBRARY_BOOLEAN_AUTO_RECOVERY_ENABLED = 0x16000009
BOOT_DEVICE = 1


def _run_bcdedit(bcdedit_args):
    args = ["bcdedit.exe"] + bcdedit_args
    osutils = osutils_factory.get_os_utils()
    (out, err, ret_val) = osutils.execute_system32_process(args)
    if ret_val:
        raise exception.CloudbaseInitException(
            'bcdedit failed.\nOutput: %(out)s\nError:'
            ' %(err)s' % {'out': out, 'err': err})


def set_boot_status_policy(policy=constant.POLICY_IGNORE_ALL_FAILURES):
    LOG.debug("Setting boot status policy: %s", policy)
    _run_bcdedit(["/set", "{current}", "bootstatuspolicy", policy])


def get_boot_system_devices():
    conn = wmi.WMI(moniker='//./root/cimv2')
    return [v.DeviceID for v in conn.Win32_Volume(
        BootVolume=True, SystemVolume=True)]


def _get_current_bcd_store():
    conn = wmi.WMI(moniker='//./root/wmi')
    success, store = conn.BcdStore.OpenStore(File="")
    if not success:
        raise exception.CloudbaseInitException("Cannot open BCD store")
    store = wmi._wmi_object(store)
    current_store, success = store.OpenObject(Id=STORE_CURRENT)
    current_store = wmi._wmi_object(current_store)
    if not success:
        raise exception.CloudbaseInitException("Cannot open BCD current store")

    return current_store


def set_current_bcd_device_to_boot_partition():
    current_store = _get_current_bcd_store()

    success, = current_store.SetDeviceElement(
        Type=BCDOSLOADER_DEVICE_OSDEVICE, DeviceType=BOOT_DEVICE,
        AdditionalOptions="")
    if not success:
        raise exception.CloudbaseInitException(
            "Cannot set device element: %s" % BCDOSLOADER_DEVICE_OSDEVICE)

    success, = current_store.SetDeviceElement(
        Type=BCDLIBRARY_DEVICE_APPLICATION_DEVICE, DeviceType=BOOT_DEVICE,
        AdditionalOptions="")
    if not success:
        raise exception.CloudbaseInitException(
            "Cannot set device element: %s" %
            BCDLIBRARY_DEVICE_APPLICATION_DEVICE)


def enable_auto_recovery(enable):
    current_store = _get_current_bcd_store()

    success, = current_store.SetBooleanElement(
        BCDLIBRARY_BOOLEAN_AUTO_RECOVERY_ENABLED, enable)
    if not success:
        raise exception.CloudbaseInitException(
            "Cannot set boolean element: %s" %
            BCDLIBRARY_BOOLEAN_AUTO_RECOVERY_ENABLED)
