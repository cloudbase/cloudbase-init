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

import os

from oslo_log import log as oslo_logging

from cloudbaseinit import constant
from cloudbaseinit import exception
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.utils.windows import productkeys
from cloudbaseinit.utils.windows import wmi_loader

wmi = wmi_loader.wmi()

LOG = oslo_logging.getLogger(__name__)

WINDOWS_APP_ID = "55c92734-d682-4d71-983e-d6ec3f16059f"
DEFAULT_KMS_PORT = 1688


def get_licensing_manager():
    osutils = osutils_factory.get_os_utils()
    if osutils.check_os_version(6, 1):
        return LicensingManagerV2()
    else:
        return LicensingManager()


class LicensingManager(object):
    @staticmethod
    def _run_slmgr(args):
        osutils = osutils_factory.get_os_utils()

        if osutils.check_sysnative_dir_exists():
            cscript_dir = osutils.get_sysnative_dir()
        else:
            cscript_dir = osutils.get_system32_dir()

        # Not SYSNATIVE, as it is already executed by a x64 process
        slmgr_dir = osutils.get_system32_dir()

        cscript_path = os.path.join(cscript_dir, "cscript.exe")
        slmgr_path = os.path.join(slmgr_dir, "slmgr.vbs")

        (out, err, exit_code) = osutils.execute_process(
            [cscript_path, slmgr_path] + args, shell=False, decode_output=True)

        if exit_code:
            raise exception.CloudbaseInitException(
                'slmgr.vbs failed with error code %(exit_code)s.\n'
                'Output: %(out)s\nError: %(err)s' % {'exit_code': exit_code,
                                                     'out': out, 'err': err})
        return out.decode(errors='replace')

    def get_licensing_info(self):
        return self._run_slmgr(['/dlv'])

    def activate_windows(self):
        return self._run_slmgr(['/ato'])

    def set_kms_host(self, host, port=DEFAULT_KMS_PORT):
        kms_host = "%s:%s" % (host, port)
        return self._run_slmgr(['/skms', kms_host])

    def set_kms_auto_discovery(self):
        return self._run_slmgr(['/ckms'])

    def set_product_key(self, product_key):
        return self._run_slmgr(['/ipk', product_key])

    def is_eval(self):
        raise NotImplementedError()

    def get_kms_product(self):
        raise NotImplementedError()

    def get_volume_activation_product_key(self, license_family,
                                          vol_act_type=constant.VOL_ACT_KMS):
        raise NotImplementedError()

    def refresh_status(self):
        pass


class LicensingManagerV2(LicensingManager):
    def __init__(self):
        self._products = None
        self._service = None

    def _get_service(self):
        if not self._service:
            conn = wmi.WMI(moniker='//./root/cimv2')
            self._service = conn.SoftwareLicensingService()[0]
        return self._service

    def set_product_key(self, product_key):
        service = self._get_service()
        service.InstallProductKey(product_key)

    def set_kms_auto_discovery(self):
        service = self._get_service()
        service.ClearKeyManagementServiceMachine()
        service.ClearKeyManagementServicePort()

    def set_kms_host(self, host, port=DEFAULT_KMS_PORT):
        service = self._get_service()
        service.SetKeyManagementServiceMachine(host)
        service.SetKeyManagementServicePort(port)

    def refresh_status(self):
        service = self._get_service()
        service.RefreshLicenseStatus()

    def _get_products(self):
        if not self._products:
            conn = wmi.WMI(moniker='//./root/cimv2')
            self._products = conn.query(
                'SELECT ID, ApplicationId, PartialProductKey, '
                'LicenseFamily, LicenseIsAddon, Description, '
                'EvaluationEndDate, Name FROM '
                'SoftwareLicensingProduct WHERE '
                'LicenseIsAddon=False')
        return self._products

    @staticmethod
    def _is_current_product(product):
        return bool(product.PartialProductKey)

    def is_eval(self):
        def _is_eval(product):
            return (u"TIMEBASED_EVAL" in product.Description or
                    product.EvaluationEndDate != u"16010101000000.000000-000")

        for product in self._get_products():
            app_id = product.ApplicationId.lower()
            if (app_id == WINDOWS_APP_ID and _is_eval(product) and
                    self._is_current_product(product)):
                return product.EvaluationEndDate

    def get_kms_product(self):
        def _is_kms_client(product):
            # note(alexpilotti): could check for
            # KeyManagementServiceProductKeyID
            return u"VOLUME_KMSCLIENT" in product.Description

        for product in self._get_products():
            app_id = product.ApplicationId.lower()
            if app_id == WINDOWS_APP_ID and _is_kms_client(product):
                return (product.Description, product.LicenseFamily,
                        self._is_current_product(product))

        raise exception.ItemNotFoundException("KMS client product not found")

    def get_volume_activation_product_key(self, license_family,
                                          vol_act_type=constant.VOL_ACT_KMS):
        osutils = osutils_factory.get_os_utils()
        os_version = osutils.get_os_version()
        os_major = os_version["major_version"]
        os_minor = os_version["minor_version"]

        product_keys_map = productkeys.SKU_TO_PRODUCT_KEY_MAP.get(
            (os_major, os_minor, vol_act_type), {})

        return product_keys_map.get(license_family)
