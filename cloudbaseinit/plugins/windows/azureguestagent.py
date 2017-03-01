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

import datetime
import os
import shutil
import zipfile

from oslo_log import log as oslo_logging
from six.moves import winreg

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)

SERVICE_NAME_RDAGENT = "RdAgent"
SERVICE_NAME_WAGUESTAGENT = "WindowsAzureGuestAgent"
SERVICE_NAME_WA_TELEMETRY = "WindowsAzureTelemetryService"
RDAGENT_FILENAME = "WaAppAgent.exe"

GUEST_AGENT_FILENAME = "Microsoft.Azure.Agent.Windows.exe"
NANO_VMAGENT_FILENAME = "WaSvc.exe"
GUEST_AGENT_EVENTNAME = "Global\AzureAgentStopRequest"

LOGMAN_TRACE_NOT_RUNNING = 0x80300104
LOGMAN_TRACE_NOT_FOUND = 0x80300002

GUEST_AGENT_ROOT_PATH = "WindowsAzure"
PACKAGES_ROOT_PATH = "Packages"
GUEST_AGENT_SOURCE_PATH = '$$\\OEM\GuestAgent'

VM_AGENT_PACKAGE = "VmAgent_Nano.zip"


class AzureGuestAgentPlugin(base.BasePlugin):
    @staticmethod
    def _check_delete_service(osutils, service_name):
        if osutils.check_service_exists(service_name):
            svc_status = osutils.get_service_status(service_name)
            if svc_status != osutils.SERVICE_STATUS_STOPPED:
                osutils.stop_service(service_name, wait=True)
            osutils.delete_service(service_name)

    @staticmethod
    def _remove_agent_services(osutils):
        LOG.info("Stopping and removing any existing Azure guest agent "
                 "services")
        for service_name in [
                SERVICE_NAME_RDAGENT, SERVICE_NAME_WAGUESTAGENT,
                SERVICE_NAME_WA_TELEMETRY]:
            AzureGuestAgentPlugin._check_delete_service(
                osutils, service_name)

    @staticmethod
    def _remove_azure_dirs():
        for path in [GUEST_AGENT_ROOT_PATH, PACKAGES_ROOT_PATH]:
            full_path = os.path.join(os.getenv("SystemDrive"), "\\", path)
            if os.path.exists(full_path):
                LOG.info("Removing folder: %s", full_path)
                try:
                    shutil.rmtree(full_path)
                except Exception as ex:
                    LOG.error("Failed to remove path: %s", full_path)
                    LOG.exception(ex)

    @staticmethod
    def _set_registry_vm_type(vm_type="IAAS"):
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,
                              "SOFTWARE\\Microsoft\\Windows Azure") as key:
            winreg.SetValueEx(key, "VMType", 0, winreg.REG_SZ, vm_type)

    @staticmethod
    def _set_registry_ga_params(install_version, install_timestamp):
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,
                              "SOFTWARE\\Microsoft\\GuestAgent") as key:

            install_version_str = "%s.%s.%s.%s" % install_version
            winreg.SetValueEx(
                key, "Incarnation", 0, winreg.REG_SZ, install_version_str)

            install_timestamp_str = install_timestamp.strftime(
                '%m/%d/%Y %I:%M:%S %p')
            winreg.SetValueEx(
                key, "VmProvisionedAt", 0, winreg.REG_SZ,
                install_timestamp_str)

    @staticmethod
    def _configure_vm_agent(osutils, vm_agent_target_path):
        vm_agent_zip_path = os.path.join(os.getenv("SystemDrive"), '\\',
                                         "Windows", "NanoGuestAgent",
                                         VM_AGENT_PACKAGE)
        vm_agent_log_path = os.path.join(os.getenv("SystemDrive"), '\\',
                                         GUEST_AGENT_ROOT_PATH, "Logs")
        if not os.path.exists(vm_agent_log_path):
            os.makedirs(vm_agent_log_path)
        with zipfile.ZipFile(vm_agent_zip_path) as zf:
            zf.extractall(vm_agent_target_path)
        vm_agent_service_path = os.path.join(
            vm_agent_target_path, NANO_VMAGENT_FILENAME)
        vm_agent_service_path = ("{service_path} -name {agent_name} -ownLog "
                                 "{log_path}\\W_svc.log -svcLog {log_path}"
                                 "\\S_svc.log -event {event_name} -- "
                                 "{vm_agent_target_path}\\"
                                 "{guest_agent}".format(
                                     service_path=vm_agent_service_path,
                                     agent_name=SERVICE_NAME_WAGUESTAGENT,
                                     log_path=vm_agent_log_path,
                                     event_name=GUEST_AGENT_EVENTNAME,
                                     vm_agent_target_path=vm_agent_target_path,
                                     guest_agent=GUEST_AGENT_FILENAME))

        osutils.create_service(
            SERVICE_NAME_WAGUESTAGENT, SERVICE_NAME_WAGUESTAGENT,
            vm_agent_service_path, osutils.SERVICE_START_MODE_MANUAL)

    @staticmethod
    def _configure_rd_agent(osutils, ga_target_path):
        rd_agent_service_path = os.path.join(
            ga_target_path, RDAGENT_FILENAME)
        # TODO(alexpilotti): Add a retry here as the service could have been
        # marked for deletion
        osutils.create_service(
            SERVICE_NAME_RDAGENT, SERVICE_NAME_RDAGENT,
            rd_agent_service_path, osutils.SERVICE_START_MODE_MANUAL)

        path = os.path.join(ga_target_path, "TransparentInstaller.dll")
        ga_version = osutils.get_file_version(path)
        ga_install_time = datetime.datetime.now()

        AzureGuestAgentPlugin._set_registry_vm_type()
        AzureGuestAgentPlugin._set_registry_ga_params(
            ga_version, ga_install_time)

    @staticmethod
    def _stop_event_trace(osutils, name, ets=False):
        return AzureGuestAgentPlugin._run_logman(osutils, "stop", name, ets)

    @staticmethod
    def _delete_event_trace(osutils, name):
        return AzureGuestAgentPlugin._run_logman(osutils, "delete", name)

    @staticmethod
    def _run_logman(osutils, action, name, ets=False):
        args = ["logman.exe"]
        if ets:
            args += ["-ets"]
        args += [action, name]
        (out, err, ret_val) = osutils.execute_system32_process(args)
        if ret_val not in [
                0, LOGMAN_TRACE_NOT_RUNNING, LOGMAN_TRACE_NOT_FOUND]:
            LOG.error(
                'logman failed.\nExit code: %(ret_val)s\n'
                'Output: %(out)s\nError: %(err)s',
                {'ret_val': hex(ret_val), 'out': out, 'err': err})

    @staticmethod
    def _stop_ga_event_traces(osutils):
        LOG.info("Stopping Azure guest agent event traces")
        AzureGuestAgentPlugin._stop_event_trace(osutils, "GAEvents")
        AzureGuestAgentPlugin._stop_event_trace(osutils, "RTEvents")
        AzureGuestAgentPlugin._stop_event_trace(
            osutils, "WindowsAzure-GuestAgent-Metrics", ets=True)
        AzureGuestAgentPlugin._stop_event_trace(
            osutils, "WindowsAzure-GuestAgent-Diagnostic", ets=True)

    @staticmethod
    def _delete_ga_event_traces(osutils):
        LOG.info("Deleting Azure guest agent event traces")
        AzureGuestAgentPlugin._delete_event_trace(osutils, "GAEvents")
        AzureGuestAgentPlugin._delete_event_trace(osutils, "RTEvents")

    @staticmethod
    def _get_guest_agent_source_path(osutils):
        base_paths = osutils.get_logical_drives()
        for base_path in base_paths:
            path = os.path.join(base_path, GUEST_AGENT_SOURCE_PATH)
            if os.path.exists(path):
                return path
        raise exception.CloudbaseInitException(
            "Azure guest agent source folder not found")

    def execute(self, service, shared_data):
        provisioning_data = service.get_vm_agent_package_provisioning_data()
        if not provisioning_data:
            LOG.info("Azure guest agent provisioning data not present")
        elif not provisioning_data.get("provision"):
            LOG.info("Skipping Azure guest agent provisioning as by metadata "
                     "request")
        else:
            osutils = osutils_factory.get_os_utils()

            self._remove_agent_services(osutils)
            # TODO(alexpilotti): Check for processes that might still be
            # running
            self._remove_azure_dirs()

            if not osutils.is_nano_server():
                ga_package_name = provisioning_data.get("package_name")
                if not ga_package_name:
                    raise exception.ItemNotFoundException(
                        "Azure guest agent package_name not found in metadata")
                LOG.debug("Azure guest agent package name: %s",
                          ga_package_name)

                ga_path = self._get_guest_agent_source_path(osutils)
                ga_zip_path = os.path.join(ga_path, ga_package_name)
                if not os.path.exists(ga_zip_path):
                    raise exception.CloudbaseInitException(
                        "Azure guest agent package file not found: %s" %
                        ga_zip_path)

                self._stop_ga_event_traces(osutils)
                self._delete_ga_event_traces(osutils)

                ga_target_path = os.path.join(
                    os.getenv("SystemDrive"), '\\', GUEST_AGENT_ROOT_PATH,
                    "Packages")

                if os.path.exists(ga_target_path):
                    shutil.rmtree(ga_target_path)
                os.makedirs(ga_target_path)

                with zipfile.ZipFile(ga_zip_path) as zf:
                    zf.extractall(ga_target_path)

                self._configure_rd_agent(osutils, ga_target_path)

                if not osutils.check_dotnet_is_installed("4"):
                    LOG.warn("The .Net framework 4.5 or greater is required "
                             "by the Azure guest agent")
                else:
                    osutils.set_service_start_mode(
                        SERVICE_NAME_RDAGENT,
                        osutils.SERVICE_START_MODE_AUTOMATIC)
                    osutils.start_service(SERVICE_NAME_RDAGENT)
            else:
                vm_agent_target_path = os.path.join(
                    os.getenv("SystemDrive"), '\\', GUEST_AGENT_ROOT_PATH,
                    "Packages", "GuestAgent")
                if not os.path.exists(vm_agent_target_path):
                    os.makedirs(vm_agent_target_path)
                self._configure_vm_agent(osutils, vm_agent_target_path)

                osutils.set_service_start_mode(
                    SERVICE_NAME_WAGUESTAGENT,
                    osutils.SERVICE_START_MODE_AUTOMATIC)
                osutils.start_service(SERVICE_NAME_WAGUESTAGENT)

        return base.PLUGIN_EXECUTION_DONE, False

    def get_os_requirements(self):
        return 'win32', (6, 1)
