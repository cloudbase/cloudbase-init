# Copyright 2019 ruilopes.com
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

import base64
import gzip
import io
import json
import os

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base
from cloudbaseinit.osutils import factory as osutils_factory

CONF = cloudbaseinit_conf.CONF

class VMwareGuestInfoService(base.BaseMetadataService):
    """
    This uses the VMware Guest Info interface to obtain the cloud init data
    from the VM extraconfig guestinfo properties using the VMware Tools
    rpctool cli application.

    You can use the following guestinfo properties:

    +--------------------+------------------------------------------------------+
    | property           | description                                          |
    +--------------------+------------------------------------------------------+
    | guestinfo.metadata | A JSON document containing the cloud-init metadata.  |
    | guestinfo.userdata | A YAML document containing the cloud-init userdata,  |
    |                    | or a MIME multipart message with the YAML document   |
    |                    | containing the cloud-init user data and custom       |
    |                    | scripts as described at doc/source/userdata.rst      |
    +--------------------+------------------------------------------------------+

    Each property value should be gzip compressed and must be base64 encoded.

    When using terraform, you can create a cloud init configuration with, e.g.:

        # a cloud-init userdata.
        # see https://www.terraform.io/docs/providers/template/d/cloudinit_config.html
        # see https://www.terraform.io/docs/configuration/expressions.html#string-literals
        data "template_cloudinit_config" "example" {
            part {
                content_type = "text/cloud-config"
                content = <<-EOF
                #cloud-config
                hostname: example
                timezone: Asia/Tbilisi
                EOF
            }
            part {
                filename = "example.ps1"
                content_type = "text/x-shellscript"
                content = <<-EOF
                #ps1_sysnative
                Start-Transcript -Append "C:\cloudinit-config-example.ps1.log"
                function Write-Title($title) {
                    Write-Output "`n#`n# $title`n#"
                }
                Write-Title "whoami"
                whoami /all
                Write-Title "Windows version"
                cmd /c ver
                Write-Title "Environment Variables"
                dir env:
                Write-Title "TimeZone"
                Get-TimeZone
                EOF
            }
        }

        # see https://www.terraform.io/docs/providers/vsphere/r/virtual_machine.html
        resource "vsphere_virtual_machine" "example" {
            ...
            # NB this extra_config data ends-up inside the VM .vmx file and will be
            #    exposed by cloudbase-init as a cloud-init datasource.
            extra_config = {
                "guestinfo.metadata" = base64gzip(jsonencode({
                    "admin-username": var.winrm_username,
                    "admin-password": var.winrm_password,
                    "public-keys": [trimspace(file("~/.ssh/id_rsa.pub"))],
                }))
                "guestinfo.userdata" = data.template_cloudinit_config.example.rendered
            }
            ...
        }

    NB The base image must have the VMware Tools installed.
    """

    def __init__(self):
        super(VMwareGuestInfoService, self).__init__()
        self._meta_data = None
        self._user_data = None
        self._os_utils = osutils_factory.get_os_utils()

    def load(self):
        super(VMwareGuestInfoService, self).load()
        if not os.path.exists(CONF.vmwareguestinfo.rpctool_path):
            return False
        self._meta_data = json.loads(self._get_guestinfo_value('metadata') or '{}')
        self._user_data = self._get_guestinfo_value('userdata')
        return True

    def _get_guestinfo_value(self, name):
        stdout, stderr, exit_code = self._os_utils.execute_process([
            CONF.vmwareguestinfo.rpctool_path,
            'info-get guestinfo.%s' % name
        ])
        if exit_code:
            raise exception.CloudbaseInitException(
                'Failed to execute "%(rpctool_path)s" with '
                'exit code: %(exit_code)s\nstdout: %(stdout)s\nstderr: %(stderr)s' % {
                    'rpctool_path': CONF.vmwareguestinfo.rpctool_path,
                    'exit_code': exit_code,
                    'stdout': stdout,
                    'stderr': stderr})
        data = base64.b64decode(stdout)
        if data[:2] == self._GZIP_MAGIC_NUMBER:
            with gzip.GzipFile(fileobj=io.BytesIO(data), mode='rb') as out:
                data = out.read()
        return data

    def _get_data(self, path):
        pass

    def get_user_data(self):
        return self._user_data

    def get_host_name(self):
        return self._meta_data.get('local-hostname')

    def get_public_keys(self):
        return self._meta_data.get('public-keys')

    def get_admin_username(self):
        return self._meta_data.get('admin-username')

    def get_admin_password(self):
        return self._meta_data.get('admin-password')
