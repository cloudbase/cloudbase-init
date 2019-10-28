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

import os
import re

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception


CONF = cloudbaseinit_conf.CONF
CONFIG_DRIVE_LABELS = ['config-2', 'CONFIG-2']
LOG = oslo_logging.getLogger(__name__)
VOLUME_LABEL_REGEX = re.compile("Volume label is (.*?)$")


def _check_mtools_path():
    if not CONF.mtools_path:
        raise exception.CloudbaseInitException(
            '"mtools_path" needs to be provided in order '
            'to access VFAT drives')


def is_vfat_drive(osutils, drive_path):
    """Check if the given drive contains a VFAT filesystem."""
    _check_mtools_path()
    mlabel = os.path.join(CONF.mtools_path, "mlabel.exe")
    args = [mlabel, "-i", drive_path, "-s"]

    out, err, exit_code = osutils.execute_process(args, shell=False)
    if exit_code:
        LOG.debug("Could not retrieve label for VFAT drive path %r",
                  drive_path)
        LOG.debug("mlabel failed with error %r", err)
        return False

    LOG.debug("Obtained label information for drive %r: %r", drive_path, out)
    out = out.decode().strip()
    match = VOLUME_LABEL_REGEX.search(out)
    return match.group(1) in CONFIG_DRIVE_LABELS if match else False


def copy_from_vfat_drive(osutils, drive_path, target_path):
    """Copy everything from the given VFAT drive into the given target."""
    _check_mtools_path()
    cwd = os.getcwd()
    try:
        os.chdir(target_path)

        # A mcopy call looks like this:
        #
        # mcopy -n -i \\.\PHYSICALDRIVEx ::/file/path destination/path
        mcopy = os.path.join(CONF.mtools_path, "mcopy.exe")
        args = [mcopy, "-s", "-n", "-i", drive_path, "::/", "."]
        osutils.execute_process(args, shell=False)
    finally:
        os.chdir(cwd)
