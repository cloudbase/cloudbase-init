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

import abc
import tempfile


class BaseConfigDriveManager(object, metaclass=abc.ABCMeta):

    def __init__(self):
        self.target_path = tempfile.mkdtemp()

    @abc.abstractmethod
    def get_config_drive_files(self, drive_label, metadata_file,
                               check_types=None, check_locations=None,
                               ):
        pass
