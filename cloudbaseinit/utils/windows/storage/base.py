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

import abc

import six

SAN_POLICY_UNKNOWN = 0
SAN_POLICY_ONLINE = 1
SAN_POLICY_OFFLINE_SHARED = 2
SAN_POLICY_OFFLINE = 3


@six.add_metaclass(abc.ABCMeta)
class BaseStorageManager(object):

    @abc.abstractmethod
    def extend_volumes(self, volume_indexes=None):
        pass

    @abc.abstractmethod
    def get_san_policy(self):
        pass

    @abc.abstractmethod
    def set_san_policy(self, san_policy):
        pass
