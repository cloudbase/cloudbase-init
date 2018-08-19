# Copyright 2018 Cloudbase Solutions Srl
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


@six.add_metaclass(abc.ABCMeta)
class BaseNetworkTeamManager(object):
    @abc.abstractmethod
    def create_team(self, team_name, mode, load_balancing_algorithm,
                    members, mac_address, primary_nic_name=None,
                    primary_nic_vlan_id=None, lacp_timer=None):
        pass

    @abc.abstractmethod
    def add_team_nic(self, team_name, nic_name, vlan_id):
        pass

    @abc.abstractmethod
    def delete_team(self, name):
        pass
