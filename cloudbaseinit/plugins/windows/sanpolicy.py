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

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import constant
from cloudbaseinit.plugins.common import base
from cloudbaseinit.utils.windows.storage import base as storage_base
from cloudbaseinit.utils.windows.storage import factory as storage_factory

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class SANPolicyPlugin(base.BasePlugin):

    def execute(self, service, shared_data):
        san_policy_map = {
            constant.SAN_POLICY_ONLINE_STR: storage_base.SAN_POLICY_ONLINE,
            constant.SAN_POLICY_OFFLINE_STR: storage_base.SAN_POLICY_OFFLINE,
            constant.SAN_POLICY_OFFLINE_SHARED_STR:
            storage_base.SAN_POLICY_OFFLINE_SHARED,
        }

        if CONF.san_policy:
            storage_manager = storage_factory.get_storage_manager()

            new_san_policy = san_policy_map[CONF.san_policy]
            if storage_manager.get_san_policy() != new_san_policy:
                storage_manager.set_san_policy(new_san_policy)
                LOG.info("SAN policy set to: %s", new_san_policy)

        return base.PLUGIN_EXECUTION_DONE, False

    def get_os_requirements(self):
        return 'win32', (6, 1)
