# Copyright 2016 Cloudbase Solutions Srl
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
"""Metadata Service for Packet."""

import json

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from oslo_log import log as oslo_logging

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class PacketService(base.BaseHTTPMetadataService):

    """Metadata Service for Packet.

    Packet is a NYC-based infrastructure startup, focused on reinventing
    how SaaS/PaaS companies go global with premium bare metal and container
    hosting.
    """

    def __init__(self):
        super(PacketService, self).__init__(
            base_url=CONF.packet.metadata_base_url,
            https_allow_insecure=CONF.packet.https_allow_insecure,
            https_ca_bundle=CONF.packet.https_ca_bundle)

        self._enable_retry = True

    def _get_meta_data(self):
        data = self._get_cache_data("metadata", decode=True)
        if data:
            return json.loads(data)

    def load(self):
        """Load all the available information from the metadata service."""
        super(PacketService, self).load()
        try:
            self._get_meta_data()
            return True
        except Exception:
            LOG.debug('Metadata not found at URL \'%s\'' %
                      CONF.packet.metadata_base_url)
            return False

    def get_instance_id(self):
        """Get the identifier for the current instance.

        The instance identifier provides an unique way to address an
        instance into the current metadata provider.
        """
        return self._get_meta_data().get("id")

    def get_host_name(self):
        """Get the hostname for the current instance.

        The hostname is the label assigned to the current instance used to
        identify it in various forms of electronic communication.
        """
        return self._get_meta_data().get("hostname")

    def get_public_keys(self):
        """Get a list of space-stripped strings as public keys."""
        meta_data = self._get_meta_data()
        ssh_keys = meta_data.get("ssh_keys")
        if not ssh_keys:
            return []
        return list(set((key.strip() for key in ssh_keys)))

    def get_user_data(self):
        """Get the available user data for the current instance."""
        return self._get_cache_data("userdata")
