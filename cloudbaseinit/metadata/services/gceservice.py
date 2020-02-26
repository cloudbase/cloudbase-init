# Copyright 2020 Cloudbase Solutions Srl
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
import json

from datetime import datetime
from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)

GCE_METADATA_HEADERS = {'Metadata-Flavor': 'Google'}
MD_INSTANCE = "instance"
MD_INSTANCE_ATTR = "%s/attributes" % MD_INSTANCE
MD_PROJECT_ATTR = "project/attributes"


class GCEService(base.BaseHTTPMetadataService):

    def __init__(self):
        super(GCEService, self).__init__(
            base_url=CONF.gce.metadata_base_url,
            https_allow_insecure=CONF.gce.https_allow_insecure,
            https_ca_bundle=CONF.gce.https_ca_bundle)
        self._enable_retry = True

    def _http_request(self, url, data=None, headers=None, method=None):
        headers = headers or {}
        headers.update(GCE_METADATA_HEADERS)

        return super(GCEService, self)._http_request(url, data,
                                                     headers, method)

    def load(self):
        super(GCEService, self).load()

        try:
            self.get_host_name()
            return True
        except base.NotExistingMetadataException:
            LOG.debug("Metadata not found at URL '%s'",
                      CONF.gce.metadata_base_url)

    def get_host_name(self):
        return self._get_cache_data('%s/name' % MD_INSTANCE, decode=True)

    def get_instance_id(self):
        return self._get_cache_data('%s/id' % MD_INSTANCE, decode=True)

    def get_user_data(self):
        user_data = self._get_cache_data('%s/user-data' % MD_INSTANCE_ATTR)
        try:
            encoding = self._get_cache_data(
                '%s/user-data-encoding' % MD_INSTANCE_ATTR,
                decode=True)
            if encoding:
                if encoding == 'base64':
                    user_data = base64.b64decode(user_data)
                else:
                    LOG.warning("Encoding '%s' not supported. "
                                "Falling back to plaintext", encoding)
        except base.NotExistingMetadataException:
            LOG.info('Userdata encoding could not be found in the metadata.')

        return user_data

    def _is_ssh_key_valid(self, expire_on):
        if not expire_on:
            return True
        try:
            time_format = '%Y-%m-%dT%H:%M:%S+0000'
            expire_time = datetime.strptime(expire_on, time_format)
            return datetime.utcnow() <= expire_time
        except ValueError:
            # Note(ader1990): Return True to be consistent with cloud-init
            return True

    def _parse_gce_ssh_key(self, raw_ssh_key):
        # GCE public keys have a special format defined here:
        # https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys#sshkeyformat
        INVALID_SSH_KEY_MSG = "Skipping invalid SSH key %s"
        header_username = None
        meta_username = None

        if not raw_ssh_key:
            return

        ssh_key = raw_ssh_key.strip()

        # Key is in the format: USERNAME:ssh-rsa ...
        # Remove the username from the key
        ssh_key_split = ssh_key.split(':', 1)
        if len(ssh_key_split) != 2:
            LOG.warning(INVALID_SSH_KEY_MSG, ssh_key)
            return

        header_username, ssh_key = ssh_key_split

        key_parts = ssh_key.split(' ')
        len_key_parts = len(key_parts)

        if len_key_parts < 3:
            # Key format not supported: USERNAME:ssh-rsa [KEY]
            LOG.warning(INVALID_SSH_KEY_MSG, ssh_key)
            return
        elif len_key_parts == 3:
            # Key format: USERNAME:ssh-rsa [KEY] [USERNAME]
            meta_username = key_parts[2]
        else:
            # Key format: USERNAME:ssh-rsa [KEY] google-ssh [JSON_METADATA]
            delimiter = 'google-ssh'
            json_key_parts = ssh_key.split(delimiter)
            if (len(json_key_parts) == 2 and json_key_parts[1]):
                ssh_key_metadata = json.loads(json_key_parts[1].strip())
                meta_username = ssh_key_metadata['userName']
                if not self._is_ssh_key_valid(ssh_key_metadata['expireOn']):
                    LOG.warning("Skipping expired key: %s", ssh_key)
                    return
                ssh_key = '%s %s' % (json_key_parts[0].strip(), meta_username)
            else:
                LOG.warning(INVALID_SSH_KEY_MSG, ssh_key)
                return

        if not (header_username == meta_username == CONF.username):
            LOG.warning("Skipping key due to non matching username: %s",
                        ssh_key)
            return

        return ssh_key

    def _get_ssh_keys(self, locations):
        ssh_keys = []
        for location in locations:
            try:
                raw_ssh_keys = self._get_cache_data(location, decode=True)
                ssh_keys += raw_ssh_keys.strip().splitlines()
            except base.NotExistingMetadataException:
                LOG.warning("SSH keys not found at location %s", location)

        return ssh_keys

    def get_public_keys(self):
        ssh_keys = []
        raw_ssh_keys = []
        block_project_keys = False
        key_locations = ["%s/ssh-keys" % MD_INSTANCE_ATTR]

        # Use GCE latest metadata, where the SSH keys are found
        # only at hyphenated locations
        try:
            block_key = "%s/block-project-ssh-keys" % MD_INSTANCE_ATTR
            if self._get_cache_data(block_key, decode=True) == 'true':
                block_project_keys = True
        except base.NotExistingMetadataException:
                LOG.debug('block-project-ssh-keys not present')

        if not block_project_keys:
            key_locations += [
                "%s/ssh-keys" % MD_PROJECT_ATTR
            ]

        raw_ssh_keys += self._get_ssh_keys(key_locations)

        for raw_ssh_key in raw_ssh_keys:
            ssh_key = self._parse_gce_ssh_key(raw_ssh_key)
            if ssh_key:
                ssh_keys.append(ssh_key)

        return ssh_keys
