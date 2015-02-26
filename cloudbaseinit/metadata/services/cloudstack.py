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

from oslo.config import cfg
from six.moves import urllib

from cloudbaseinit.metadata.services import base
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('cloudstack_metadata_ip', default="10.1.1.1",
               help='The IP adress where the service looks for metadata'),
]
CONF = cfg.CONF
CONF.register_opts(OPTS)


class CloudStack(base.BaseMetadataService):

    URI_TEMPLATE = 'http://%s/latest/meta-data/'

    def __init__(self):
        super(CloudStack, self).__init__()
        self.osutils = osutils_factory.get_os_utils()
        self._metadata_uri = None
        self._router_ip = None

    def _test_api(self, ip_address):
        """Test if the CloudStack API is responding properly."""
        self._metadata_uri = self.URI_TEMPLATE % ip_address
        try:
            response = self._http_request(self._metadata_uri)
            self._get_data('service-offering')
        except urllib.error.HTTPError as exc:
            LOG.debug('Error response code: %s', exc.code)
            return False
        except base.NotExistingMetadataException:
            LOG.debug('Invalid service response.')
            return False
        except Exception as exc:
            LOG.debug('Something went wrong.')
            LOG.exception(exc)
            return False

        LOG.debug('Available services: %s', response)
        self._router_ip = ip_address
        return True

    def load(self):
        """Obtain all the required informations."""
        super(CloudStack, self).load()
        if self._test_api(CONF.cloudstack_metadata_ip):
            return True

        dhcp_servers = self.osutils.get_dhcp_hosts_in_use()
        if not dhcp_servers:
            LOG.debug('No DHCP server was found.')
            return False
        for _, ip_address in dhcp_servers:
            LOG.debug('Testing: %s', ip_address)
            if self._test_api(ip_address):
                return True

        return False

    def _http_request(self, url, **kwargs):
        """Get content for received url."""
        LOG.debug('Getting metadata from:  %s', url)
        request = urllib.request.Request(url, **kwargs)
        response = urllib.request.urlopen(request)
        return response.read()

    def _get_data(self, path):
        """Getting required metadata using CloudStack metadata API."""
        metadata_uri = urllib.parse.urljoin(self._metadata_uri, path)
        try:
            content = self._http_request(metadata_uri)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise base.NotExistingMetadataException()
            raise
        return content

    def get_instance_id(self):
        """Instance name of the virtual machine."""
        return self._get_cache_data('instance-id')

    def get_host_name(self):
        """Hostname of the virtual machine."""
        return self._get_cache_data('local-hostname')

    def get_user_data(self):
        """User data for this virtual machine."""
        return self._get_cache_data('../user-data')

    def get_public_keys(self):
        """Available ssh public keys."""
        ssh_keys = []
        for ssh_key in self._get_cache_data('public-keys').splitlines():
            ssh_key = ssh_key.strip()
            if not ssh_key:
                continue
            ssh_keys.append(ssh_key)
        return ssh_keys
