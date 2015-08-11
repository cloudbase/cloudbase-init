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

import contextlib

from oslo_config import cfg
from oslo_log import log as oslo_logging
from six.moves import http_client
from six.moves import urllib

from cloudbaseinit.metadata.services import base
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.utils import encoding


LOG = oslo_logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('cloudstack_metadata_ip', default="10.1.1.1",
               help='The IP adress where the service looks for metadata'),
]
CONF = cfg.CONF
CONF.register_opts(OPTS)

BAD_REQUEST = b"bad_request"
SAVED_PASSWORD = b"saved_password"
TIMEOUT = 10


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
        return self._get_cache_data('instance-id', decode=True)

    def get_host_name(self):
        """Hostname of the virtual machine."""
        return self._get_cache_data('local-hostname', decode=True)

    def get_user_data(self):
        """User data for this virtual machine."""
        return self._get_cache_data('../user-data')

    def get_public_keys(self):
        """Available ssh public keys."""
        ssh_keys = []
        ssh_chunks = self._get_cache_data('public-keys',
                                          decode=True).splitlines()
        for ssh_key in ssh_chunks:
            ssh_key = ssh_key.strip()
            if not ssh_key:
                continue
            ssh_keys.append(ssh_key)
        return ssh_keys

    def _get_password(self):
        """Get the password from the Password Server.

        The Password Server can be found on the DHCP_SERVER on the port 8080.
        .. note:
            The Password Server can return the following values:
                * `bad_request`:    the Password Server did not recognise
                                    the request
                * `saved_password`: the password was already deleted from
                                    the Password Server
                * ``:               the Password Server did not have any
                                    password for this instance
                * the password
        """
        LOG.debug("Try to get password from the Password Server.")
        headers = {"DomU_Request": "send_my_password"}
        password = None

        with contextlib.closing(http_client.HTTPConnection(
                self._router_ip, 8080, timeout=TIMEOUT)) as connection:

            for _ in range(CONF.retry_count):
                try:
                    connection.request("GET", "/", headers=headers)
                    response = connection.getresponse()
                except http_client.HTTPException as exc:
                    LOG.exception(exc)
                    continue

                if response.status != 200:
                    LOG.warning("Getting password failed: %(status)s "
                                "%(reason)s - %(message)r",
                                {"status": response.status,
                                 "reason": response.reason,
                                 "message": response.read()})
                    continue

                content = response.read().strip()
                if not content:
                    LOG.warning("The Password Server did not have any "
                                "password for the current instance.")
                    continue

                if content == BAD_REQUEST:
                    LOG.error("The Password Server did not recognise the "
                              "request.")
                    break

                if content == SAVED_PASSWORD:
                    LOG.warning("For this instance the password was already "
                                "taken from the Password Server.")
                    break

                LOG.info("The password server return a valid password "
                         "for the current instance.")
                password = encoding.get_as_string(content)
                break

        return password

    def _delete_password(self):
        """Delete the password from the Password Server.

        After the password is used, it must be deleted from the Password
        Server for security reasons.
        """
        LOG.debug("Remove the password for this instance from the "
                  "Password Server.")
        headers = {"DomU_Request": "saved_password"}
        connection = http_client.HTTPConnection(self._router_ip, 8080,
                                                timeout=TIMEOUT)
        for _ in range(CONF.retry_count):
            connection.request("GET", "/", headers=headers)
            response = connection.getresponse()
            if response.status != 200:
                LOG.warning("Removing password failed: %(status)s "
                            "%(reason)s - %(message)r",
                            {"status": response.status,
                             "reason": response.reason,
                             "message": response.read()})
                continue

            content = response.read()
            if content != BAD_REQUEST:    # comparing bytes with bytes
                LOG.info("The password was removed from the Password Server.")
                break
        else:
            LOG.warning("Fail to remove the password from the "
                        "Password Server.")

    def get_admin_password(self):
        """Get the admin pasword from the Password Server.

        .. note:
            The password is deleted from the Password Server after the first
            call of this method.
            Another request for password will work only if the password was
            changed and sent to the Password Server.
        """
        password = self._get_password()
        if password:
            self._delete_password()
        return password

    @property
    def can_update_password(self):
        """The CloudStack Password Server supports password update."""
        return True

    def is_password_changed(self):
        """Check if a new password exists in the Password Server."""
        return bool(self._get_password())
