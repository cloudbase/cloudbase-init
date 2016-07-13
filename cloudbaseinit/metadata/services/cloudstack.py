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
import posixpath

from oslo_log import log as oslo_logging
from six.moves import http_client
from six.moves import urllib

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.utils import encoding

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)

BAD_REQUEST = b"bad_request"
SAVED_PASSWORD = b"saved_password"
TIMEOUT = 10


class CloudStack(base.BaseHTTPMetadataService):

    def __init__(self):
        # Note: The base url used by the current metadata service will be
        #       updated later by the `_test_api` method.
        super(CloudStack, self).__init__(
            base_url=None,
            https_allow_insecure=CONF.cloudstack.https_allow_insecure,
            https_ca_bundle=CONF.cloudstack.https_ca_bundle)

        self._osutils = osutils_factory.get_os_utils()
        self._router_ip = None

    def _get_path(self, resource, version="latest"):
        """Get the relative path for the received resource."""
        return posixpath.normpath(
            posixpath.join(version, "meta-data", resource))

    def _test_api(self, metadata_url):
        """Test if the CloudStack API is responding properly."""
        self._base_url = metadata_url
        try:
            response = self._get_data(self._get_path("service-offering"))
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
        netloc = urllib.parse.urlparse(metadata_url).netloc
        self._router_ip = netloc.split(":")[0]
        return True

    def load(self):
        """Obtain all the required informations."""
        super(CloudStack, self).load()
        if self._test_api(CONF.cloudstack.metadata_base_url):
            return True

        dhcp_servers = self._osutils.get_dhcp_hosts_in_use()
        if not dhcp_servers:
            LOG.debug('No DHCP server was found.')
            return False
        for _, ip_address in dhcp_servers:
            LOG.debug('Testing: %s', ip_address)
            if self._test_api('http://%s/' % ip_address):
                return True

        return False

    def get_instance_id(self):
        """Instance name of the virtual machine."""
        return self._get_cache_data(self._get_path("instance-id"),
                                    decode=True)

    def get_host_name(self):
        """Hostname of the virtual machine."""
        return self._get_cache_data(self._get_path("local-hostname"),
                                    decode=True)

    def get_user_data(self):
        """User data for this virtual machine."""
        return self._get_cache_data(self._get_path('../user-data'))

    def get_public_keys(self):
        """Available ssh public keys."""
        ssh_keys = []
        ssh_chunks = self._get_cache_data(self._get_path("public-keys"),
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
