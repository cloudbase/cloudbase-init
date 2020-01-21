# Copyright 2012 Cloudbase Solutions Srl
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
import copy
import gzip
import io
import time

from oslo_log import log as oslo_logging
import requests
import six

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.utils import encoding

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class NotExistingMetadataException(Exception):
    pass


@six.add_metaclass(abc.ABCMeta)
class BaseMetadataService(object):
    _GZIP_MAGIC_NUMBER = b'\x1f\x8b'

    def __init__(self):
        self._cache = {}
        self._enable_retry = False

    def get_name(self):
        return self.__class__.__name__

    def load(self):
        self._cache = {}

    @abc.abstractmethod
    def _get_data(self, path):
        pass

    def _exec_with_retry(self, action):
        i = 0
        while True:
            try:
                return action()
            except NotExistingMetadataException:
                raise
            except Exception:
                if self._enable_retry and i < CONF.retry_count:
                    i += 1
                    time.sleep(CONF.retry_count_interval)
                else:
                    raise

    def _get_cache_data(self, path, decode=False):
        """Get meta data with caching and decoding support."""
        key = (path, decode)
        if key in self._cache:
            LOG.debug("Using cached copy of metadata: '%s'" % path)
            return self._cache[key]
        else:
            data = self._exec_with_retry(lambda: self._get_data(path))
            if decode:
                data = encoding.get_as_string(data)
            self._cache[key] = data
            return data

    def get_instance_id(self):
        pass

    def get_content(self, name):
        """Get raw content within a service."""

    def get_user_data(self):
        pass

    def get_decoded_user_data(self):
        """Get the decoded user data, if any

        The user data can be gzip-encoded, which means
        that every access to it should verify this fact,
        leading to code duplication.
        """
        user_data = self.get_user_data()
        if user_data and user_data[:2] == self._GZIP_MAGIC_NUMBER:
            bio = io.BytesIO(user_data)
            with gzip.GzipFile(fileobj=bio, mode='rb') as out:
                user_data = out.read()

        return user_data

    def get_host_name(self):
        pass

    def get_public_keys(self):
        """Get a list of space-stripped strings as public keys."""
        pass

    def get_user_pwd_encryption_key(self):
        """Get the user password encryption public key as a string.

        The encryption public key, if existent, will be used to encrypt the
        user password to be sent to the metadata service.
        By default, the first public key set by the user
        will be used to encrypt the user password.

        """
        public_keys = self.get_public_keys()
        if public_keys:
            return list(public_keys)[0]

    def get_network_details(self):
        """Return a list of `NetworkDetails` objects.

        These objects provide details regarding static
        network configuration, details which can be found
        in the namedtuple defined above.
        """

    def get_network_details_v2(self):
        """Return a `NetworkDetailsV2` object."""

    def get_admin_username(self):
        pass

    def get_admin_password(self):
        pass

    @property
    def can_post_password(self):
        return False

    @property
    def is_password_set(self):
        return False

    def post_password(self, enc_password_b64):
        pass

    def get_winrm_listeners_configuration(self):
        pass

    def get_server_certs(self):
        pass

    def get_vm_agent_package_provisioning_data(self):
        pass

    def get_client_auth_certs(self):
        pass

    def cleanup(self):
        pass

    @property
    def can_update_password(self):
        """The ability to update password of the metadata provider.

        If :meth:`~can_update_password` is True, plugins can check
        periodically (e.g. at every boot) if the password changed.

        :rtype: bool

        .. notes:
            The password will be updated only if the
            :meth:`~is_password_changed` returns True.
        """
        return False

    def is_password_changed(self):
        """Check if the metadata provider has a new password for this instance

        :rtype: bool

        .. notes:
            This method will be used only when :meth:`~can_update_password`
            is True.
        """
        return False

    def provisioning_started(self):
        pass

    def provisioning_completed(self):
        pass

    def provisioning_failed(self):
        pass

    @property
    def can_post_rdp_cert_thumbprint(self):
        return False

    def post_rdp_cert_thumbprint(self, thumbprint):
        pass

    def get_kms_host(self):
        pass

    def get_use_avma_licensing(self):
        pass

    def get_enable_automatic_updates(self):
        """Check if the metadata provider enforces automatic updates."""
        pass

    def get_ephemeral_disk_data_loss_warning(self):
        raise NotExistingMetadataException()

    def get_instance_data(self):
        """Returns a dictionary with instance data from the metadata source

        The instance data structure is based on the cloud-init specifications:
        https://cloudinit.readthedocs.io/en/latest/topics/instancedata.html

        The v1 namespace contains a subset of the cloud-init standard
        for the instance data. In the future, it should reach parity with the
        cloud-init standard.

        The ds.meta_data namespace contains all the values the v1 namespace
        contains, in order to be compatible with cloud-init, plus a subset of
        other instance data.
        The ds namespace can change without prior notice and should not be
        used in production.
        """

        instance_id = self.get_instance_id()
        hostname = self.get_host_name()

        v1_data = {
            "instance_id": instance_id,
            "local_hostname": hostname,
            "public_ssh_keys": self.get_public_keys()
        }

        # Copy the v1 data to the ds.meta_data and add more fields
        ds_meta_data = copy.deepcopy(v1_data)
        ds_meta_data.update({
            "hostname": hostname
        })

        return {
            "v1": v1_data,
            "ds": {
                "meta_data": ds_meta_data,
            }
        }


class BaseHTTPMetadataService(BaseMetadataService):

    """Contract class for metadata services that are using HTTP(S)."""

    def __init__(self, base_url, https_allow_insecure=False,
                 https_ca_bundle=None):
        """Setup a new metadata service.

        :param https_allow_insecure:
            Whether to disable the validation of HTTPS certificates
            (default False).
        :param base_url:
            The base URL where the service looks for metadata.
        :param https_ca_bundle:
            The path to a CA_BUNDLE file or directory with certificates
            of trusted CAs.

        .. note ::
            If `https_ca_bundle` is set to a path to a directory, the
            directory must have been processed using the c_rehash utility
            supplied with OpenSSL.
        """
        super(BaseHTTPMetadataService, self).__init__()
        self._https_allow_insecure = https_allow_insecure
        self._https_ca_bundle = https_ca_bundle
        self._base_url = base_url

    def _verify_https_request(self):
        """Whether to disable the validation of HTTPS certificates.

        When this option is `True` the SSL certificate validation for the
        current metadata provider will be disabled (please don't use it if
        you don't know the implications of this behaviour).
        """
        if self._https_ca_bundle:
            return self._https_ca_bundle
        else:
            return self._https_allow_insecure

    def _http_request(self, url, data=None, headers=None, method=None):
        """Get content for received url."""
        if not url.startswith("http"):
            url = requests.compat.urljoin(self._base_url, url)
        if not method:
            if data:
                method = "POST"
            else:
                method = "GET"
        method = method.upper()

        LOG.debug('Executing http request %s at %s', method, url)
        response = requests.request(method=method, url=url, data=data,
                                    headers=headers,
                                    verify=self._verify_https_request())
        response.raise_for_status()
        return response.content

    def _get_data(self, path):
        """Getting the required information using metadata service."""
        try:
            response = self._http_request(path)
        except requests.HTTPError as exc:
            if exc.response.status_code == 404:
                raise NotExistingMetadataException(
                    getattr(exc, "message", str(exc)))
            raise
        except requests.exceptions.SSLError as exc:
            LOG.exception(exc)
            raise exception.CertificateVerifyFailed(
                "HTTPS certificate validation failed.")
        except (requests.ConnectionError, requests.Timeout) as exc:
            LOG.exception(exc)
            raise

        return response


class EmptyMetadataService(BaseMetadataService):

    """Empty metadata service implementation.

    The empty metadata service can be used to run plugins that do not
    rely on metadata service information, like setting ntp, mtu, etc.
    It can be used also as a fallback metadata service, in case no other
    previous metadata service could be loaded.
    """

    def __init__(self):
        super(EmptyMetadataService, self).__init__()

    def _get_data(self, path):
        pass

    def load(self):
        return True

    def get_admin_username(self):
        raise NotExistingMetadataException()

    def get_admin_password(self):
        raise NotExistingMetadataException()

    def is_password_changed(self):
        raise NotExistingMetadataException()
