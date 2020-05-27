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

import ctypes


class CloudbaseInitException(Exception):
    pass


class ItemNotFoundException(CloudbaseInitException):
    pass


class InvalidStateException(CloudbaseInitException):
    pass


class ServiceException(Exception):

    """Base exception for all the metadata services related errors."""

    pass


class MetadataNotFoundException(CloudbaseInitException):

    """Exception thrown in case no metadata service is found."""

    pass


class MetadataEndpointException(CloudbaseInitException):

    """Exception thrown in case the metadata is unresponsive or errors out."""

    pass


class CertificateVerifyFailed(ServiceException):

    """The received certificate is not valid.

    In order to avoid the current exception, the validation of the SSL
    certificate should be disabled for the metadata provider. In order
    to do that the `https_allow_insecure` config option should be set.
    """

    pass


class WindowsCloudbaseInitException(CloudbaseInitException):

    def __init__(self, msg="%r", error_code=None):
        if error_code is None:
            error_code = ctypes.GetLastError()
        description = ctypes.FormatError(error_code)
        try:
            formatted_msg = msg % description
        except TypeError:
            formatted_msg = msg
        super(WindowsCloudbaseInitException, self).__init__(formatted_msg)
