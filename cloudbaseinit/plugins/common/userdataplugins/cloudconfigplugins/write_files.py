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

import base64
import gzip
import io
import os

from oslo_log import log as oslo_logging
import six

from cloudbaseinit import exception
from cloudbaseinit.plugins.common.userdataplugins.cloudconfigplugins import (
    base
)


DEFAULT_PERMISSIONS = 0o644
BASE64_MIME = 'application/base64'
GZIP_MIME = 'application/x-gzip'
LOG = oslo_logging.getLogger(__name__)


def _decode_steps(encoding):
    encoding = encoding.lower().strip() if encoding else ''
    if encoding in ('gz', 'gzip'):
        return [GZIP_MIME]
    if encoding in ('gz+base64', 'gzip+base64', 'gz+b64', 'gzip+b64'):
        return [BASE64_MIME, GZIP_MIME]
    if encoding in ('b64', 'base64'):
        return [BASE64_MIME]
    return []


def _convert_permissions(permissions):
    if isinstance(permissions, (int, float)):
        return int(permissions)
    try:
        permissions = int(permissions, 8)
    except (ValueError, TypeError):
        LOG.warning("Fail to process permissions %s, assuming %s",
                    permissions, DEFAULT_PERMISSIONS)
        permissions = DEFAULT_PERMISSIONS

    return permissions


def _process_content(content, encoding):
    """Decode the content taking into consideration the encoding."""
    result = content
    if six.PY3 and not isinstance(result, six.binary_type):
        # At this point, content will be string, which is wrong for Python 3.
        result = result.encode()

    steps = _decode_steps(encoding)
    if not steps:
        LOG.error("Unknown encoding, doing nothing.")
        return result

    for mime_type in _decode_steps(encoding):
        if mime_type == GZIP_MIME:
            bufferio = io.BytesIO(result)
            with gzip.GzipFile(fileobj=bufferio, mode='rb') as file_handle:
                try:
                    result = file_handle.read()
                except (IOError, ValueError):
                    LOG.exception("Fail to decompress gzip content.")
        elif mime_type == BASE64_MIME:
            try:
                result = base64.b64decode(result)
            except (ValueError, TypeError):
                LOG.exception("Fail to decode base64 content.")
    return result


def _write_file(path, content, permissions=DEFAULT_PERMISSIONS,
                open_mode="wb"):
    """Writes a file with the given content.

    Also the function sets the file mode as specified.
    The function arguments are the following:
        path: The absolute path to the location on the filesystem where
        the file should be written.
        content: The content that should be placed in the file.
        permissions:The octal permissions set that should be given for
        this file.
        open_mode: The open mode used when opening the file.
    """
    dirname = os.path.dirname(path)
    if not os.path.isdir(dirname):
        try:
            os.makedirs(dirname)
        except OSError as exc:
            LOG.exception(exc)
            return False

    with open(path, open_mode) as file_handle:
        file_handle.write(content)
        file_handle.flush()

    os.chmod(path, permissions)
    return True


class WriteFilesPlugin(base.BaseCloudConfigPlugin):
    """Plugin for writing files on the filesystem.

    It can process either a list of files or only one file,
    where the file is represented by a dictionary, which
    can contain the following keys:

        path: The absolute path to the location on the filesystem where
        the file should be written.
        content: The content that should be placed in the file.
        owner: The user account and group that should be given ownership of
        the file.
        permissions: The octal permissions set that should be given for
        this file.
        encoding: An optional encoding specification for the file.

    The only required keys in this dictionary are `path` and `content`.
    """

    def _process_item(self, item):
        if not {'path', 'content'}.issubset(set(item)):
            LOG.warning("Missing required keys from file information %s",
                        item)
            return

        path = os.path.abspath(item['path'])
        content = _process_content(item['content'],
                                   item.get('encoding'))
        permissions = _convert_permissions(item.get('permissions'))
        _write_file(path, content, permissions)

    def process(self, data):
        """Process the given data received from the cloud-config userdata.

        It knows to process only lists and dicts.
        """

        if not isinstance(data, (list, dict)):
            raise exception.CloudbaseInitException(
                "Can't process the type of data %r" % type(data))

        if isinstance(data, dict):
            data = [data]

        for item in data:
            self._process_item(item)
