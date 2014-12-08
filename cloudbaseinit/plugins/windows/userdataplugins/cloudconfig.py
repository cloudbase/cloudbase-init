# Copyright 2013 Mirantis Inc.
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

import base64
import gzip
import io
import os

from oslo.config import cfg
import yaml

from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.plugins.windows.userdataplugins import base


LOG = logging.getLogger(__name__)
OPTS = [
    cfg.ListOpt(
        'cloud_config_plugins',
        default=[],
        help=(
            'List which contains the name of the plugins ordered by priority.'
        ),
    )
]
CONF = cfg.CONF
CONF.register_opts(OPTS)

DEFAULT_MIME_TYPE = 'text/plain'
DEFAULT_PERMISSIONS = 0o644
BASE64_MIME = 'application/base64'
GZIP_MIME = 'application/x-gzip'


def decode_steps(encoding):
    """Predict the decoding steps required to obtain the initial content."""
    encoding = encoding.lower().strip() if encoding else ''
    if encoding in ('gz', 'gzip'):
        return [GZIP_MIME]

    if encoding in ('gz+base64', 'gzip+base64', 'gz+b64', 'gzip+b64'):
        return [BASE64_MIME, GZIP_MIME]

    if encoding in ('b64', 'base64'):
        return [BASE64_MIME]

    if encoding:
        LOG.warning("Unknown encoding type %s, assuming %s",
                    encoding, DEFAULT_MIME_TYPE)

    return [DEFAULT_MIME_TYPE]


def process_permissions(permissions):
    """Safe process the permissions value."""
    if type(permissions) in (int, float):
        permissions = int(permissions)
    else:
        try:
            permissions = int(permissions, 8)
        except (ValueError, TypeError):
            LOG.warning("Fail to process permissions %s, assuming %s",
                        permissions, DEFAULT_PERMISSIONS)
            permissions = DEFAULT_PERMISSIONS

    return permissions


def process_content(content, encoding):
    """Decode the content taking into consideration the encoding."""
    result = str(content)
    for mime_type in decode_steps(encoding):
        if mime_type == GZIP_MIME:
            bufferio = io.BytesIO(content)
            with gzip.GzipFile(fileobj=bufferio, mode='rb') as file_handle:
                try:
                    result = file_handle.read()
                except (IOError, ValueError) as exc:
                    LOG.exception(
                        "Fail to decompress gzip content. Exception: %s", exc)
        elif mime_type == BASE64_MIME:
            try:
                result = base64.b64decode(result)
            except (ValueError, TypeError) as exc:
                LOG.exception(
                    "Fail to decode base64 content. Exception: %s", exc)
    return result


def write_file(path, content, permissions=DEFAULT_PERMISSIONS, open_mode="wb"):
    """Writes a file with the given content

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


class CloudConfigPlugin(base.BaseUserDataPlugin):

    def __init__(self):
        super(CloudConfigPlugin, self).__init__("text/cloud-config")
        self._plugins_order = CONF.cloud_config_plugins

    def _priority(self, plugin):
        """Predict the priority for this plugin

        Returns a numeric value that represents the priority of the plugin
        designated by the received key.

        Note: If the priority for a plugin is not specified, it will designate
        the lowest priority for it.
        """
        try:
            return self._plugins_order.index(plugin)
        except ValueError:
            return len(self._plugins_order)

    def _content(self, part):
        """Iterator over the deserialized information from the receivedpart."""
        loader = getattr(yaml, 'CLoader', yaml.Loader)

        try:
            content = yaml.load(part, Loader=loader)
        except (ValueError, AttributeError):
            LOG.error("Invalid yaml stream provided.")
            return False

        if not isinstance(content, dict):
            LOG.warning("Unsupported content type %s", type(content))
            return False

        # Create a list that will contain the information received in the order
        # specified by the user.
        return sorted(content.items(),
                      key=lambda item: self._priority(item[0]))

    def plugin_write_files(self, files):
        """Plugin for writing files on the filesystem

        Receives a list of files in order to write them on disk.
        Each file that should be written is represented by a dictionary which
        can contain the following keys:
            path: The absolute path to the location on the filesystem where
            the file should be written.
            content: The content that should be placed in the file.
            owner: The user account and group that should be given ownership of
            the file.
            permissions: The octal permissions set that should be given for
            this file.
            encoding: An optional encoding specification for the file.

        Note: The only required keys in this dictionary are `path` and
        `content`.
        """

        for current_file in files:
            incomplete = False
            for required_key in ('path', 'content'):
                if required_key not in current_file:
                    incomplete = True
                    break
            if incomplete:
                LOG.warning("Missing required keys from file information %s",
                            current_file)
                continue

            path = os.path.abspath(current_file['path'])
            content = process_content(current_file['content'],
                                      current_file.get('encoding'))
            permissions = process_permissions(current_file.get('permissions'))
            write_file(path, content, permissions)

    def process(self, part):
        content = self._content(part) or []
        for key, value in content:
            method_name = "plugin_%s" % key.replace("-", "_")
            method = getattr(self, method_name, None)
            if not method:
                LOG.info("Plugin %s is currently not supported", key)
                continue

            try:
                method(value)
            except Exception as exc:
                LOG.exception(exc)
