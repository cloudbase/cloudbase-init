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

import six

from oslo_log import log as oslo_logging


LOG = oslo_logging.getLogger(__name__)


def get_as_string(value):
    if value is None or isinstance(value, six.text_type):
        return value
    else:
        try:
            return value.decode()
        except Exception:
            # This is important, because None will be returned,
            # but not that serious to raise an exception.
            LOG.error("Couldn't decode: %r", value)


def write_file(target_path, data, mode='wb'):
    if isinstance(data, six.text_type) and 'b' in mode:
        data = data.encode()

    with open(target_path, mode) as f:
        f.write(data)
