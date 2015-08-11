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

import json
import threading

from oslo_log import log as oslo_logging
import pbr.version
import requests
import six


_UPDATE_CHECK_URL = 'https://www.cloudbase.it/checkupdates.php?p={0}&v={1}'
_PRODUCT_NAME = 'Cloudbase-Init'
LOG = oslo_logging.getLogger(__name__)


def _read_url(url):
    # Disable certificate verification on Python 2 as
    # requests's CA list is incomplete. Works fine on Python3.
    req = requests.get(url, verify=six.PY3,
                       headers={'User-Agent': _PRODUCT_NAME})
    req.raise_for_status()
    if req.text:
        return json.loads(req.text)


def _check_latest_version(callback):
    product_version = get_version()
    url = _UPDATE_CHECK_URL.format(_PRODUCT_NAME, product_version)
    try:
        content = _read_url(url)
        if not content:
            return

        version = content.get('new_version')
        if version:
            callback(version)

    except Exception as exc:
        LOG.debug('Failed checking for new versions: %s', exc)
        return


def check_latest_version(done_callback):
    """Try to obtain the latest version of the product."""
    thread = threading.Thread(target=_check_latest_version,
                              args=(done_callback, ))
    thread.daemon = True
    thread.start()


def get_version():
    """Obtain the project version."""
    version = pbr.version.VersionInfo('cloudbase-init')
    return version.release_string()
