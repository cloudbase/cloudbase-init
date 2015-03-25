# Copyright 2013 Cloudbase Solutions Srl
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

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock
from oslo.config import cfg

from cloudbaseinit.utils import network

CONF = cfg.CONF


class NetworkUtilsTest(unittest.TestCase):

    @mock.patch('sys.platform', new='win32')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('six.moves.urllib.parse.urlparse')
    def _test_check_metadata_ip_route(self, mock_urlparse, mock_get_os_utils,
                                      side_effect):
        mock_utils = mock.MagicMock()
        mock_split = mock.MagicMock()
        mock_get_os_utils.return_value = mock_utils
        mock_utils.check_os_version.return_value = True
        mock_urlparse().netloc.split.return_value = mock_split
        mock_split[0].startswith.return_value = True
        mock_utils.check_static_route_exists.return_value = False
        mock_utils.get_default_gateway.return_value = (1, '0.0.0.0')
        mock_utils.add_static_route.side_effect = [side_effect]
        network.check_metadata_ip_route('196.254.196.254')
        mock_utils.check_os_version.assert_called_once_with(6, 0)
        mock_urlparse.assert_called_with('196.254.196.254')
        mock_split[0].startswith.assert_called_once_with("169.254.")
        mock_utils.check_static_route_exists.assert_called_once_with(
            mock_split[0])
        mock_utils.get_default_gateway.assert_called_once_with()
        mock_utils.add_static_route.assert_called_once_with(
            mock_split[0], "255.255.255.255", '0.0.0.0', 1, 10)

    def test_test_check_metadata_ip_route(self):
        self._test_check_metadata_ip_route(side_effect=None)

    def test_test_check_metadata_ip_route_fail(self):
        self._test_check_metadata_ip_route(side_effect=Exception)
