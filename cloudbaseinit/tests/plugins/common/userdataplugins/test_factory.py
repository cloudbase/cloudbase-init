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

import unittest
import unittest.mock as mock

from cloudbaseinit.plugins.common.userdataplugins import factory


class UserDataPluginsFactoryTests(unittest.TestCase):

    @mock.patch('cloudbaseinit.utils.classloader.ClassLoader.load_class')
    def test_process(self, mock_load_class):
        response = factory.load_plugins()
        self.assertTrue(response is not None)
