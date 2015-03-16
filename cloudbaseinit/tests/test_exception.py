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

import os
import unittest

from cloudbaseinit import exception
from cloudbaseinit.tests import testutils


WINDOWS = os.name == "nt"


@unittest.skipUnless(WINDOWS, "This requires the Windows platform.")
class TestException(testutils.CloudbaseInitTestBase):

    def test_windows_exception_no_error_code_given(self):
        with self.assert_raises_windows_message("Test %r", error_code=100):
            raise exception.WindowsCloudbaseInitException("Test %r")

    def test_windows_exception_error_code_given(self):
        with self.assert_raises_windows_message("Test %r", error_code=100):
            raise exception.WindowsCloudbaseInitException("Test %r",
                                                          error_code=100)
