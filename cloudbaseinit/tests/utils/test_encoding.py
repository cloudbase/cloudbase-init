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


import os
import tempfile
import unittest

from cloudbaseinit.tests import testutils
from cloudbaseinit.utils import encoding


class TestEncoding(unittest.TestCase):

    def test_get_as_string(self):
        self.assertIsNone(encoding.get_as_string(None))
        content_map = [
            ("data", "data"),
            (b"data", "data"),
            ("data".encode(), "data"),
            ("data".encode("utf-16"), None)
        ]
        with testutils.LogSnatcher("cloudbaseinit.utils.encoding") as snatch:
            for content, expect in content_map:
                self.assertEqual(expect, encoding.get_as_string(content))
        self.assertIn("couldn't decode", snatch.output[0].lower())

    def test_write_file(self):
        mode_map = [
            (("w", "r"), "my test\ndata\n\n", False),
            (("wb", "rb"), "\r\n".join((chr(x) for x in
                                        (32, 125, 0))).encode(), False),
            (("wb", "rb"), "my test\ndata\n\n", True),
            (("wb", "rb"), u"my test\n data", True)
        ]
        with testutils.create_tempdir() as temp:
            fd, path = tempfile.mkstemp(dir=temp)
            os.close(fd)
            for (write, read), data, encode in mode_map:
                encoding.write_file(path, data, mode=write)
                with open(path, read) as stream:
                    content = stream.read()
                if encode:
                    data = data.encode()
                self.assertEqual(data, content)

    def test_hex_to_bytes(self):
        result = encoding.hex_to_bytes("66616b652064617461")
        self.assertEqual(result, b"fake data")
