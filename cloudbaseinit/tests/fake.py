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


class FakeComError(Exception):

    def __init__(self):
        super(FakeComError, self).__init__()
        self.excepinfo = [None, None, None, None, None, -2144108544]


class FakeError(Exception):

    def __init__(self, msg="Fake error."):
        super(FakeError, self).__init__(msg)
        self.winerror = None
