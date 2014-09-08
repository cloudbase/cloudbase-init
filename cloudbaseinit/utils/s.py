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

import sys

_unicode = None


def unicode(obj):
    def unicode_2(obj):
        import __builtin__
        return __builtin__.unicode(obj)

    def unicode_3(obj):
        return str(obj)

    global _unicode
    if not _unicode:
        if sys.version_info.major >= 3:
            _unicode = unicode_3
        else:
            _unicode = unicode_2

    return _unicode(obj)
