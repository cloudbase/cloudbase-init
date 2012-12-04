# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Cloudbase Solutions Srl
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

from cloudbaseinit.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class Utils(object):
    def load_class(self, class_path):
        LOG.debug('Loading class \'%s\'' % class_path)
        parts = class_path.rsplit('.', 1)
        module = __import__(parts[0], fromlist=parts[1])
        return getattr(module, parts[1])
