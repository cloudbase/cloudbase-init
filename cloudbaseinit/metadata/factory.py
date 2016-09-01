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

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.utils import classloader


CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


def get_metadata_service():
    # Return the first service that loads correctly
    cl = classloader.ClassLoader()
    for class_path in CONF.metadata_services:
        service = cl.load_class(class_path)()
        try:
            if service.load():
                return service
        except Exception as ex:
            LOG.error("Failed to load metadata service '%s'" % class_path)
            LOG.exception(ex)
    raise exception.CloudbaseInitException("No available service found")
