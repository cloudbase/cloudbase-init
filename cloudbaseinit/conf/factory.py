# Copyright 2016 Cloudbase Solutions Srl
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

from cloudbaseinit.utils import classloader

_OPT_PATHS = (
    'cloudbaseinit.conf.cloudconfig.CloudConfigOptions',
    'cloudbaseinit.conf.cloudstack.CloudStackOptions',
    'cloudbaseinit.conf.default.GlobalOptions',
    'cloudbaseinit.conf.ec2.EC2Options',
    'cloudbaseinit.conf.maas.MAASOptions',
    'cloudbaseinit.conf.openstack.OpenStackOptions',
)


def get_options():
    """Return a list of all the available `Options` subclasses."""
    loader = classloader.ClassLoader()
    return [loader.load_class(class_path) for class_path in _OPT_PATHS]
