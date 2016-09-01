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

"""
This is the single point of entry to generate the sample configuration
file for Cloudbase-Init.
"""

import collections

from cloudbaseinit.conf import base as conf_base
from cloudbaseinit.conf import factory as conf_factory


def get_options():
    """Collect all the options info from the other modules."""
    options = collections.defaultdict(list)
    for opt_class in conf_factory.get_options():
        if not issubclass(opt_class, conf_base.Options):
            continue
        config_options = opt_class(None)
        options[config_options.group_name].extend(config_options.list())
    return [(key, value) for key, value in options.items()]
