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

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class Options(object):

    """Contact class for all the collections of config options."""

    def __init__(self, config, group="DEFAULT"):
        self._config = config
        self._group_name = group

    @property
    def group_name(self):
        """The group name for the current options."""
        return self._group_name

    @abc.abstractmethod
    def register(self):
        """Register the current options to the global ConfigOpts object."""
        pass

    @abc.abstractmethod
    def list(self):
        """Return a list which contains all the available options."""
        pass
