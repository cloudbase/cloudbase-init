# Copyright 2019 Cloudbase Solutions Srl
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
import re
import six


@six.add_metaclass(abc.ABCMeta)
class BaseTemplateEngine(object):
    def __init__(self):
        self._template_matcher = re.compile(r"##\s*template:(.*)", re.I)

    @abc.abstractmethod
    def get_template_type(self):
        """Return the template type for the class loader"""
        pass

    @abc.abstractmethod
    def render(self, data, template):
        """Renders the template according to the data dictionary

        The data variable is a dict which contains the key-values
        that will be used to render the template.

        The template is an encoded string which can contain special
        constructions that will be used by the template engine.

        The return value will be an encoded string.
        """

    def load(self, data):
        """Returns True if the template header matches, False otherwise"""
        if not data:
            return

        template_type_matcher = self._template_matcher.match(data.decode())
        if not template_type_matcher:
            return

        template_type = template_type_matcher.group(1).lower().strip()
        if self.get_template_type() == template_type:
            return True

    @staticmethod
    def remove_template_definition(raw_template):
        # return the raw template as is if it is None or empty array / dict
        if not raw_template:
            return raw_template

        # Remove the first line, as it contains the template definition
        template_split = raw_template.split(b"\n", 1)

        if len(template_split) == 2:
            # return the template without the header
            return template_split[1]

        # the template has just one line, return empty encoded string
        return b''
