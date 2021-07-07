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
import jinja2

from cloudbaseinit.utils.template_engine import base_template

MISSING_JINJA_VARIABLE = u'CI_MISSING_JINJA_VAR/'


class MissingJinjaVariable(jinja2.DebugUndefined):
    """Missing Jinja2 variable class."""

    def __str__(self):
        return u'%s%s' % (MISSING_JINJA_VARIABLE, self._undefined_name)


class Jinja2TemplateEngine(base_template.BaseTemplateEngine):
    def get_template_type(self):
        return 'jinja'

    def render(self, data, raw_template):
        """Renders the template using Jinja2 template engine

        The data variable is a dict which contains the key-values
        that will be used to render the template.

        The template is an encoded string which can contain special
        constructions that will be used by the template engine.

        The return value will be an encoded string.
        """

        template = self.remove_template_definition(raw_template).decode()
        jinja_template = jinja2.Template(template,
                                         trim_blocks=True,
                                         undefined=MissingJinjaVariable,)
        return jinja_template.render(**data).encode()
