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

from cloudbaseinit.utils import classloader
from oslo_log import log as oslo_logging

TEMPLATE_ENGINE_CLASS_PATHS = ["cloudbaseinit.utils.template_engine"
                               ".jinja2_template.Jinja2TemplateEngine"]
LOG = oslo_logging.getLogger(__name__)


def get_template_engine(user_data):
    """Returns the first template engine that loads correctly"""

    cl = classloader.ClassLoader()
    for class_path in TEMPLATE_ENGINE_CLASS_PATHS:
        tpl_engine = cl.load_class(class_path)()
        try:
            if tpl_engine.load(user_data):
                LOG.info("Using template engine: %s"
                         % tpl_engine.get_template_type())
                return tpl_engine
        except Exception as ex:
            LOG.error("Failed to load template engine '%s'" % class_path)
            LOG.exception(ex)
    return
