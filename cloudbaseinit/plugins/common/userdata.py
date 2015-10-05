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

import email

from oslo_log import log as oslo_logging

from cloudbaseinit.metadata.services import base as metadata_services_base
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import execcmd
from cloudbaseinit.plugins.common.userdataplugins import factory
from cloudbaseinit.plugins.common import userdatautils
from cloudbaseinit.utils import encoding
from cloudbaseinit.utils import x509constants


LOG = oslo_logging.getLogger(__name__)


class UserDataPlugin(base.BasePlugin):
    _PART_HANDLER_CONTENT_TYPE = "text/part-handler"
    _GZIP_MAGIC_NUMBER = b'\x1f\x8b'

    def execute(self, service, shared_data):
        try:
            user_data = service.get_decoded_user_data()
        except metadata_services_base.NotExistingMetadataException:
            return base.PLUGIN_EXECUTION_DONE, False

        if not user_data:
            return base.PLUGIN_EXECUTION_DONE, False

        LOG.debug('User data content length: %d' % len(user_data))
        return self._process_user_data(user_data)

    @staticmethod
    def _parse_mime(user_data):
        user_data_str = encoding.get_as_string(user_data)
        LOG.debug('User data content:\n%s', user_data_str)
        return email.message_from_string(user_data_str).walk()

    def _process_user_data(self, user_data):
        plugin_status = base.PLUGIN_EXECUTION_DONE
        reboot = False

        if user_data.startswith(b'Content-Type: multipart'):
            user_data_plugins = factory.load_plugins()
            user_handlers = {}

            for part in self._parse_mime(user_data):
                (plugin_status, reboot) = self._process_part(part,
                                                             user_data_plugins,
                                                             user_handlers)
                if reboot:
                    break

            if not reboot:
                for handler_func in list(set(user_handlers.values())):
                    self._end_part_process_event(handler_func)

            return plugin_status, reboot
        else:
            return self._process_non_multi_part(user_data)

    def _process_part(self, part, user_data_plugins, user_handlers):
        ret_val = None
        try:
            content_type = part.get_content_type()

            handler_func = user_handlers.get(content_type)
            if handler_func:
                LOG.debug("Calling user part handler for content type: %s" %
                          content_type)
                handler_func(None, content_type, part.get_filename(),
                             part.get_payload())
            else:
                user_data_plugin = user_data_plugins.get(content_type)
                if not user_data_plugin:
                    LOG.info("Userdata plugin not found for content type: %s" %
                             content_type)
                else:
                    LOG.debug("Executing userdata plugin: %s" %
                              user_data_plugin.__class__.__name__)

                    if content_type == self._PART_HANDLER_CONTENT_TYPE:
                        new_user_handlers = user_data_plugin.process(part)
                        self._add_part_handlers(user_data_plugins,
                                                user_handlers,
                                                new_user_handlers)
                    else:
                        ret_val = user_data_plugin.process(part)
        except Exception as ex:
            LOG.error('Exception during multipart part handling: '
                      '%(content_type)s, %(filename)s' %
                      {'content_type': part.get_content_type(),
                       'filename': part.get_filename()})
            LOG.exception(ex)

        return execcmd.get_plugin_return_value(ret_val)

    def _add_part_handlers(self, user_data_plugins, user_handlers,
                           new_user_handlers):
        handler_funcs = set()

        for (content_type,
             handler_func) in new_user_handlers.items():
            if not user_data_plugins.get(content_type):
                LOG.info("Adding part handler for content "
                         "type: %s" % content_type)
                user_handlers[content_type] = handler_func
                handler_funcs.add(handler_func)
            else:
                LOG.info("Skipping part handler for content type \"%s\" as it "
                         "is already managed by a plugin" % content_type)

        for handler_func in handler_funcs:
            self._begin_part_process_event(handler_func)

    def _begin_part_process_event(self, handler_func):
        LOG.debug("Calling part handler \"__begin__\" event")
        handler_func(None, "__begin__", None, None)

    def _end_part_process_event(self, handler_func):
        LOG.debug("Calling part handler \"__end__\" event")
        handler_func(None, "__end__", None, None)

    def _process_non_multi_part(self, user_data):
        ret_val = None
        if user_data.startswith(b'#cloud-config'):
            user_data_plugins = factory.load_plugins()
            cloud_config_plugin = user_data_plugins.get('text/cloud-config')
            ret_val = cloud_config_plugin.process_non_multipart(user_data)
        elif user_data.strip().startswith(x509constants.PEM_HEADER.encode()):
            LOG.debug('Found X509 certificate in userdata')
        else:
            ret_val = userdatautils.execute_user_data_script(user_data)

        return execcmd.get_plugin_return_value(ret_val)
