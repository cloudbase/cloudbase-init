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

import os
import re
import tempfile
import uuid
import email
import errno

from cloudbaseinit.metadata.services import base as metadata_services_base
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins import base
from cloudbaseinit.plugins.windows.userdata_plugins import PluginSet
from cloudbaseinit.openstack.common import cfg


opts = [
    cfg.StrOpt('user_data_folder', default='cloud-data',
        help='Specifies a folder to store multipart data files.'),
    ]


CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)


class UserDataPlugin(base.BasePlugin): 
    def __init__(self, cfg=CONF):
        self.cfg = cfg
        self.msg = None
        self.plugin_set = PluginSet(self.get_plugin_path())
        self.plugin_set.reload()
        return

    def get_plugin_path(self):
        return os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))),
                 "windows/userdata-plugins")
    
    def execute(self, service):
        try:
            user_data = service.get_user_data('openstack')
        except metadata_services_base.NotExistingMetadataException:
            return (base.PLUGIN_EXECUTION_DONE, False)

        if not user_data:
            return (base.PLUGIN_EXECUTION_DONE, False)

        self.process_userdata(user_data)
        return (base.PLUGIN_EXECUTION_DONE, False)
    
    def process_userdata(self, user_data):
        LOG.debug('User data content:\n%s' % user_data)
        if user_data.startswith('Content-Type: multipart'):
            for part in self.parse_MIME(user_data):
                self.process_part(part)
        else:
            handle(user_data)
        return
        
    def process_part(self, part):
        part_handler = self.get_part_handler(part)
        if part_handler is not None:
            try:
                self.begin_part_process_event(part)
                LOG.info("Processing part %s filename: %s with handler: %s", part.get_content_type(), part.get_filename(), part_handler.name)
                part_handler.process(part)
                self.end_part_process_event(part)
            except Exception,e:
                LOG.error('Exception during multipart part handling: %s %s \n %s' , part.get_content_type(), part.get_filename(), e)
        return
    
    def begin_part_process_event(self, part):
        handler = self.get_custom_handler(part)
        if handler is not None:
            try:
              handler("","__begin__", part.get_filename(), part.get_payload())
            except Exception,e:
                LOG.error("Exception occurred during custom handle script invocation (__begin__): %s ", e)
        return
    
    def end_part_process_event(self, part):
        handler = self.get_custom_handler(part)
        if handler is not None:
            try:
              handler("","__end__", part.get_filename(), part.get_payload())
            except Exception,e:
              LOG.error("Exception occurred during custom handle script invocation (__end__): %s ", e)
        return
    
    
    def get_custom_handler(self, part):
        if self.plugin_set.has_custom_handlers:
            if part.get_content_type() in self.plugin_set.custom_handlers:
                handler = self.plugin_set.custom_handlers[part.get_content_type()]
                return handler
        return None

    def get_part_handler(self, part):
        if part.get_content_type() in self.plugin_set.set:
            handler = self.plugin_set.set[part.get_content_type()]
            return handler
        else:
            return None
    
    def parse_MIME(self, user_data):
        self.msg = email.message_from_string(user_data)
        return self.msg.walk()

    
    
def handle(self, user_data):
    osutils = osutils_factory.OSUtilsFactory().get_os_utils()

    target_path = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))
    if re.search(r'^rem cmd\s', user_data, re.I):
        target_path += '.cmd'
        args = [target_path]
        shell = True
    elif re.search(r'^#!', user_data, re.I):
        target_path += '.sh'
        args = ['bash.exe', target_path]
        shell = False
    elif re.search(r'^#ps1\s', user_data, re.I):
        target_path += '.ps1'
        args = ['powershell.exe', '-ExecutionPolicy', 'RemoteSigned',
                '-NonInteractive', target_path]
        shell = False
    elif re.search(r'^#ps1_sysnative\s', user_data, re.I):
        if os.path.isdir(os.path.expandvars('%windir%\\sysnative')):
            target_path += '.ps1'
            args = [os.path.expandvars('%windir%\\sysnative\\'
                                       'WindowsPowerShell\\v1.0\\'
                                       'powershell.exe'),
                    '-ExecutionPolicy',
                    'RemoteSigned', '-NonInteractive', target_path]
            shell = False
        else:
            # Unable to validate sysnative presence
            LOG.warning('Unable to validate sysnative folder presence. '
                        'If Target OS is Server 2003, please ensure you '
                        'have KB942589 installed')
            return (base.PLUGIN_EXECUTION_DONE, False)
    else:
        # Unsupported
        LOG.warning('Unsupported user_data format')
        return (base.PLUGIN_EXECUTION_DONE, False)

    try:
        with open(target_path, 'wb') as f:
            f.write(user_data)
        (out, err, ret_val) = osutils.execute_process(args, shell)

        LOG.info('User_data script ended with return code: %d' % ret_val)
        LOG.debug('User_data stdout:\n%s' % out)
        LOG.debug('User_data stderr:\n%s' % err)
    except Exception, ex:
        LOG.warning('An error occurred during user_data execution: \'%s\''
                    % ex)
    finally:
        if os.path.exists(target_path):
            os.remove(target_path)

    return (base.PLUGIN_EXECUTION_DONE, False)

