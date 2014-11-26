# Copyright 2014 Cloudbase Solutions Srl
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

import socket
import time
import urllib
import os
import tempfile

from oslo.config import cfg

from cloudbaseinit import exception
from cloudbaseinit.openstack.common import log as logging
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins import base
from cloudbaseinit.plugins.windows import fileexecutils
from cloudbaseinit.utils import dhcp

opts = [
    cfg.StrOpt('set_date_url', default=None,
                help='Configures date at boot by fetching it from a url'),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)

class SetDatePlugin(base.BasePlugin):
    def execute(self, service, shared_data):
        if CONF.set_date_url is None:
            LOG.info('No date_url set, cannot set date')
            return (base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False)
        url = CONF.set_date_url
        date_format = '%d %B %Y %H:%M:%S'
        LOG.info('Fetching date from: %s' % url)
        date_str = urllib.urlopen(url).read().strip()
        date_val = time.strptime(date_str, date_format)
        windows_date_str = time.strftime('%m-%d-%y', date_val)
        windows_time_str = time.strftime('%H:%M:%S', date_val)
        commands = """
date %s
time %s
""" % (windows_date_str, windows_time_str)
        target_path = os.path.join(tempfile.gettempdir(), 'setdate.cmd')

        try:
            with open(target_path, 'wb') as f:
                f.write(commands)
            ret_val = fileexecutils.exec_file(target_path)
            if ret_val == 0:
                LOG.info('Set date: %s' % date_str)
            else:
                LOG.warning('Failed to set date: %s' % ret_val)
        except Exception as ex:
            LOG.warning('An error occurred during set_date execution: \'%s\'' % ex)
        finally:
            if os.path.exists(target_path):
                os.remove(target_path)
        return (base.PLUGIN_EXECUTION_DONE, False)
