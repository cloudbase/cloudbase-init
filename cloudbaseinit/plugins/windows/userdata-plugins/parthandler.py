# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Mirantis Inc.
# All Rights Reserved.
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
import imp
import os
from cloudbaseinit.openstack.common import log as logging

LOG = logging.getLogger("cloudbaseinit")

def get_plugin(parent_set):
    return PartHandlerScriptHandler(parent_set)

def load_from_file(filepath, function):
    class_inst = None

    mod_name,file_ext = os.path.splitext(os.path.split(filepath)[-1])

    if file_ext.lower() == '.py':
        py_mod = imp.load_source(mod_name, filepath)

    elif file_ext.lower() == '.pyc':
        py_mod = imp.load_compiled(mod_name, filepath)

    if hasattr(py_mod, function):
        callable = getattr(__import__(mod_name),function)
  
    return callable

class PartHandlerScriptHandler:
        
    def __init__(self, parent_set):
        LOG.info("Part-handler script part handler is loaded.")
        self.type = "text/part-handler"
        self.name = "Part-handler userdata plugin"
        self.parent_set = parent_set
        return
    
    def process(self, part):
       handler_path = self.parent_set.path + "/part-handler/"+part.get_filename()
       with open(handler_path, "wb") as f:
            f.write(part.get_payload())
        
        
       list_types = load_from_file(handler_path,"list_types")
       handle_part = load_from_file(handler_path, "handle_part")
       
       if list_types is not None and handle_part is not None:
           parts = list_types() 
           for part in parts:
               LOG.info("Installing new custom handler for type: %s", part)
               self.parent_set.custom_handlers[part] = handle_part
           self.parent_set.has_custom_handlers = True       
       return
   