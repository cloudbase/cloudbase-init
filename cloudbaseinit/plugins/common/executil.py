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

import functools
import os
import tempfile
import uuid

from cloudbaseinit.osutils import factory as osutils_factory


__all__ = (
    'BaseCommand',
    'Shell',
    'Python',
    'Bash',
    'Powershell',
    'PowershellSysnative',
)


class BaseCommand(object):
    """Implements logic for executing an user command.

    This is intended to be subclassed and each subclass should change the
    attributes which controls the behaviour of the execution.
    It must be instantiated with a file.
    It can also execute string commands, by using the alternate
    constructor :meth:`~from_data`.

    The following attributes can control the behaviour of the command:

       * shell: Run the command as a shell command.
       * extension:

           A string, which will be appended to a generated script file.
           This is important for certain commands, e.g. Powershell,
           which can't execute something without the `.ps1` extension.

       * command:

           A program which will execute the underlying command,
           e.g. `python`, `bash` etc.

    """
    shell = False
    extension = None
    command = None

    def __init__(self, target_path, cleanup=None):
        """Instantiate the command.

        The parameter *target_path* represents the file which will be
        executed. The optional parameter *cleanup* can be a callable,
        which will be called after executing a command, no matter if the
        execution was succesful or not.
        """

        self._target_path = target_path
        self._cleanup = cleanup
        self._osutils = osutils_factory.get_os_utils()

    @property
    def args(self):
        """Return a list of commands.

        The list will be passed to :meth:`~execute_process`.
        """
        if not self.command:
            # Then we can assume it's a shell command.
            return [self._target_path]
        else:
            return [self.command, self._target_path]

    def get_execute_method(self):
        """Return a callable, which will be called by :meth:`~execute`."""
        return functools.partial(self._osutils.execute_process,
                                 self.args, shell=self.shell)

    def execute(self):
        """Execute the underlying command."""
        try:
            return self.get_execute_method()()
        finally:
            if self._cleanup:
                self._cleanup()

    __call__ = execute

    @classmethod
    def from_data(cls, command):
        """Create a new command class from the given command data."""
        def safe_remove(target_path):
            try:
                os.remove(target_path)
            except OSError:  # pragma: no cover
                pass

        tmp = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))
        if cls.extension:
            tmp += cls.extension
        with open(tmp, 'wb') as stream:
            stream.write(command)
        return cls(tmp, cleanup=functools.partial(safe_remove, tmp))


class Shell(BaseCommand):
    shell = True
    extension = '.cmd'


class Python(BaseCommand):
    extension = '.py'
    command = 'python'


class Bash(BaseCommand):
    extension = '.sh'
    command = 'bash'


class PowershellSysnative(BaseCommand):
    extension = '.ps1'
    sysnative = True

    def get_execute_method(self):
        return functools.partial(
            self._osutils.execute_powershell_script,
            self._target_path,
            self.sysnative)


class Powershell(PowershellSysnative):
    sysnative = False
