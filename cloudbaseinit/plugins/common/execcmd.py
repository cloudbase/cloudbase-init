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
import re
import tempfile
import uuid

from oslo_log import log as oslo_logging

from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import base


LOG = oslo_logging.getLogger(__name__)

# used with ec2 config files (xmls)
SCRIPT_TAG = 1
POWERSHELL_TAG = 2
# regexp and temporary file extension for each tag
TAG_REGEX = {
    SCRIPT_TAG: (
        re.compile(br"<script>([\s\S]+?)</script>"),
        "cmd"
    ),
    POWERSHELL_TAG: (
        re.compile(br"<powershell>([\s\S]+?)</powershell>"),
        "ps1"
    )
}

NO_REBOOT = 0

# important return values range
RET_START = 1001
RET_END = 1003


def _ec2_find_sections(data):
    """An intuitive script generator.

    Is able to detect and extract code between:
        - <script>...</script>
        - <powershell>...</powershell>
    tags. Yields data with each specific block of code.
    Note that, regardless of data structure, all cmd scripts are
    yielded before the rest of powershell scripts.
    """
    # extract code blocks between the tags
    blocks = {
        SCRIPT_TAG: TAG_REGEX[SCRIPT_TAG][0].findall(data),
        POWERSHELL_TAG: TAG_REGEX[POWERSHELL_TAG][0].findall(data)
    }
    # build and yield blocks (preserve order)
    for script_type in (SCRIPT_TAG, POWERSHELL_TAG):
        for code in blocks[script_type]:
            code = code.strip()
            if not code:
                continue    # skip the empty ones
            yield code, script_type


def _split_sections(multicmd):
    for code, stype in _ec2_find_sections(multicmd):
        if stype == SCRIPT_TAG:
            command = Shell.from_data(code)
        else:
            command = PowershellSysnative.from_data(code)
        yield command


def get_plugin_return_value(ret_val):
    plugin_status = base.PLUGIN_EXECUTION_DONE
    reboot = False

    try:
        ret_val = int(ret_val)
    except (ValueError, TypeError):
        ret_val = 0

    if ret_val and RET_START <= ret_val <= RET_END:
        reboot = bool(ret_val & 1)
        if ret_val & 2:
            plugin_status = base.PLUGIN_EXECUTE_ON_NEXT_BOOT

    return plugin_status, reboot


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


class CommandExecutor(object):

    """Execute multiple commands and gather outputs."""

    SEP = b"\n"            # multistring separator

    def __init__(self, commands):
        self._commands = commands

    def execute(self):
        out_total = []
        err_total = []
        ret_total = 0
        for command in self._commands:
            out = err = b""
            ret_val = 0
            try:
                out, err, ret_val = command()
            except Exception as exc:
                LOG.exception(
                    "An error occurred during part execution: %s",
                    exc
                )
            else:
                out_total.append(out)
                err_total.append(err)
                ret_total += ret_val
        return (
            self.SEP.join(out_total),
            self.SEP.join(err_total),
            ret_total
        )

    __call__ = execute


class EC2Config(object):

    @classmethod
    def from_data(cls, multicmd):
        """Create multiple `CommandExecutor` objects.

        These are created using data chunks
        parsed from the given command data.
        """
        return CommandExecutor(_split_sections(multicmd))
