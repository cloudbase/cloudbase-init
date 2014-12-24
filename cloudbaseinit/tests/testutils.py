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

import contextlib
import os
import shutil
import tempfile


__all__ = (
    'create_tempfile',
    'create_tempdir',
)


@contextlib.contextmanager
def create_tempdir():
    """Create a temporary directory.

    This is a context manager, which creates a new temporary
    directory and removes it when exiting from the context manager
    block.
    """
    tempdir = tempfile.mkdtemp(prefix="cloudbaseinit-tests")
    try:
        yield tempdir
    finally:
        shutil.rmtree(tempdir)


@contextlib.contextmanager
def create_tempfile(content=None):
    """Create a temporary file.

    This is a context manager, which uses `create_tempdir` to obtain a
    temporary directory, where the file will be placed.

    :param content:
        Additionally, a string which will be written
        in the new file.
    """
    with create_tempdir() as temp:
        fd, path = tempfile.mkstemp(dir=temp)
        os.close(fd)
        if content:
            with open(path, 'w') as stream:
                stream.write(content)
        yield path
