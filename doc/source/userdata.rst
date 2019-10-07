.. _userdata:

Userdata
========

The *userdata* is the user custom content exposed to the guest instance
by the currently deployed and running cloud infrastructure. Its purpose is
to provide additional data for the instance to customize it as much as you
need, if the cloud initialization service does support this feature.

Fortunately, *cloudbase-init* is able to interpret and use this kind of user
specific data in multiple ways. In most of the cases, the thing that indicates
of what type is the processed data is usually the **first line**.

Currently supported contents:


PEM certificate
---------------

**-----BEGIN CERTIFICATE-----**

This one should start with a PEM specific beginning header, which will
be eventually parsed by the :ref:`configuration drive <configdrive>`
and :ref:`web API <httpservice>` OpenStack services and used by the
:ref:`certificate` plugin for storing and using it.


Batch
-----

**rem cmd**

The file is executed in a *cmd.exe* shell (can be changed with the `COMSPEC`
environment variable).


PowerShell
----------

**#ps1_sysnative** (system native)

**#ps1_x86** (Windows On Windows 32bit)

Execute PowerShell scripts using the desired executable. For finding out more
about the system nativeness thing, click :ref:`here <sysnative>`.


Bash
----

**#!/bin/bash**

A bash shell needs to be installed in the system and available in the `PATH`
in order to use this feature.


Python
------

**#!/usr/bin/env python**

Python is available by default with the build itself, but also it must be in
the system `PATH`.


EC2 format
----------

There is no "first line" here, but the content should follow a XML pattern
with valid Batch/PowerShell script contents under **script** or **powershell**
enclosing tags like in this example:

.. code-block:: xml

    <script>
    set root=%SystemDrive%
    echo ec2dir>%root%\ec2file.txt
    </script>

    <powershell>
    $root = $env:SystemDrive
    $dname = Get-Content "$root\ec2file.txt"
    New-Item -path "$root\$dname" -type directory
    </powershell>

.. note:: http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/UsingConfig_WinAMI.html


Cloud config
------------

**#cloud-config**

Cloud-config YAML configuration as supported by *cloud-init*, excluding Linux
specific content.
The following cloud-config directives are supported:

* write_files - Defines a set of files which will be created on the local
  filesystem. It can be a list of items or only one item,
  with the following attributes:

    1. path - Absolute path on disk where the content should be written.
    2. content - The content which will be written in the given file.
    3. permissions - Integer representing file permissions.
    4. encoding - The encoding of the data in content. Supported encodings
       are: b64, base64 for base64-encoded content, gz,
       gzip for gzip encoded content, gz+b64, gz+base64,
       gzip+b64, gzip+base64 for base64 encoded gzip content.

    *Examples:*

    .. code-block:: xml

        # One item

        #cloud-config
        write_files:
           encoding: b64
           content: NDI=
           path: C:\test
           permissions: '0o466'

    .. code-block:: xml

        # Multiple items

        #cloud-config
        write_files:
           -   encoding: b64
               content: NDI=
               path: C:\b64
               permissions: '0644'
           -   encoding: base64
               content: NDI=
               path: C:\b64_1
               permissions: '0644'
           -   encoding: gzip
               content: !!binary |
                   H4sIAGUfoFQC/zMxAgCIsCQyAgAAAA==
               path: C:\gzip
               permissions: '0644'

* set_timezone - Change the underlying timezone.

    *Example:*

    .. code-block:: text

        set_timezone: Asia/Tbilisi

* set_hostname - Override the already default set host name value. (metadata)

    *Example:*

    .. code-block:: text

        set_hostname: newhostname


Multi-part content
------------------

MIME multi-part user data is supported. The content will be handled based on
the content type.

* text/x-shellscript - Any script to be executed: PowerShell, Batch, Bash
  or Python.

* text/part-handler - A script that can manage other content type parts.
  This is used in particular by Heat / CFN templates,
  although Linux specific.

* text/x-cfninitdata - Heat / CFN content. Written to the path provided by
  `heat_config_dir` option which defaults to "C:\\cfn".
  (examples of Heat Windows `templates`_)

----

.. _sysnative:

Sysnativeness
-------------

*When deciding which path to use for system executable files...*

On 32bit OSes, the return value will be the *System32* directory,
which contains 32bit programs.
On 64bit OSes, the return value may be different, depending on the
Python bits and the `sysnative` parameter. If the Python interpreter is
32bit, the return value will be *System32* (containing 32bit
programs) if `sysnative` is set to False and *Sysnative* otherwise. But
if the Python interpreter is 64bit and `sysnative` is False, the return
value will be *SysWOW64* and *System32* for a True value of `sysnative`.

Why this behavior and what is the purpose of `sysnative` parameter?

On a 32bit OS the things are clear, there is one *System32* directory
containing 32bit applications and that's all. On a 64bit OS, there's a
*System32* directory containing 64bit applications and a compatibility
one named *SysWOW64* (WindowsOnWindows) containing the 32bit version of
them. Depending on the Python interpreter's bits, the `sysnative` flag
will try to bring the appropriate version of the system directory, more
exactly, the physical *System32* or *SysWOW64* found on disk. On a WOW case
(32bit interpreter on 64bit OS), a return value of *System32* will point
to the physical *SysWOW64* directory and a return value of *Sysnative*,
which is consolidated by the existence of this alias, will point to the
real physical *System32* directory found on disk. If the OS is still
64bit and there is no WOW case (that means the interpreter is 64bit),
the system native concept is out of discussion and each return value
will point to the physical location it intends to.

On a 32bit OS the `sysnative` parameter has no meaning, but on a 64bit
one, based on its value, it will provide a real/alias path pointing to
system native applications if set to True (64bit programs) and to
system compatibility applications if set to False (32bit programs). Its
purpose is to provide the correct system paths by taking into account
the Python interpreter bits too, because on a 32bit interpreter
version, *System32* is not the same with the *System32* on a 64bit
interpreter. Also, using a 64bit interpreter, the *Sysnative* alias will
not work, but the `sysnative` parameter will take care to return
*SysWOW64* if you explicitly want 32bit applications, by setting it to False.


.. _templates: https://github.com/openstack/heat-templates/tree/master/hot/Windows
