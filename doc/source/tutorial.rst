Tutorial
========

First, download your desired type of installer from :ref:`here <download>`,
then install it and fill in configuration options which suits you best.
Based on the current selected *cloudbase-init* installer architecture, it'll
be available under *C:\\Program Files* or *C:\\Program Files (x86)* as
**Cloudbase Solutions\\Cloudbase-Init** directory. There, are located some
folders of interest like:

    * bin - Executable files and other binaries.
    * conf - Configuration files holding miscellaneous options.
    * log - Here are the cloudbase-init logs.
    * LocalScripts - User supplied :ref:`scripts <execution>`.
    * Python - Bundle of executable and library files to support Python
      scripts and core execution.

After install, cloudbase-init acts like a 2-step service which will read
metadata using :ref:`services` and will pass that to the executing
:ref:`plugins`, this way configuring all the supported things.
Depending on the platform, some plugins may request reboots.


Sysprepping
-----------

The System Preparation (Sysprep) tool prepares an installation of Windows for
duplication, auditing, and customer delivery. Duplication, also called imaging,
enables you to capture a customized Windows image that you can reuse throughout
an organization.
The Sysprep phase uses the "Unattend.xml" which implies the service to run
using the "cloudbase-init-unattend.conf" configuration file.


.. _config:

Configuration file
------------------

In the chosen installation path, under the *conf* directory, are present
two config files named "cloudbase-init.conf" and
"cloudbase-init-unattend.conf".
These can hold various config options for picking up the desired available
services and plugins ready for execution and also customizing user experience.

*Explained example of configuration file:*

.. code-block:: text

    [DEFAULT]
    # What user to create and in which group(s) to be put.
    username=Admin
    groups=Administrators
    inject_user_password=true  # Use password from the metadata (not random).
    # Which devices to inspect for a possible configuration drive (metadata).
    config_drive_raw_hhd=true
    config_drive_cdrom=true
    # Path to tar implementation from Ubuntu.
    bsdtar_path=C:\Program Files (x86)\Cloudbase Solutions\Cloudbase-Init\bin\bsdtar.exe
    # Logging debugging level.
    verbose=true
    debug=true
    # Where to store logs.
    logdir=C:\Program Files (x86)\Cloudbase Solutions\Cloudbase-Init\log\
    logfile=cloudbase-init-unattend.log
    default_log_levels=comtypes=INFO,suds=INFO,iso8601=WARN
    logging_serial_port_settings=
    # Enable MTU and NTP plugins.
    mtu_use_dhcp_config=true
    ntp_use_dhcp_config=true
    # Where are located the user supplied scripts for execution.
    local_scripts_path=C:\Program Files (x86)\Cloudbase Solutions\Cloudbase-Init\LocalScripts\
    # Services that will be tested for loading until one of them succeeds.
    metadata_services=cloudbaseinit.metadata.services.configdrive.ConfigDriveService,
                      cloudbaseinit.metadata.services.httpservice.HttpService,
                      cloudbaseinit.metadata.services.ec2service.EC2Service,
                      cloudbaseinit.metadata.services.maasservice.MaaSHttpService
    # What plugins to execute.
    plugins=cloudbaseinit.plugins.common.mtu.MTUPlugin,
            cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin
    # Miscellaneous.
    allow_reboot=false    # allow the service to reboot the system
    stop_service_on_exit=false

The "cloudbase-init-unattend.conf" configuration file is similar to the
default one and is used by the Sysprepping phase. It was designed for the
scenario where the minimum user intervention is required and it only runs
the MTU and host name plugins, leaving the image ready for further
initialization cases.

More of these explained options are available under the :ref:`services`,
:ref:`plugins` and :ref:`userdata` documentation.

A complete list of config options can be found at :ref:`config_list`.

.. _execution:

File execution
--------------

Cloudbase-init has the ability to execute user provided scripts, usually
found in the default path
*C:\\Program Files (x86)\\Cloudbase Solutions\\Cloudbase-Init\\LocalScripts*,
through a specific :ref:`plugin <scripts>` for doing it. Depending on
the platform used, the files should be valid PowerShell, Python, Batch or Bash scripts.
The userdata can be also a PEM certificate, in a cloud-config format or a MIME content.
The user data plugin is capable of executing various script types and exit code value handling.

Based on their exit codes, you can instruct the system to reboot or even
re-execute the plugin on the next boot:

* 1001 - reboot and don't run the plugin again on next boot
* 1002 - don't reboot now and run the plugin again on next boot
* 1003 - reboot and run the plugin again on next boot
