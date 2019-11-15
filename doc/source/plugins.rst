Plugins
=======

Plugins execute actions based on the metadata obtained by the loaded service.
They are intended to configure the instance using data provided by the underlying cloud and
by the user who created the instance. There are three stages for the plugins' execution:

1. The **PRE_NETWORKING** stage (for setting up the network, before doing any
valid web request.

2. The **PRE_METADATA_DISCOVERY** stage (additional configuration before the
metadata service discovery).

3. The default **MAIN** stage, which holds the rest of the plugins which are
(re)executed according to their saved status. The metadata service loaded needs to provide
an instance id for the plugins to be able to have a saved status. If the metadata service
cannot provide an instance id, the plugins state from the **MAIN** stage cannot be saved,
and therefore, all plugins will be executed at every boot.

Note that the plugins from the two stages are executed each time the cloudbase-init service
starts (those plugins do not have saved status).

Just before the **MAIN** stage, the metadata service can report to the
cloud service that the provision started. After the **MAIN** stage ended,
the metadata service can report to the cloud service that the provisioning completed
successfully or failed.


----


Configuring selected plugins
----------------------------

By default, only a subset of plugins is executed. The plugins are:

.. code:: python

    [DEFAULT]
    plugins = cloudbaseinit.plugins.common.mtu.MTUPlugin, cloudbaseinit.plugins.windows.ntpclient.NTPClientPlugin, cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin, cloudbaseinit.plugins.windows.createuser.CreateUserPlugin, cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin, cloudbaseinit.plugins.windows.licensing.WindowsLicensingPlugin, cloudbaseinit.plugins.common.sshpublickeys.SetUserSSHPublicKeysPlugin, cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin, cloudbaseinit.plugins.common.userdata.UserDataPlugin, cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin, cloudbaseinit.plugins.windows.winrmlistener.ConfigWinRMListenerPlugin, cloudbaseinit.plugins.windows.winrmcertificateauth.ConfigWinRMCertificateAuthPlugin, cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin


A custom list of plugins can be specified through the `plugins` option in the configuration file.

For more details on doing this, see :ref:`configuration <config>`
file in :ref:`tutorial`.


----


Setting hostname (MAIN)
--------------------------

.. class:: cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin

Sets the instance hostname. The hostname gets truncated to 15 characters for
Netbios compatibility reasons if `netbios_host_name_compatibility` is set.

Config options:

    * netbios_host_name_compatibility (bool: True)

Notes:

    * Requires support in the metadata service.
    * May require a system restart.


Creating user (MAIN)
----------------------

.. class:: cloudbaseinit.plugins.windows.createuser.CreateUserPlugin

Creates (or updates if existing) a new user and adds it to a
set of provided local groups. By default, it creates the user "Admin" under
"Administrators" group, but this can be changed in the configuration file.

A random user password is set for the user. The password length is by default set
to 20 and can be customized using the `user_password_length` configuration option.

If `rename_admin_user` is set to `True`, the user `Administrator` is renamed
to the `username` config value or to the metadata service provided value.

Config options:

    * username (string: "Admin")
    * groups (list of strings: ["Administrators"])
    * user_password_length (int: 20)
    * rename_admin_user (bool: false)

Notes:

    * The metadata service can provide the username. If the metadata service
      provides the admin username, it will override the `username` configuration
      value.


Setting password (MAIN)
-------------------------

.. class:: cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin

Sets the cloud user's password. If a password has been provided in the metadata
during boot it will be used, otherwise a random password will be generated,
encrypted with the user's SSH public key and posted to the metadata provider.

An option called `inject_user_password` is set *True* by default to make
available the use of metadata password which is found under the "admin_pass"
field or through an URL request. If the option is set to *False* or if the
password isn't found in metadata, then an attempt of using an already set
password is done (usually a random value by the CreateUserPlugin plugin).
With `first_logon_behaviour` you can control what happens with the password at
the next logon. If this option is set to "always", the user will be forced to
change the password at the next logon.

If it is set to "clear_text_injected_only",
the user will be forced to change the password only if the password is a
clear text password, coming from the metadata. The last option is "no",
when the user is never forced to change the password.

Config options:

    * username (string: "Admin")
    * inject_user_password (bool: True)
    * first_logon_behaviour (string: "clear_text_injected_only")
    * user_password_length (int: 20)

Notes:

    * The metadata service may provide the username. If the metadata service
      provides the admin username, it will override the `username` configuration
      value.
    * May run at every boot to (re)set and post the password if the
      metadata service supports this behaviour.


Static networking (MAIN)
--------------------------

.. class:: cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin

Statically configures each network adapter for which corresponding details
are found into metadata. The details/addresses association is done using
MAC matching and if this fails, then name or interface index matching.
The basic setting is based on IPv4 addresses, but it supports IPv6 addresses
too if they are enabled and exposed to the metadata.
The purpose of this plugin is to configure network adapters, for which the
DHCP server is disabled, to have internet access and static IPs.

NIC teaming (bonding) is supported and uses `NetLBFO <https://docs.microsoft.com/en-us/windows-server/networking/technologies/nic-teaming/nic-teaming>`_ implementation.

Notes:

    * Requires support in the metadata service.
    * May require a system restart.


Saving public keys (MAIN)
---------------------------

.. class:: cloudbaseinit.plugins.common.sshpublickeys.SetUserSSHPublicKeysPlugin

Creates an **authorized_keys** file in the user's home directory containing
the SSH keys provided in the metadata. It is needed by the plugin responsible
for encrypting and setting passwords.

Config options:

    * username (string: "Admin")

Notes:

    * Requires support in the metadata service. The metadata service provides
      the SSH public keys.
    * The metadata service can provide the username. If the metadata service
      provides the admin username, it will override the `username` configuration
      value.


Volume expanding (MAIN)
-------------------------

.. class:: cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin

Extends automatically a disk partition to its maximum size. This is useful
when booting images with different flavors. By default, all the volumes are
extended, but you can select specific ones by populating with their indexes the
`volumes_to_extend` option.

Config options:

    * volumes_to_extend (list of integers: None)

Notes:

    * Runs at every boot.


WinRM listener (MAIN)
-----------------------

.. class:: cloudbaseinit.plugins.windows.winrmlistener.ConfigWinRMListenerPlugin

Configures a WinRM HTTPS listener to allow remote management via
`WinRM <https://msdn.microsoft.com/en-us/library/aa384426(v=vs.85).aspx>`_
or PowerShell.

If `winrm_enable_basic_auth` is set to True, it enables basic authentication
(authentication using username and password) for the WinRM listeners.

If `winrm_configure_http_listener` is set to True, the WinRM http listener will also
be enabled.

Config options:

    * winrm_enable_basic_auth (bool: True)
    * winrm_configure_https_listener (bool: True)
    * winrm_configure_http_listener (bool: False)

Notes:
    * The metadata service can provide the listeners configuration (protocol
      and certificate thumbprint).
    * May run at every boot. If the `WinRM` Windows service does not exist,
      it will run at the next boot.


.. _certificate:

WinRM certificate (MAIN)
--------------------------

.. class:: cloudbaseinit.plugins.windows.winrmcertificateauth.ConfigWinRMCertificateAuthPlugin

Enables password-less authentication for remote management via WinRS or
PowerShell. Usually uses x509 embedded with UPN certificates.

Config options:

    * username (string: "Admin")

Notes

    * Requires support in the metadata service.
      The metadata service must provide the certificate metadata.
      The admin user password needs to be present, either from the metadata,
      either as shared data set by running CreateUserPlugin or SetUserPasswordPlugin.
      The metadata service can provide the username. If the metadata service
      provides the admin username, it will override the `username` configuration
      value.
    * How to use this feature: http://www.cloudbase.it/windows-without-passwords-in-openstack/


.. _scripts:

Local Scripts execution (MAIN)
--------------------------------

.. class:: cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin

Executes any script (powershell, batch, python etc.) located in the following
path indicated by `local_scripts_path` option.

More details about the supported scripts and content can be found
in :ref:`tutorial` on :ref:`file execution <execution>` subject.

Config options:

    * local_scripts_path (string: None)

Notes:

    * May require a system restart.
    * May run at every boot. It depends on the exit codes of the scripts.


Licensing (MAIN)
------------------

.. class:: cloudbaseinit.plugins.windows.licensing.WindowsLicensingPlugin

Activates the Windows instance if the `activate_windows` option is *True*.
If `set_kms_product_key` or `set_avma_product_key` are set, it will use that
KMS or AVMA product key in Windows.

If `kms_host` is set, it will set the provided host as the KMS licensing server.

Config options:

    * activate_windows (bool: False)
    * set_kms_product_key (bool: False)
    * set_avma_product_key (bool: False)
    * kms_host (string: None)
    * log_licensing_info (bool: True)

Notes:

    * The metadata service can provide the KMS host, overriding the configuration
      option `kms_host`.
      The metadata service can provide the avma_product_key, overriding the configuration
      option `set_avma_product_key`.


Clock synchronization (PRE_NETWORKING)
----------------------------------------

.. class:: cloudbaseinit.plugins.windows.ntpclient.NTPClientPlugin

Applies NTP client info based on the DHCP server options, if available. This
behavior is enabled only when the `ntp_use_dhcp_config` option is set
to *True* (which by default is *False*).

If `real_time_clock_utc` is set to True, it will set the real time clock to use
universal time. If set to `False`, it will set the real time clock to use the
local time.

Config options:

    * ntp_use_dhcp_config (bool: False)
    * real_time_clock_utc (bool: False)
    * ntp_enable_service (bool: True)

Notes:

    * May require a reboot.
    * May run at every boot.


MTU customization (PRE_METADATA_DISCOVERY)
--------------------------------------------

.. class:: cloudbaseinit.plugins.common.mtu.MTUPlugin

Sets the network interfaces MTU based on the value provided by the DHCP server
options, if available and enabled (by default is *True*).
This is particularly useful for cases in which a lower MTU value is required
for networking (e.g. OpenStack GRE Neutron Open vSwitch configurations).

Config options:

    * mtu_use_dhcp_config (bool: True)

Notes:

    * Runs at every boot.


User data (MAIN)
------------------

.. class:: cloudbaseinit.plugins.common.userdata.UserDataPlugin

Executes custom scripts provided by user data metadata as plain text or
compressed with Gzip.
More details, examples and possible formats here: :ref:`userdata`.


Trim Config (MAIN)
------------------

.. class:: cloudbaseinit.plugins.common.trim.TrimConfigPlugin

Enables or disables TRIM delete notifications for the underlying
storage device.

Config options:

    * trim_enabled (bool: False)


San Policy Config (MAIN)
------------------------

.. class:: cloudbaseinit.plugins.windows.sanpolicy.SANPolicyPlugin

If not None, the SAN policy is set to the given value of the configuration
option `san_policy`. The possible values are: OnlineAll, OfflineAll or OfflineShared.

Config options:

    * san_policy (string: None)


RDP Settings Config (MAIN)
--------------------------

.. class:: cloudbaseinit.plugins.windows.rdp.RDPSettingsPlugin

Sets the registry key `KeepAliveEnable`, to enable or disable the RDP keep alive functionality.

Config options:

    * rdp_set_keepalive (bool: False)


RDP Post Certificate Thumbprint (MAIN)
--------------------------------------

.. class:: cloudbaseinit.plugins.windows.rdp.RDPPostCertificateThumbprintPlugin

Posts the RDP certificate thumbprint to the metadata service endpoint.

Notes:

    * Requires support in the metadata service.
      The metadata service should expose an HTTP endpoint where the certificate
      thumbprint can be posted.


Page Files (MAIN)
-----------------

.. class:: cloudbaseinit.plugins.windows.pagefiles.PageFilesPlugin

Sets custom page files according to the config options.

Config options:

    * page_file_volume_labels (array: [])
    * page_file_volume_mount_points (array: [])

Notes:

    * May require a reboot.
      If the page file is configured, a reboot is required.
    * Runs at every boot.


Display Idle Timeout Config (MAIN)
----------------------------------

.. class:: cloudbaseinit.plugins.windows.displayidletimeout.DisplayIdleTimeoutConfigPlugin

Sets the idle timeout, in seconds, before powering off the display.
Set 0 to leave the display always on.

Config options:

    * display_idle_timeout (int: 0)


Boot Status Policy Config (MAIN)
--------------------------------

.. class:: cloudbaseinit.plugins.windows.bootconfig.BootStatusPolicyPlugin

Sets the Windows BCD boot status policy according to the config option.
When set, the only possible value for `bcd_boot_status_policy` is `ignoreallfailures`.

Config options:

    * bcd_boot_status_policy (string: None)


BCD Config (MAIN)
-----------------------

.. class:: cloudbaseinit.plugins.windows.bootconfig.BCDConfigPlugin

A unique disk ID is needed to avoid disk signature collisions.
This plugin resets the boot disk id and enables auto-recovery in the
BCD store.

Config options:

    * set_unique_boot_disk_id (bool: False)
    * bcd_enable_auto_recovery (bool: False)


Ephemeral Disk Config (MAIN)
----------------------------

.. class:: cloudbaseinit.plugins.common.ephemeraldisk.EphemeralDiskPlugin

Sets the ephemeral disk data loss warning file.
On public clouds like Azure, the ephemeral disk should contain a read only
file with data loss warning text, that warns the user to not use the
ephemeral disk as a persistent storage disk.

Config options:

    * ephemeral_disk_volume_label (string: None)
    * ephemeral_disk_volume_mount_point (string: None)
    * ephemeral_disk_data_loss_warning_path (string: None)

Notes:

    * Requires support in the metadata service.
      The metadata service should provide the disk data loss warning text.


Windows Auto Updates (MAIN)
---------------------------

.. class:: cloudbaseinit.plugins.windows.updates.WindowsAutoUpdatesPlugin

Enables automatic Windows updates based on the user configuration or
the metadata service information. The metadata service setting takes
priority over the configuration option.

Config options:

    * enable_automatic_updates (bool: False)

Notes:

    * If the metadata service provides the information needed to enable the
      automatic updates, it will override the `enable_automatic_updates`
      configuration value.


Server Certificates (MAIN)
--------------------------

.. class:: cloudbaseinit.plugins.windows.certificates.ServerCertificatesPlugin

Imports X509 certificates into the desired store location. The metadata service
provides the certificate and key in a PFX archive, their store location and store name.

Notes:

    * Requires support in the metadata service.


Azure Guest Agent (MAIN)
------------------------

.. class:: cloudbaseinit.plugins.windows.azureguestagent.AzureGuestAgentPlugin

Installs Azure Guest agent, which is required for the Azure cloud platform.

Notes:

    * Requires support in the metadata service.
      Azure metadata service should provide the agent package provisioning data.

