.. _plugins:

Plugins
=======

Plugins execute actions based on the metadata obtained by the loaded service.
They are intended to actually configure your instance using data provided by
the cloud and even by the user. There are three stages for the plugins
execution:

1. The `pre-networking` stage (for setting up the network, before doing any
valid web request).

2. The `pre-metadata-discovery` one (additional configuration before the
metadata service discovery).

3. The `main` set of plugins, which holds the rest of the plugins which are
(re)executed according to their saved status.

Note that the first two stages (1,2) are executed each time the service
starts.

Current list of supported plugins:


Setting host name *(main)*
--------------------------

.. class:: cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin

Sets the instance's hostname. It may be truncated to 15 characters for Netbios
compatibility reasons using the option below.

Config options:

    * netbios_host_name_compatibility (bool: True)

.. warning:: This may require a system restart.


Creating user *(main)*
----------------------

.. class:: cloudbaseinit.plugins.windows.createuser.CreateUserPlugin

Creates (or updates if existing) a new user and adds it to a
set of provided local groups. By default, it creates the user "Admin" under
"Administrators" group, but this can be changed under configuration file.

Config options:

    * username (string: "Admin")
    * groups (list of strings: ["Administrators"])


Setting password *(main)*
-------------------------

.. class:: cloudbaseinit.plugins.windows.setuserpassword.SetUserPasswordPlugin

Sets the cloud user's password. If a password has been provided in the metadata
during boot it will be used, otherwise a random password will be generated,
encrypted with the user's SSH public key and posted to the metadata provider
(currently supported only by the OpenStack HTTP metadata provider).
An option called `inject_user_password` is set *True* by default to make
available the use of metadata password which is found under the "admin_pass"
field or through an URL request. If the option is set to *False* or if the
password isn't found in metadata, then an attempt of using an already set
password is done (usually a random value by the `createuser` plugin).
With `first_logon_behaviour` you can control what happens with the password at
the next logon. If this option is set to "always", the user will be forced to
change the password at the next logon. If it is set to "clear_text_injected_only",
the user will be forced to change the password only if the password is a
clear text password, coming from the metadata. The last option is "no",
when the user is never forced.

Config options:

    * inject_user_password (bool: True)
    * first_logon_behaviour (string: "clear_text_injected_only")

.. note:: This plugin can run multiple times (for posting the password if the
          metadata service supports this).


Static networking *(main)*
--------------------------

.. class:: cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin

Statically configures each network adapter for which corresponding details
are found into metadata. The details/addresses association is done using
MAC matching and if this fails, then name or interface index matching.
The basic setting is based on IPv4 addresses, but it supports IPv6 addresses
too if they are enabled and exposed to the metadata.
The purpose of this plugin is to configure network adapters, for which the
DHCP server is disabled, to have internet access and static IPs.

.. warning:: This may require a system restart.


Saving public keys *(main)*
---------------------------

.. class:: cloudbaseinit.plugins.common.sshpublickeys.SetUserSSHPublicKeysPlugin

Creates an **authorized_keys** file in the user's home directory containing
the SSH keys provided in the metadata. It is needed by the plugin responsible
for encrypting and setting passwords.

Config options:

    * username (string: "Admin")


Volume expanding *(main)*
-------------------------

.. class:: cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin

Extends automatically a disk partition to its maximum size. This is useful
when booting images with different flavors. By default, all the volumes are
extended, but you can select specific ones by populating with their indexes the
`volumes_to_extend` option.

Config options:

    * volumes_to_extend (list of integers: None)

.. note:: This plugin will run at every boot.


WinRM listener *(main)*
-----------------------

.. class:: cloudbaseinit.plugins.windows.winrmlistener.ConfigWinRMListenerPlugin

Configures a WinRM HTTPS listener to allow remote management via
`WinRM <https://msdn.microsoft.com/en-us/library/aa384426(v=vs.85).aspx>`_
or PowerShell.

Config options:

    * winrm_enable_basic_auth (bool: True)

.. note:: This plugin will run until a full and proper configuration
          will take place.


.. _certificate:

WinRM certificate *(main)*
--------------------------

.. class:: cloudbaseinit.plugins.windows.winrmcertificateauth.ConfigWinRMCertificateAuthPlugin

Enables password-less authentication for remote management via WinRS or
PowerShell. Usually uses x509 embedded with UPN certificates.

Config options:

    * username (string: "Admin")

.. note:: http://www.cloudbase.it/windows-without-passwords-in-openstack/


.. _scripts:

Scripts execution *(main)*
--------------------------

.. class:: cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin

Executes any script (powershell, batch, python etc.) located in the following
path indicated by `local_scripts_path` option.
More details about the supported scripts and content can be found
in :ref:`tutorial` on :ref:`file execution <execution>` subject.

Config options:

    * local_scripts_path (string: None)

.. warning:: This may require a system restart.

.. note:: This plugin may run multiple times (depending on the script(s)
          return code).


Licensing *(main)*
------------------

.. class:: cloudbaseinit.plugins.windows.licensing.WindowsLicensingPlugin

Activates the Windows instance if the `activate_windows` option is *True*.

Config options:

    * activate_windows (bool: False)


Clock synchronization *(pre-networking)*
----------------------------------------

.. class:: cloudbaseinit.plugins.windows.ntpclient.NTPClientPlugin

Applies NTP client info based on the DHCP server options, if available. This
behavior is enabled only when the `ntp_use_dhcp_config` option is set
to *True* (which by default is *False*).

Config options:

    * ntp_use_dhcp_config (bool: False)

.. note:: This plugin will run until the NTP client is configured.


MTU customization *(pre-metadata-discovery)*
--------------------------------------------

.. class:: cloudbaseinit.plugins.common.mtu.MTUPlugin

Sets the network interfaces MTU based on the value provided by the DHCP server
options, if available and enabled (by default is *True*).
This is particularly useful for cases in which a lower MTU value is required
for networking (e.g. OpenStack GRE Neutron Open vSwitch configurations).

Config options:

    * mtu_use_dhcp_config (bool: True)

.. note:: This plugin will run at every boot.


User data *(main)*
------------------

.. class:: cloudbaseinit.plugins.common.userdata.UserDataPlugin

Executes custom scripts provided by user data metadata as plain text or
compressed with Gzip.
More details, examples and possible formats here: :ref:`userdata`.

----

Configuring selected plugins
----------------------------

By default, all plugins are executed, but a custom list of them can be
specified through the `plugins` option in the configuration file.

For more details on doing this, see :ref:`configuration <config>`
file in :ref:`tutorial`.
