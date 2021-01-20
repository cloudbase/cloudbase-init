Services
========

A **metadata service** has the role of getting the guest provided data
(configuration information) and exposing it to the :ref:`plugins` for a
general and basic initialization of the instance.
These sub-services can change their behavior according to custom
configuration options documented below.


------


Configuring available services
------------------------------

Any of these classes can be specified manually in the configuration file
under `metadata_services` option. Based on this option, the service loader
will search across these providers in the defined order and load the first
one that is available.

For more details on doing this, see :ref:`configuration <config>`
file in :ref:`tutorial`.


------


.. _httpservice:

OpenStack (web API)
-------------------

.. class:: cloudbaseinit.metadata.services.httpservice.HttpService

A complete service which supports password related capabilities and
can be usually accessed at the http://169.254.169.254/ magic URL.
The magic URL can be customized using the `metadata_base_url` config option.
A default value of *True* for `add_metadata_private_ip_route` option is used
to add a route for the IP address to the gateway. This is needed for supplying
a bridge between different VLANs in order to get access to the web server.

Metadata version used: `latest`.

Capabilities:

    * instance id
    * hostname
    * public keys
    * `WinRM <https://docs.microsoft.com/en-us/windows/win32/winrm/authentication-for-remote-connections#client-certificate-based-authentication>`_ authentication certificates
    * static network configuration
    * admin user name
    * admin user password
    * post admin user password (only once)
    * user data

Config options for `openstack` section:

    * metadata_base_url (string: "http://169.254.169.254/")
    * add_metadata_private_ip_route (bool: True)
    * https_allow_insecure (bool: False)
    * https_ca_bundle (string: None)

Config options for `default` section:

    * retry_count (integer: 5)
    * retry_count_interval (integer: 4)


.. _configdrive:

OpenStack (configuration drive)
-------------------------------

.. class:: cloudbaseinit.metadata.services.configdrive.ConfigDriveService

This is similar to the web API, but it "serves" its files locally without
requiring network access. The data is generally retrieved from a
`cdrom <https://en.wikipedia.org/wiki/ISO_9660>`_,
`vfat <https://en.wikipedia.org/wiki/File_Allocation_Table#VFAT>`_ or
*raw* disks/partitions by enabling selective lookup across different devices.
Use the `types` option to specify which types of config drive
content the service will search for and also on which devices using the
`locations` option.

It will search for metadata:

    a. in mounted optical units
    b. directly in the physical disk bytes
    c. by exploring the physical disk as a vfat drive; which requires
       *mtools* (specified by the `mtools_path` option in the `Default` section)

This service is usually faster than the HTTP twin, as there is no timeout
waiting for the network to be up.

Metadata version used: `latest`.

Capabilities:

    * instance id
    * hostname
    * public keys
    * authentication certificates
    * static network configuration
    * admin user name
    * admin user password
    * user data

Config options for `config_drive` section:

    * raw_hdd (bool: True)
    * cdrom (bool: True)
    * vfat (bool: True)
    * types (list: ["vfat", "iso"])
    * locations (list: ["cdrom", "hdd", "partition"])


.. _nocloudconfigdrive:

NoCloud configuration drive
-------------------------------

.. class:: cloudbaseinit.metadata.services.nocloudservice.NoCloudConfigDriveService

NoCloudConfigDriveService is similar to OpenStack config drive metadata in terms of
the medium on which the data is provided (as an attached ISO, partition or disk) and
similar to the EC2 metadata in terms of how the metadata files are named and structured.

The metadata is provided on a config-drive (vfat or iso9660) with the label cidata or CIDATA.

The folder structure for NoCloud is:

  * /user-data
  * /meta-data

The user-data and meta-data files respect the EC2 metadata service format.

Capabilities:

    * instance id
    * hostname
    * public keys
    * static network configuration (Debian and `network config v1
      <https://cloudinit.readthedocs.io/en/latest/topics/network-config-format-v1.html>`_
      formats)
    * user data

Config options for `config_drive` section:

    * raw_hdd (bool: True)
    * cdrom (bool: True)
    * vfat (bool: True)
    * types (list: ["vfat", "iso"])
    * locations (list: ["cdrom", "hdd", "partition"])

Example metadata:

.. code-block:: yaml

    instance-id: windows1
    network-interfaces: |
      iface Ethernet0 inet static
      address 10.0.0.2
      network 10.0.0.0
      netmask 255.255.255.0
      broadcast 10.0.0.255
      gateway 10.0.0.1
      hwaddress ether 00:11:22:33:44:55
    hostname: windowshost1

Cloud-init's `network config v1
<https://cloudinit.readthedocs.io/en/latest/topics/network-config-format-v1.html>`_
format can be used to configure static network configuration.
The configuration file should be named `network-config` and should be present
at the same folder level with the `meta-data` and `user-data` file.
If no `network-config` is found, cloudbase-init will use the `network-interfaces`
value from the metadata (if any).

The following network config types are implemented: physical, bond, vlan and
nameserver.
Unsupported config types: bridge and route.

Example:

.. code-block:: yaml

    version: 1
    config:
       - type: physical
         name: interface0
         mac_address: "52:54:00:12:34:00"
         mtu: 1450
         subnets:
            - type: static
              address: 192.168.1.10
              netmask: 255.255.255.0
              dns_nameservers:
                - 192.168.1.11
       - type: bond
         name: bond0
         bond_interfaces:
           - gbe0
           - gbe1
         mac_address: "52:54:00:12:34:00"
         params:
           bond-mode: active-backup
           bond-lacp-rate: false
         mtu: 1450
         subnets:
            - type: static
              address: 192.168.1.10
              netmask: 255.255.255.0
              dns_nameservers:
                - 192.168.1.11
       - type: vlan
         name: vlan0
         vlan_link: eth1
         vlan_id: 150
         mac_address: "52:54:00:12:34:00"
         mtu: 1450
         subnets:
            - type: static
              address: 192.168.1.10
              netmask: 255.255.255.0
              dns_nameservers:
                - 192.168.1.11
       - type: nameserver
         address:
           - 192.168.23.2
           - 8.8.8.8
         search: acme.local

More information on the NoCloud metadata service specifications can be found
`here <https://cloudinit.readthedocs.io/en/latest/topics/datasources/nocloud.html>`_.

Amazon EC2
----------

.. class:: cloudbaseinit.metadata.services.ec2service.EC2Service

This is similar to the OpenStack HTTP service but is using a different
format for metadata endpoints and has general capabilities.

Metadata version used: `2009-04-04`.

Capabilities:

    * instance id
    * hostname
    * public keys
    * user data

Config options for `ec2` section:

    * metadata_base_url (string: "http://169.254.169.254/")
    * add_metadata_private_ip_route (bool: True)
    * https_allow_insecure (bool: False)
    * https_ca_bundle (string: None)

Config options for `default` section:

    * retry_count (integer: 5)
    * retry_count_interval (integer: 4)

.. note:: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html


Apache CloudStack
-----------------

.. class:: cloudbaseinit.metadata.services.cloudstack.CloudStack

Another web-based service which usually uses "10.1.1.1" or DHCP addresses for
retrieving content. If no metadata can be found at the `metadata_base_url`,
the service will look for the metadata at the DHCP server URL.

Capabilities:

    * instance id
    * hostname
    * public keys
    * admin user password
    * poll for, post, delete admin user password (each reboot)
    * user data

Config options for `cloudstack` section:

    * metadata_base_url (string: "http://10.1.1.1/")
    * password_server_port (int: 8080)
    * add_metadata_private_ip_route (bool: True)
    * https_allow_insecure (bool: False)
    * https_ca_bundle (string: None)

Config options for `default` section:

    * retry_count (integer: 5)
    * retry_count_interval (integer: 4)

.. note:: By design, this service can update the password anytime, so it will
          cause the `setuserpassword` plugin to run at every boot and
          by security concerns, the password is deleted right after retrieval
          and no updating will occur until a new password is available on the
          server.


OpenNebula Service
------------------

.. class:: cloudbaseinit.metadata.services.opennebulaservice.OpenNebulaService

The *OpenNebula* provider is related to configuration drive and searches for
a specific context file which holds all the available info. The provided
details are exposed as bash variables gathered in a shell script.

Capabilities:

    * hardcoded instance id to `iid-dsopennebula`
    * hostname
    * public keys
    * static network configuration
    * user data

Config options for `default` section:

    * retry_count (integer: 5)
    * retry_count_interval (integer: 4)


Ubuntu MaaS
-----------

.. class:: cloudbaseinit.metadata.services.maasservice.MaaSHttpService

This metadata service usually works with instances on baremetal and
uses web requests for retrieving the available exposed metadata. It uses
`OAuth <http://oauth.net/>`_ to secure the requests.

Metadata version used: `2012-03-01`.

Capabilities:

    * instance id
    * hostname
    * public keys
    * `WinRM <https://docs.microsoft.com/en-us/windows/win32/winrm/authentication-for-remote-connections#client-certificate-based-authentication>`_ authentication certificates
    * static network configuration
    * user data

Config options for `maas` section:

    * metadata_base_url (string: None)
    * oauth_consumer_key (string: None)
    * oauth_consumer_secret (string: None)
    * oauth_token_key (string: None)
    * oauth_token_secret (string: None)
    * https_allow_insecure (bool: False)
    * https_ca_bundle (string: None)

Config options for `default` section:

    * retry_count (integer: 5)
    * retry_count_interval (integer: 4)

.. note:: By design, the configuration options are set by an agent
          called `curtin <https://curtin.readthedocs.io/en/latest/topics/overview.html>`_
          which runs the hooks that set the config values.
          On Windows, these hooks need to be present in the root directory:
          `Windows curtin hooks <https://github.com/cloudbase/windows-curtin-hooks>`_.


Open Virtualization Format (OVF)
--------------------------------

.. class:: cloudbaseinit.metadata.services.ovfservice.OvfService

The *OVF* provider searches data from OVF environment ISO transport.

Capabilities:

    * instance id (hardcoded to `iid-ovf` if not present)
    * hostname
    * public keys
    * admin user name
    * admin user password
    * user data

Config options:

    * config_file_name (string: "ovf-env.xml")
    * drive_label (string: "OVF ENV")
    * ns (string: "oe")

Packet Service
--------------

.. class:: cloudbaseinit.metadata.services.packet.PacketService

`Packet <packet.net>`_ metadata service provides the metadata for baremetal servers
at the magic URL `https://metadata.packet.net/`.

Capabilities:

    * instance id
    * hostname
    * public keys
    * post admin user password (only once)
    * user data
    * call home on successful provision

Config options for `packet` section:

    * metadata_base_url (string: "https://metadata.packet.net/")
    * https_allow_insecure (bool: False)
    * https_ca_bundle (string: None)

Config options for `default` section:

    * retry_count (integer: 5)
    * retry_count_interval (integer: 4)


Azure Service
--------------

.. class:: cloudbaseinit.metadata.services.azureservice.AzureService

`Azure <https://azure.microsoft.com/>`_ metadata service provides the metadata
for Microsoft Azure cloud platform.

Azure metadata is offered via multiple sources like HTTP metadata, config-drive metadata
and KVP (Hyper-V Key-Value Pair Data Exchange).
This implementation uses only HTTP and config-drive metadata sources.

Azure service implements the interface to notify the cloud provider when the instance
has started provisioning, completed provisioning and if the provisioning failed.

Metadata version used: `2015-04-05`.

Capabilities:

    * instance id
    * hostname
    * public keys
    * `WinRM <https://docs.microsoft.com/en-us/windows/win32/winrm/authentication-for-remote-connections#client-certificate-based-authentication>`_ authentication certificates
    * admin user name
    * admin user password
    * user data
    * post RDP certificate thumbprint
    * provisioning status
    * Windows Update status
    * VM agent configuration
    * licensing configuration
    * ephemeral disk warning

Config options for `azure` section:

    * transport_cert_store_name (string: Windows Azure Environment")

Config options for `default` section:

    * retry_count (integer: 5)
    * retry_count_interval (integer: 4)

Empty Metadata Service
----------------------

.. class:: cloudbaseinit.metadata.services.base.EmptyMetadataService

The empty metadata service can be used to run plugins that do not
rely on metadata service information, like setting NTP, MTU,
extending volumes, local scripts execution, licensing, etc.

It can be used also as a fallback metadata service, in case no other
previous metadata service could be loaded.

EmptyMetadataService does not support the following plugins:
  * cloudbaseinit.plugins.windows.createuser.CreateUserPlugin
  * cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin
  * cloudbaseinit.plugins.common.sshpublickeys.SetUserSSHPublicKeysPlugin
  * cloudbaseinit.plugins.windows.winrmcertificateauth.ConfigWinRMCertificateAuthPlugin

If any of the plugins defined above are executed,
they will fail with exception NotExistingMetadataException. The reason
for the hardcoded failure is that these plugins rely on metadata to execute
correctly. If metadata like username or password is not provided,
these plugins can lock or misconfigure the user, leading to unwanted problems.


.. note:: If a service returns an empty instance-id (like EmptyMetadataService does),
          all the plugins will be executed at every cloudbase-init run (reboot, service restart).
          Plugins that set NTP, MTU, extend volumes are idempotent and can be re-executed
          with no issues. Make sure that if you configure cloudbase-init to run local scripts,
          those local scripts are idempotent.


VMware GuestInfo Service
------------------------

.. class:: cloudbaseinit.metadata.services.vmwareguestinfoservice.VMwareGuestInfoService

VMwareGuestInfoService is a metadata service which uses VMware's rpctool to extract guest
metadata and userdata configured for machines running on VMware hypervisors.

The VMware RPC tool used to query the instance metadata and userdata needs to be present at
the config option path.

Both json and yaml are supported as metadata formats.
The metadata / userdata can be encoded in base64, gzip or gzip+base64.

Example metadata in yaml format:

  .. code-block:: yaml

    instance-id: cloud-vm
    local-hostname: cloud-vm
    admin-username: cloud-username
    admin-password: Passw0rd
    public-keys-data: |
      ssh-key 1
      ssh-key 2

This metadata content needs to be set as string in the guestinfo
dictionary, thus needs to be converted to base64 (it is recommended to
gzip it too).
To convert to gzip+base64 format:

.. code-block:: bash

    cat metadata.yml | gzip.exe -9 | base64.exe -w0

The output of the gzip+base64 conversion needs to be set in the instance guestinfo, along with
the encoding of the metadata / userdata.

For more information on how to achieve this, please check https://github.com/vmware/cloud-init-vmware-guestinfo#configuration

This is an example how to set the information from the instance:

.. code-block:: bash

    <rpctool_path> "info-set guestinfo.metadata <gzip+base64-encoded-metadata>"
    <rpctool_path> "info-set guestinfo.metadata.encoding gzip+base64"
    <rpctool_path> "info-set guestinfo.userdata <gzip+base64-encoded-userdata>"
    <rpctool_path> "info-set guestinfo.userdata.encoding gzip+base64"


Capabilities:

    * instance id
    * hostname
    * public keys
    * admin user name
    * admin user password
    * user data

Config options for `vmwareguestinfo` section:

    * vmware_rpctool_path (string: "%ProgramFiles%/VMware/VMware Tools/rpctool.exe")


Google Compute Engine Service
-----------------------------

.. class:: cloudbaseinit.metadata.services.gceservice.GCEService

`GCE <https://cloud.google.com/compute/>`_ metadata service provides
the metadata for instances running on Google Compute Engine.

GCE metadata is offered via an internal HTTP metadata endpoint, reachable at the magic URL
`http://metadata.google.internal/computeMetadata/v1/`. More information can be found in the GCE
metadata `documents <https://cloud.google.com/compute/docs/storing-retrieving-metadata#querying>`_.

To provide userdata to be executed by the instance (in cloud-config format, for example), use the
user-data and user-data-encoding instance metadata keys.

Capabilities:

    * instance id
    * hostname
    * public keys
    * user data

Config options for `gce` section:

    * metadata_base_url (string: http://metadata.google.internal/computeMetadata/v1/")
    * https_allow_insecure (bool: False)
    * https_ca_bundle (string: None)

Config options for `default` section:

    * retry_count (integer: 5)
    * retry_count_interval (integer: 4)
