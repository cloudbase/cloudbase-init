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
    * admin user password
    * user data

Config options for `config_drive` section:

    * raw_hdd (bool: True)
    * cdrom (bool: True)
    * vfat (bool: True)
    * types (list: ["vfat", "iso"])
    * locations (list: ["cdrom", "hdd", "partition"])


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
    * user data

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
