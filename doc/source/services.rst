.. _services:

Services
========

A **metadata service** has the role of pulling the guest provided data
(configuration information) and exposing it to the :ref:`plugins` for a
general and basic initialization of the instance.
These sub-services can change their behavior according to custom
configuration options, if they are specified, which are documented below.

Supported metadata services (cloud specific):


.. _httpservice:

OpenStack (web API)
-------------------

.. class:: cloudbaseinit.metadata.services.httpservice.HttpService

A complete service which also supports password related capabilities and
can be usually accessed with http://169.254.169.254/ magic address, which can
also be changed using `metadata_base_url` option under the config file. A
default value of *True* for `add_metadata_private_ip_route` option is used
to add a route for the IP address to the gateway. This is needed for supplying
a bridge between different VLANs in order to get access to the web server.

Capabilities:

    * instance ID
    * host name
    * public keys
    * authentication certificates (metadata + user data)
    * static network configuration addresses
    * admin password
    * user data
    * user content (additional files)
    * ability to post passwords

Config options:

    * metadata_base_url (string: "http://169.254.169.254/")
    * add_metadata_private_ip_route (bool: True)


.. _configdrive:

OpenStack (configuration drive)
-------------------------------

.. class:: cloudbaseinit.metadata.services.configdrive.ConfigDriveService

This is similar to the web API, but it "serves" its files locally without
requiring network access. The data is generally retrieved from a
`cdrom <https://en.wikipedia.org/wiki/ISO_9660>`_,
`vfat <https://en.wikipedia.org/wiki/File_Allocation_Table#VFAT>`_ or
*raw* disks/partitions by enabling selective lookup across different devices.
Use the `config_drive_types` option to specify which types of config drive
content the service will search for and also on which devices using the
`config_drive_locations` option.

.. warning:: *deprecated options*

Using the option:

    a. `config_drive_cdrom`
    b. `config_drive_raw_hhd`
    c. `config_drive_vfat`

It will search for metadata:

    a. in mounted optical units
    b. directly in the physical disk bytes
    c. by exploring the physical disk as a vfat drive; which requires
       *mtools* (specified by the `mtools_path` option)

The interesting part with this service is the fact that is quite fast in
comparison with the HTTP twin.

Capabilities:

    * instance ID
    * host name
    * public keys (search in the entire metadata)
    * authentication certificates (metadata + user data)
    * static network configuration addresses
    * admin password
    * user data
    * user content (additional files)

Config options:

    * config_drive_types (list: ["vfat", "iso"])
    * config_drive_locations (list: ["cdrom", "hdd", "partition"])
    * mtools_path (string: None)


Amazon EC2
----------

.. class:: cloudbaseinit.metadata.services.ec2service.EC2Service

This is similar to the OpenStack HTTP service but is using a different
format for URLs and is having general capabilities.

Capabilities:

    * instance ID
    * host name
    * public keys

Config options:

    * ec2_metadata_base_url (string: "http://169.254.169.254/")
    * ec2_add_metadata_private_ip_route (bool: True)

.. note:: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html


CloudStack
----------

.. class:: cloudbaseinit.metadata.services.cloudstack.CloudStack

Another web-based service which usually uses "10.1.1.1" or DHCP addresses for
retrieving content.

Capabilities:

    * instance ID
    * host name
    * public keys
    * admin password (retrieval/deletion/polling)
    * user data

Config options:

    * cloudstack_metadata_ip (string: "10.1.1.1")

.. note:: By design, this service can update the password anytime, so it will
          cause the `setuserpassword` plugin to run at every boot and
          by security concerns, the password is deleted right after retrieval
          and no updating will occur until a new password is available on the
          server.


OpenNebula
----------

.. class:: cloudbaseinit.metadata.services.opennebulaservice.OpenNebulaService

The *OpenNebula* provider is related to configuration drive and searches for
a specific context file which holds all the available info. The provided
details are exposed as bash variables gathered in a shell script.

Capabilities:

    * instance ID (not present; usually a constant is returned)
    * host name
    * public keys
    * static network configuration addresses
    * user data


Ubuntu MaaS
-----------

.. class:: cloudbaseinit.metadata.services.maasservice.MaaSHttpService

This one works with instances on bare metal and uses web requests for
retrieving the available exposed metadata. It uses
`OAuth <http://oauth.net/>`_ to secure the requests.

Capabilities:

    * instance ID
    * host name
    * public keys
    * authentication certificates (x509)
    * user data

----

Configuring available services
------------------------------

Some of these classes can be specified manually in the configuration file
under `metadata_services` option. Based on this option, the service loader
will search across these providers and try to load the most suitable one.

For more details on doing this, see :ref:`configuration <config>`
file in :ref:`tutorial`.
