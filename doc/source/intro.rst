Intro
=====

The open source `project <https://github.com/openstack/cloudbase-init>`_
**cloudbase-init** is a service conceived and
maintained by Cloudbase Solutions Srl, currently working on NT systems.
It was designed to initialize and configure guest operating systems under
`OpenStack <https://www.openstack.org/>`_,
`OpenNebula <http://opennebula.org/>`_,
`CloudStack <https://cloudstack.apache.org/>`_,
`MaaS <https://maas.ubuntu.com/>`_ and many others.
Under `Cloudbase <http://www.cloudbase.it/cloud-init-windows/>`_ page,
stable and beta installers can be found and the service itself is very easy to
configure through configuration files. It can also customize instances based
on user input like local scripts and data.

More details on how you can use this can be found under :ref:`tutorial`.


Portable cloud initialization service
-------------------------------------

The main goal of this project is to provide guest cloud initialization for
*Windows* and other operating systems.
The architecture of the project is highly flexible and allows extensions for
additional clouds and plugins.

There's no limitation in the type of supported hypervisors. This service can be
used on instances running on Hyper-V, KVM, Xen, ESXi etc.


.. _download:

Binaries
--------

Stable installers:

* https://www.cloudbase.it/downloads/CloudbaseInitSetup_Stable_x64.msi
* https://www.cloudbase.it/downloads/CloudbaseInitSetup_Stable_x86.msi

Beta installers:

* https://www.cloudbase.it/downloads/CloudbaseInitSetup_x64.msi
* https://www.cloudbase.it/downloads/CloudbaseInitSetup_x86.msi

Use a x64 installer on 64 bit versions of Windows and the x86 one
exclusively on 32 bit versions.
