Portable OpenStack Cloud Initialization Service 
===============================================

The main goal of this project is to bring the benefits of cloud-init to guests running a wide range of OSs.
The first release provides support for Windows OSs, but due to the modular and decoupled architecture of the service, plugins for any OS can be easily added.

The features available with the first release include HTTP and ConfigDriveV2 metadata services and plugins for:  
hostname, user creation, group membership, static networking, SSH user's public keys, user_data custom scripts running in various shells (CMD.exe / Powershell / bash)

There's no limitation in the type of supported Hypervisor. This service can be used on instances running on Hyper-V, KVM, Xen, ESXi, etc

Documentation, support and contacts: http://www.cloudbase.it 


Metatada services
-----------------

A metadata service has the role of pulling the metadata configuration information. 
ConfigDriveV2 and HTTP are supported out of the box, but other sources can be easily added. 


Plugins
-------

Plugins execute actions based on the metadata obtained by the service.

Currently the following plugins have been implemented for the Windows OS:


cloudbaseinit.plugins.windows.sethostname.SetHostNamePlugin

Sets the instance's hostname


cloudbaseinit.plugins.windows.createuser.CreateUserPlugin

Creates / updates a user setting the password provided in the metadata (admin_pass) if available.
The user is then added to a set of provided local groups.
The following configuration parameters control the behaviour of this plugin:

username
default: Admin

groups
Comma separated list of groups. Default: Administrators

inject_user_password
Can be set to false to avoid the injection of the password provided in the metadata. Default: True


cloudbaseinit.plugins.windows.networkconfig.NetworkConfigPlugin

Configures static networking.

network_adapter
Network adapter to configure. If not specified, the first available ethernet adapter will be chosen. Default: None


cloudbaseinit.plugins.windows.sshpublickeys.SetUserSSHPublicKeysPlugin

Creates an "authorized_keys" file in the user's home directory containing the SSH keys provided in the metadata.
Note: on Windows a SSH service needs to be installed to take advantage of this feature.


cloudbaseinit.plugins.windows.userdata.UserDataPlugin

Executes custom scripts provided with the user_data metadata as plain text or compressed with Gzip. 

Supported formats:

Windows batch

The file is executed in a cmd.exe shell (can be changed with the COMSPEC environment variable).
The user_data first line must be:
rem cmd

Powershell

Scripting is automatically enabled if not set (RemoteSigned).
The user_data first line must be:
#ps1

Bash
A bash shell needs to be installed in the system and available in the PATH in order to use this feature. 
The user_data first line must start with:
#!



