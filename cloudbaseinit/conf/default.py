# Copyright 2016 Cloudbase Solutions Srl
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


"""Config options available all across the project."""

from oslo_config import cfg

from cloudbaseinit.conf import base as conf_base
from cloudbaseinit import constant


class GlobalOptions(conf_base.Options):

    """Config options available all across the project."""

    def __init__(self, config):
        super(GlobalOptions, self).__init__(config, group="DEFAULT")
        self._options = [
            cfg.BoolOpt(
                'allow_reboot', default=True,
                help='Allows OS reboots requested by plugins'),
            cfg.BoolOpt(
                'stop_service_on_exit', default=True,
                help='In case of execution as a service, specifies if the '
                     'service must be gracefully stopped before exiting'),
            cfg.BoolOpt(
                'check_latest_version', default=False,
                help='Check if there is a newer version of cloudbase-init '
                     'available.  If this option is activated, a log '
                     'message  will be  emitted if there is a newer version '
                     'available.'),
            cfg.IntOpt(
                'retry_count', default=5,
                help='Max. number of attempts for fetching metadata in '
                     'case of transient errors'),
            cfg.FloatOpt(
                'retry_count_interval', default=4,
                help='Interval between attempts in case of transient errors, '
                     'expressed in seconds'),
            cfg.StrOpt(
                'mtools_path', default=None,
                help='Path to "mtools" program suite, used for interacting '
                     'with VFAT filesystems'),
            cfg.StrOpt(
                'bsdtar_path', default='bsdtar.exe',
                help='Path to "bsdtar", used to extract ISO ConfigDrive '
                     'files'),
            cfg.BoolOpt(
                'netbios_host_name_compatibility', default=True,
                help='Truncates the hostname to 15 characters for Netbios '
                     'compatibility'),
            cfg.StrOpt(
                'logging_serial_port_settings', default=None,
                help='Serial port logging settings. Format: '
                     '"port,baudrate,parity,bytesize", e.g.: '
                     '"COM1,115200,N,8". Set to None (default) to disable.'),
            cfg.BoolOpt(
                'activate_windows', default=False,
                help='Activates Windows automatically'),
            cfg.BoolOpt(
                'set_kms_product_key', default=False,
                help='Sets the KMS product key for this operating system'),
            cfg.BoolOpt(
                'set_avma_product_key', default=False,
                help='Sets the AVMA product key for this operating system'),
            cfg.StrOpt(
                'kms_host', default=None,
                help='The KMS host address in form <host>[:<port>], '
                     'e.g: "kmshost:1688"'),
            cfg.BoolOpt(
                'log_licensing_info', default=True,
                help='Logs the operating system licensing information'),
            cfg.BoolOpt(
                'winrm_enable_basic_auth', default=True,
                help='Enables basic authentication for the WinRM '
                     'HTTPS listener'),
            cfg.BoolOpt(
                'winrm_configure_http_listener', default=False,
                help='Configures the WinRM HTTP listener'),
            cfg.BoolOpt(
                'winrm_configure_https_listener', default=True,
                help='Configures the WinRM HTTPS listener'),
            cfg.ListOpt(
                'volumes_to_extend', default=None,
                help='List of volumes that need to be extended '
                     'if contiguous space is available on the disk. '
                     'By default all the available volumes can be extended. '
                     'Volumes must be specified using a comma separated list '
                     'of volume indexes, e.g.: "1,2"'),
            cfg.StrOpt(
                'san_policy', default=None,
                choices=[constant.SAN_POLICY_ONLINE_STR,
                         constant.SAN_POLICY_OFFLINE_STR,
                         constant.SAN_POLICY_OFFLINE_SHARED_STR],
                help='If not None, the SAN policy is set to the given value'),
            cfg.StrOpt(
                'local_scripts_path', default=None,
                help='Path location containing scripts to be executed when '
                     'the plugin runs'),
            cfg.BoolOpt(
                'mtu_use_dhcp_config', default=True,
                help='Configures the network interfaces MTU based on the '
                     'values provided via DHCP'),
            cfg.StrOpt(
                'username', default='Admin', help='User to be added to the '
                'system or updated if already existing'),
            cfg.ListOpt(
                'groups', default=['Administrators'],
                help='List of local groups to which the user specified in '
                     '"username" will be added'),
            cfg.BoolOpt(
                'rename_admin_user', default=False,
                help='Renames the builtin admin user instead of creating a '
                     'new user'),
            cfg.StrOpt(
                'heat_config_dir', default='C:\\cfn',
                help='The directory where the Heat configuration files must '
                     'be saved'),
            cfg.BoolOpt(
                'ntp_enable_service', default=True,
                help='Enables the NTP client service'),
            cfg.BoolOpt(
                'ntp_use_dhcp_config', default=False,
                help='Configures NTP client time synchronization using '
                     'the NTP servers provided via DHCP'),
            cfg.BoolOpt(
                'real_time_clock_utc', default=False,
                help='Sets the real time clock to use universal time (True) '
                     'or local time (False)'),
            cfg.BoolOpt(
                'inject_user_password', default=True,
                help='Set the password provided in the configuration. '
                     'If False or no password is provided, a random one '
                     'will be set'),
            cfg.StrOpt(
                'first_logon_behaviour',
                default=constant.CLEAR_TEXT_INJECTED_ONLY,
                choices=constant.LOGON_PASSWORD_CHANGE_OPTIONS,
                help='Control the behaviour of what happens at '
                     'next logon. If this option is set to `always`, '
                     'then the user will be forced to change the password '
                     'at next logon. If it is set to '
                     '`clear_text_injected_only`, '
                     'then the user will have to change the password only if '
                     'the password is a clear text password, coming from the '
                     'metadata. The last option is `no`, when the user is '
                     'never forced to change the password.'),
            cfg.ListOpt(
                'metadata_services',
                default=[
                    'cloudbaseinit.metadata.services.httpservice.HttpService',
                    'cloudbaseinit.metadata.services'
                    '.configdrive.ConfigDriveService',
                    'cloudbaseinit.metadata.services.ec2service.EC2Service',
                    'cloudbaseinit.metadata.services'
                    '.maasservice.MaaSHttpService',
                    'cloudbaseinit.metadata.services.cloudstack.CloudStack',
                    'cloudbaseinit.metadata.services'
                    '.opennebulaservice.OpenNebulaService',
                ],
                help='List of enabled metadata service classes, '
                     'to be tested for availability in the provided order. '
                     'The first available service will be used to retrieve '
                     'metadata'),
            cfg.ListOpt(
                'plugins',
                default=[
                    'cloudbaseinit.plugins.common.mtu.MTUPlugin',
                    'cloudbaseinit.plugins.windows.ntpclient'
                    '.NTPClientPlugin',
                    'cloudbaseinit.plugins.common.sethostname'
                    '.SetHostNamePlugin',
                    'cloudbaseinit.plugins.windows.createuser'
                    '.CreateUserPlugin',
                    'cloudbaseinit.plugins.common.networkconfig'
                    '.NetworkConfigPlugin',
                    'cloudbaseinit.plugins.windows.licensing'
                    '.WindowsLicensingPlugin',
                    'cloudbaseinit.plugins.common.sshpublickeys'
                    '.SetUserSSHPublicKeysPlugin',
                    'cloudbaseinit.plugins.windows.extendvolumes'
                    '.ExtendVolumesPlugin',
                    'cloudbaseinit.plugins.common.userdata.UserDataPlugin',
                    'cloudbaseinit.plugins.common.setuserpassword.'
                    'SetUserPasswordPlugin',
                    'cloudbaseinit.plugins.windows.winrmlistener.'
                    'ConfigWinRMListenerPlugin',
                    'cloudbaseinit.plugins.windows.winrmcertificateauth.'
                    'ConfigWinRMCertificateAuthPlugin',
                    'cloudbaseinit.plugins.common.localscripts'
                    '.LocalScriptsPlugin',
                ],
                help='List of enabled plugin classes, '
                     'to be executed in the provided order'),
            cfg.ListOpt(
                'user_data_plugins',
                default=[
                    'cloudbaseinit.plugins.common.userdataplugins.parthandler.'
                    'PartHandlerPlugin',
                    'cloudbaseinit.plugins.common.userdataplugins.cloudconfig.'
                    'CloudConfigPlugin',
                    'cloudbaseinit.plugins.common.userdataplugins'
                    '.cloudboothook.CloudBootHookPlugin',
                    'cloudbaseinit.plugins.common.userdataplugins.shellscript.'
                    'ShellScriptPlugin',
                    'cloudbaseinit.plugins.common.userdataplugins'
                    '.multipartmixed.MultipartMixedPlugin',
                    'cloudbaseinit.plugins.common.userdataplugins.heat.'
                    'HeatPlugin',
                ],
                help='List of enabled userdata content plugins'),
            cfg.ListOpt(
                'cloud_config_plugins', default=[],
                help='List which contains the name of the cloud config '
                     'plugins ordered by priority.'),
            cfg.BoolOpt(
                'rdp_set_keepalive', default=True,
                help='Sets the RDP KeepAlive policy'),
            cfg.StrOpt(
                'bcd_boot_status_policy',
                default=None,
                choices=[constant.POLICY_IGNORE_ALL_FAILURES],
                help='Sets the Windows BCD boot status policy'),
            cfg.BoolOpt(
                'bcd_enable_auto_recovery', default=False,
                help='Enables or disables the BCD auto recovery'),
            cfg.BoolOpt(
                'set_unique_boot_disk_id', default=True,
                help='Sets a new random unique id on the boot disk to avoid '
                     'collisions'),
            cfg.IntOpt(
                'display_idle_timeout', default=0,
                help='The idle timeout, in seconds, before powering off '
                     'the display. Set 0 to leave the display always on'),
            cfg.ListOpt(
                'page_file_volume_labels', default=[],
                help='Labels of volumes on which a Windows page file needs to '
                     'be created. E.g.: "Temporary Storage"'),
            cfg.ListOpt(
                'page_file_volume_mount_points', default=[],
                help='Volume mount points on which a Windows page file needs '
                     'to be created. E.g.: '
                     '"\\\\?\\GLOBALROOT\\device\\Harddisk1\\Partition1\\"'),
            cfg.BoolOpt(
                'trim_enabled', default=False,
                help='Enables or disables TRIM delete notifications for '
                     'the underlying storage device.'),
            cfg.BoolOpt(
                'process_userdata', default=True,
                help='Processes the userdata content based on the type, e.g. '
                     'executing a PowerShell script'),
            cfg.StrOpt(
                'userdata_save_path',
                default=None,
                help='Copies the userdata to the given file path. The path '
                     'can include environment variables that will be expanded,'
                     ' e.g. "%%SYSTEMDRIVE%%\\CloudbaseInit\\UserData.bin"'),
            cfg.BoolOpt(
                'enable_automatic_updates', default=None,
                help='If set, enables or disables automatic operating '
                     'system updates.'),
            cfg.BoolOpt(
                'metadata_report_provisioning_started', default=False,
                help='Reports to the metadata service that provisioning has '
                     'started'),
            cfg.BoolOpt(
                'metadata_report_provisioning_completed', default=False,
                help='Reports to the metadata service that provisioning '
                     'completed successfully or failed'),
            cfg.StrOpt(
                'ephemeral_disk_volume_label', default=None,
                help='Ephemeral disk volume label, e.g.: "Temporary Storage"'),
            cfg.StrOpt(
                'ephemeral_disk_volume_mount_point', default=None,
                help='Ephemeral disk volume mount point, e.g.:'
                     '"\\\\?\\GLOBALROOT\\device\\Harddisk1\\Partition1\\"'),
            cfg.StrOpt(
                'ephemeral_disk_data_loss_warning_path', default=None,
                help='Ephemeral disk data loss warning path, relative to the '
                     'ephemeral disk volume path. E.g.: '
                     'DATALOSS_WARNING_README.txt'),
            cfg.IntOpt(
                'user_password_length', default=20,
                help='The length of the generated password for the user '
                     'defined by the `username` config option.'),
        ]

        self._cli_options = [
            cfg.BoolOpt(
                'reset_service_password', default=True,
                help='If set to True, the service user password will be '
                     'reset at each execution with a new random value of '
                     'appropriate length and complexity, unless the user is '
                     'a built-in or domain account.'
                     'This is needed to avoid "pass the hash" attacks on '
                     'Windows cloned instances.'),
        ]

    def register(self):
        """Register the current options to the global ConfigOpts object."""
        self._config.register_cli_opts(self._cli_options)
        self._config.register_opts(self._options + self._cli_options)

    def list(self):
        """Return a list which contains all the available options."""
        return self._options
