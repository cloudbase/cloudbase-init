# coding: utf-8

from cloudbaseinit.plugins.common import base
import os
import re


class CreateVolumesPlugin(base.BasePlugin):

    _fstype = 'ntfs'

    def _get_offline_disks(self):
        offline_disks = []
        pattern = re.compile('[^ ]+')
        lines = os.popen('echo list disk | diskpart').readlines()
        for line in lines:
            ss = pattern.findall(line)
            if len(ss) < 3:
                continue
            if (ss[0] == '磁盘' and ss[2] == '脱机') or (ss[0].lower() == 'disk' and ss[2].lower == 'offline'):
                offline_disks.append(int(ss[1]))
        return offline_disks

    def _createvolume(self, disk, do_online, is_old_sys):
        # make partition(and format if supported)
        script = 'C:\\Windows\\temp\\cloudbase-diskpart.txt'
        with open(script, 'w') as f:
            f.write('select disk %d\r\n' % disk.Index)
            if do_online:
                if is_old_sys:
                    f.write('online\r\n')
                else:
                    f.write('online disk\r\n')
                    f.write('attr disk clear readonly\r\n')
            f.write('create partition primary\r\n')
            if not is_old_sys:
                f.write('format fs=%s quick\r\n' % self._fstype)
            f.write('assign')
        os.popen('diskpart /s %s' % script).readlines()
        os.remove(script)

        # format
        if is_old_sys:
            for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                    os.popen('format %s /v: /fs:%s /q /y' % (logical_disk.DeviceId, self._fstype)).readlines()

    def execute(self, service, shared_data):
        from cloudbaseinit.osutils import windows
        import wmi
        is_old_sys = not windows.WindowsUtils().check_os_version(6, 1)
        offline_disks = self._get_offline_disks()
        conn = wmi.WMI()
        disks = conn.Win32_DiskDrive()
        for disk in disks:
            if disk.Partitions > 0:
                continue
            self._createvolume(disk, do_online=disk.Index in offline_disks, is_old_sys=is_old_sys)

        return base.PLUGIN_EXECUTE_ON_NEXT_BOOT, False

    def get_os_requirements(self):
        return 'win32', (5, 1)
