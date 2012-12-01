# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Cloudbase Solutions Srl
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

import setuptools

from nova.openstack.common import setup as common_setup
from nova import version

requires = common_setup.parse_requirements()
dependency_links = common_setup.parse_dependency_links()

setuptools.setup(name='cloudbase-init',
      version='0.9.0',
      description='Portable cloud initialization service',
      author='Cloudbase Solutions Srl',
      author_email='apilotti@cloudbasesolutions.com',
      url='http://www.cloudbase.it/',
      classifiers=[
          'Environment :: OpenStack',
          'Intended Audience :: Information Technology',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: Apache Software License',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          ],
      cmdclass=common_setup.get_cmdclass(),
      packages=setuptools.find_packages(exclude=['bin']),
      install_requires=requires,
      dependency_links=dependency_links,
      include_package_data=True,
      setup_requires=['setuptools_git>=0.4'],
      entry_points={'console_scripts': ['cloudbase-init = cloudbaseinit.shell:main']},
        py_modules=[])
