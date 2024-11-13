# Copyright 2014 Cloudbase Solutions Srl
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

import os
import json
import yaml

from oslo_log import log as oslo_logging
from oslo_config import cfg

from cloudbaseinit import exception, conf as cloudbaseinit_conf
from cloudbaseinit.conf import base as conf_base
from cloudbaseinit.metadata.services import maasservice
from cloudbaseinit.models import network as network_model
from cloudbaseinit.plugins.common import base, networkconfig
from cloudbaseinit.osutils import windows

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)

class LocalNetworkConfigOptions(conf_base.Options):
    """Config options for the local network config plugin"""

    def __init__(self, config):
        super(LocalNetworkConfigOptions, self).__init__(config, group="local_network_config")
        self._options = [
            cfg.StrOpt(
                'config_path', default=None,
                help='Specify config file path override for reading local network configs.')
        ]

    def register(self):
        """Register the current options to the global ConfigOpts object."""
        group = cfg.OptGroup(self.group_name, title='Local Network Config Options')
        self._config.register_group(group)
        self._config.register_opts(self._options, group=group)

    def list(self):
        """Return a list which contains all the available options."""
        return self._options

class LocalNetworkConfigPlugin(base.BasePlugin):
    """Read local network configuration files to configure the network prior to metadata services"""

    execution_stage = base.PLUGIN_STAGE_PRE_NETWORKING

    def __init__(self):
        LocalNetworkConfigOptions(CONF).register()

    @staticmethod
    def _get_network_data():
        # Find the local network config file path.
        configPath = CONF.local_network_config.config_path
        if configPath is None:
            for filePath in ['/curtin/network.json', '/network.json', '/network.yaml', '/network.cfg']:
                if os.path.isfile(filePath):
                    configPath = filePath
                    break

        # If the config file wasn't found,
        if configPath is None or not os.path.isfile(configPath):
            LOG.info('The network config %s does not exist.' % configPath)
            return None

        # Parse the network config file.
        network_data = None
        try:
            file = open(configPath, 'r')
            fileExt = os.path.splitext(configPath)[1].lower()

            # Try yaml if the extension is one which is expected to be yaml.
            if fileExt==".yaml" or fileExt==".yml" or fileExt==".cfg":
                network_data = yaml.safe_load(file)
            else:
                # Default to json otherwise.
                network_data = json.load(file)
        except:
            file.close()
            raise exception.CloudbaseInitException('Error reading and parsing data.')
        file.close()
        return network_data

    @staticmethod
    def _create_bond_for_bondless_vlans(links: list, networks: list):
        # It is possible to have a vlan attached to an individual interface,
        # without a bond being created. The network configuration code requires
        # that a network team is created for each interface that has vlans.
        # We create bonds for such interfaces, and move configurations to that bond.

        # Get list of bond interface IDs.
        bond_links = [
            link.id for link in links if link.type == network_model.LINK_TYPE_BOND]

        # List of links that needs bonds added.
        bondless_links = []

        # Find all vlan links without a bond interface.
        for link in links:
            if (link.type == network_model.LINK_TYPE_VLAN and
                    not link.vlan_link is None and
                    not link.vlan_link in bond_links and
                    not link.vlan_link in bondless_links):
                bondless_links.append(link.vlan_link)

        # Create bonds for bondless links.
        for link_id in bondless_links:
            # Find the physical link for this vlan.
            for link1 in links:
                if (link1.type == network_model.LINK_TYPE_PHYSICAL and
                        link1.id == link_id):

                    # Create a new bond link for this interface.
                    bond_id = "%s_vlan" % link1.id
                    LOG.debug('New bond interface %s' % bond_id)
                    bond = network_model.Bond(
                        members=[link1.id],
                        type="active-backup",
                        lb_algorithm="layer2",
                        lacp_rate=None
                    )
                    link = network_model.Link(
                        id=bond_id,
                        name=bond_id,
                        type=network_model.LINK_TYPE_BOND,
                        enabled=True,
                        mac_address=link1.mac_address,
                        mtu=link1.mtu,
                        bond=bond,
                        vlan_id=None,
                        vlan_link=None
                    )

                    # Update all vlan links on this interface to use the bond.
                    for index, link2 in enumerate(links):
                        if (link2.type == network_model.LINK_TYPE_VLAN and
                            link2.vlan_link == link1.id):
                            links[index] = link2._replace(vlan_link=bond_id)

                    # Add the bond link.
                    bond_links.append(bond_id)
                    links.append(link)

                    # Update all networks which are assigned to the physical interface,
                    # so that they are now assigned to the bond interface we created.
                    for index, net in enumerate(networks):
                        if net.link==link1.id:
                            networks[index] = net._replace(link=bond_id)
                    break

    @staticmethod
    def _configure_interfaces_dhcp(config: list, links: list):
        # Loop through each local config item, find its interface name,
        # and enable or disable DHCP.
        for config_item in config:
            # If not an interface config, we should skip.
            if not config_item.get("type") in [
                maasservice.MAAS_CONFIG_TYPE_PHYSICAL,
                maasservice.MAAS_CONFIG_TYPE_BOND,
                maasservice.MAAS_CONFIG_TYPE_VLAN]:
                continue

            # Get the name from the local config.
            name = config_item.get("id")
            # Find if there is an vlan bond and update name to that.
            for link in links:
                if (link.type == network_model.LINK_TYPE_BOND and
                    len(link.bond.members)==1 and
                    name in link.bond.members):
                    # Verify this bond is not actually defined, somehow,
                    # in the local config.
                    linkInConfig = False
                    for config_item2 in config:
                        if config_item2.get("id")==link.id:
                            linkInConfig = True
                            break

                    # If this bond is not in local config, update name.
                    if not linkInConfig:
                        name = link.id

            # Check subnets for DHCP configurations.
            dhcpv4Enabled = False
            dhcpv6Enabled = False
            subnets = config_item.get("subnets", [])
            for subnet in subnets:
                subnet_type = subnet.get("type")
                if subnet_type=="dhcp4":
                    dhcpv4Enabled = True
                elif subnet_type=="dhcp6":
                    dhcpv6Enabled = True

            # Fix the network adapter's DHCP config.
            if dhcpv4Enabled:
                LOG.debug('Enabling DHCP4 on %s' % name)
                windows.WindowsUtils._fix_network_adapter_dhcp(name, True, windows.AF_INET)
            else:
                LOG.debug('Disabling DHCP4 on %s' % name)
                windows.WindowsUtils._fix_network_adapter_dhcp(name, False, windows.AF_INET)

            if dhcpv6Enabled:
                LOG.debug('Enabling DHCP6 on %s' % name)
                windows.WindowsUtils._fix_network_adapter_dhcp(name, True, windows.AF_INET6)
            else:
                LOG.debug('Disabling DHCP6 on %s' % name)
                windows.WindowsUtils._fix_network_adapter_dhcp(name, False, windows.AF_INET6)

    def execute(self, service, shared_data):
        reboot_required = False

        # Parse the network config file.
        network_data = self._get_network_data()
        if network_data is None:
            LOG.info('No data parsed.')
            return base.PLUGIN_EXECUTION_DONE, reboot_required

        # We expect the version number to be 1, as per what MaaS uses.
        version = network_data.get("version")
        if version != 1:
            raise exception.CloudbaseInitException(
                'Unsupported local network metadata version: %s' % version)

        # Parse the links and services from the configuration.
        links = []
        networks = []
        services = []
        config = network_data.get("config", [])
        for config_item in config:
            link, link_networks, service = maasservice.MaaSHttpService._parse_config_item(config_item)
            if link:
                links.append(link)
            if link_networks:
                networks.extend(link_networks)
            if service:
                services.append(service)

        # Windows requires a team nic to be created before you can add vlans to an interface.
        # The network config plugin uses bonds to create team nics, so we need to make a virtual
        # bond for every interface that is assigned vlans.
        self._create_bond_for_bondless_vlans(links, networks)

        # Interfaces that are on a bond in MaaS does not have subnets which ends up going disabled.
        # We need to re-enable the interfaces, so that the bond can be created ontop of it.
        maasservice.MaaSHttpService._enable_bond_physical_links(links)

        # Create a network details version 2 model for processing.
        network_details = network_model.NetworkDetailsV2(
            links=links,
            networks=networks,
            services=services
        )

        # Have the network config plugin configure the network.
        networkconfig.NetworkConfigPlugin._process_network_details_v2(network_details)

        # Now that configurations are applied, interfaces have been created and renamed.
        # We need to go back and disable/enable DHCP where needed, according to the configuration file.
        self._configure_interfaces_dhcp(config, links)

        return base.PLUGIN_EXECUTION_DONE, reboot_required
