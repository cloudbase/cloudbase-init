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

import pywintypes
import re

from win32com import client
from xml.etree import ElementTree


CBT_HARDENING_LEVEL_NONE = "none"
CBT_HARDENING_LEVEL_RELAXED = "relaxed"
CBT_HARDENING_LEVEL_STRICT = "strict"

LISTENER_PROTOCOL_HTTP = "HTTP"
LISTENER_PROTOCOL_HTTPS = "HTTPS"


class WinRMConfig(object):
    _SERVICE_AUTH_URI = 'winrm/Config/Service/Auth'
    _SERVICE_LISTENER_URI = 'winrm/Config/Listener?Address=*+Transport=%s'

    def _get_wsman_session(self):
        wsman = client.Dispatch('WSMan.Automation')
        return wsman.CreateSession()

    def _get_node_tag(self, tag):
        return re.match("^{.*}(.*)$", tag).groups(1)[0]

    def _parse_listener_xml(self, data_xml):
        listening_on = []
        data = {"ListeningOn": listening_on}

        ns = {'cfg':
              'http://schemas.microsoft.com/wbem/wsman/1/config/listener'}
        tree = ElementTree.fromstring(data_xml)
        for node in tree:
            tag = self._get_node_tag(node.tag)
            if tag == "ListeningOn":
                listening_on.append(node.text)
            elif tag == "Enabled":
                if node.text == "true":
                    value = True
                else:
                    value = False
                data[tag] = value
            elif tag == "Port":
                data[tag] = int(node.text)
            else:
                data[tag] = node.text

        return data

    def get_listener(self, protocol=LISTENER_PROTOCOL_HTTPS):
        session = self._get_wsman_session()
        resourceUri = self._SERVICE_LISTENER_URI % protocol
        try:
            data_xml = session.Get(resourceUri)
        except pywintypes.com_error, ex:
            if len(ex.excepinfo) > 5 and ex.excepinfo[5] == -2144108544:
                return None
            else:
                raise

        return self._parse_listener_xml(data_xml)

    def delete_listener(self, protocol=LISTENER_PROTOCOL_HTTPS):
        session = self._get_wsman_session()
        resourceUri = self._SERVICE_LISTENER_URI % protocol
        session.Delete(resourceUri)

    def create_listener(self, protocol=LISTENER_PROTOCOL_HTTPS, enabled=True,
                        cert_thumbprint=None):
        session = self._get_wsman_session()
        resource_uri = self._SERVICE_LISTENER_URI % protocol

        if enabled:
            enabled_str = "true"
        else:
            enabled_str = "false"

        session.Create(
            resource_uri,
            '<p:Listener xmlns:p="http://schemas.microsoft.com/'
            'wbem/wsman/1/config/listener.xsd">'
            '<p:Enabled>%(enabled_str)s</p:Enabled>'
            '<p:CertificateThumbPrint>%(cert_thumbprint)s'
            '</p:CertificateThumbPrint>'
            '<p:URLPrefix>wsman</p:URLPrefix>'
            '</p:Listener>' % {"enabled_str": enabled_str,
                               "cert_thumbprint": cert_thumbprint})

    def get_auth_config(self):
        data = {}

        session = self._get_wsman_session()
        data_xml = session.Get(self._SERVICE_AUTH_URI)
        tree = ElementTree.fromstring(data_xml)
        for node in tree:
            tag = self._get_node_tag(node.tag)
            value_str = node.text.lower()
            if value_str == "true":
                value = True
            elif value_str == "false":
                value = False
            else:
                value = value_str
            data[tag] = value

        return data

    def set_auth_config(self, basic=None, kerberos=None, negotiate=None,
                        certificate=None, credSSP=None,
                        cbt_hardening_level=None):

        tag_map = {'Basic': basic,
                   'Kerberos': kerberos,
                   'Negotiate': negotiate,
                   'Certificate': certificate,
                   'CredSSP': credSSP,
                   'CbtHardeningLevel': cbt_hardening_level}

        session = self._get_wsman_session()
        data_xml = session.Get(self._SERVICE_AUTH_URI)

        ns = {'cfg':
              'http://schemas.microsoft.com/wbem/wsman/1/config/service/auth'}
        tree = ElementTree.fromstring(data_xml)

        for (tag, value) in tag_map.items():
            if value is not None:
                if value:
                    new_value = "true"
                else:
                    new_value = "false"

                node = tree.find('.//cfg:%s' % tag, namespaces=ns)

                if node.text.lower() != new_value:
                    node.text = new_value
                    data_xml = ElementTree.tostring(tree)
                    session.Put(self._SERVICE_AUTH_URI, data_xml)
