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
from xml.sax import saxutils


CBT_HARDENING_LEVEL_NONE = "none"
CBT_HARDENING_LEVEL_RELAXED = "relaxed"
CBT_HARDENING_LEVEL_STRICT = "strict"

LISTENER_PROTOCOL_HTTP = "HTTP"
LISTENER_PROTOCOL_HTTPS = "HTTPS"


class WinRMConfig(object):
    _SERVICE_AUTH_URI = 'winrm/Config/Service/Auth'
    _SERVICE_LISTENER_URI = ('winrm/Config/Listener?Address='
                             '%(address)s+Transport=%(protocol)s')
    _SERVICE_CERTMAPPING_URI = ('winrm/Config/Service/certmapping?Issuer='
                                '%(issuer)s+Subject=%(subject)s+Uri=%(uri)s')

    def _get_wsman_session(self):
        wsman = client.Dispatch('WSMan.Automation')
        return wsman.CreateSession()

    def _get_node_tag(self, tag):
        return re.match("^{.*}(.*)$", tag).groups(1)[0]

    def _parse_listener_xml(self, data_xml):
        if not data_xml:
            return None

        listening_on = []
        data = {"ListeningOn": listening_on}

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

    def _parse_cert_mapping_xml(self, data_xml):
        if not data_xml:
            return None

        data = {}

        tree = ElementTree.fromstring(data_xml)
        for node in tree:
            tag = self._get_node_tag(node.tag)
            if tag == "Enabled":
                if node.text == "true":
                    value = True
                else:
                    value = False
                data[tag] = value
            else:
                data[tag] = node.text

        return data

    def _get_xml_bool(self, value):
        if value:
            return "true"
        else:
            return "false"

    def _get_resource(self, resource_uri):
        session = self._get_wsman_session()
        try:
            return session.Get(resource_uri)
        except pywintypes.com_error as ex:
            if len(ex.excepinfo) > 5 and ex.excepinfo[5] == -2144108544:
                return None
            else:
                raise

    def _delete_resource(self, resource_uri):
        session = self._get_wsman_session()
        session.Delete(resource_uri)

    def _create_resource(self, resource_uri, data_xml):
        session = self._get_wsman_session()
        session.Create(resource_uri, data_xml)

    def get_cert_mapping(self, issuer, subject, uri="*"):
        resource_uri = self._SERVICE_CERTMAPPING_URI % {'issuer': issuer,
                                                        'subject': subject,
                                                        'uri': uri}
        return self._parse_cert_mapping_xml(self._get_resource(resource_uri))

    def delete_cert_mapping(self, issuer, subject, uri="*"):
        resource_uri = self._SERVICE_CERTMAPPING_URI % {'issuer': issuer,
                                                        'subject': subject,
                                                        'uri': uri}
        self._delete_resource(resource_uri)

    def create_cert_mapping(self, issuer, subject, username, password,
                            uri="*", enabled=True):
        resource_uri = self._SERVICE_CERTMAPPING_URI % {'issuer': issuer,
                                                        'subject': subject,
                                                        'uri': uri}
        escaped_password = saxutils.escape(password)
        escaped_username = saxutils.escape(username)
        self._create_resource(
            resource_uri,
            '<p:certmapping xmlns:p="http://schemas.microsoft.com/wbem/wsman/'
            '1/config/service/certmapping.xsd">'
            '<p:Enabled>%(enabled)s</p:Enabled>'
            '<p:Password>%(password)s</p:Password>'
            '<p:UserName>%(username)s</p:UserName>'
            '</p:certmapping>' % {'enabled': self._get_xml_bool(enabled),
                                  'username': escaped_username,
                                  'password': escaped_password})

    def get_listener(self, protocol=LISTENER_PROTOCOL_HTTPS, address="*"):
        resource_uri = self._SERVICE_LISTENER_URI % {'protocol': protocol,
                                                     'address': address}
        return self._parse_listener_xml(self._get_resource(resource_uri))

    def delete_listener(self, protocol=LISTENER_PROTOCOL_HTTPS, address="*"):
        resource_uri = self._SERVICE_LISTENER_URI % {'protocol': protocol,
                                                     'address': address}
        self._delete_resource(resource_uri)

    def create_listener(self, protocol=LISTENER_PROTOCOL_HTTPS,
                        cert_thumbprint=None, address="*", enabled=True):
        resource_uri = self._SERVICE_LISTENER_URI % {'protocol': protocol,
                                                     'address': address}
        self._create_resource(
            resource_uri,
            '<p:Listener xmlns:p="http://schemas.microsoft.com/'
            'wbem/wsman/1/config/listener.xsd">'
            '<p:Enabled>%(enabled)s</p:Enabled>'
            '<p:CertificateThumbPrint>%(cert_thumbprint)s'
            '</p:CertificateThumbPrint>'
            '<p:URLPrefix>wsman</p:URLPrefix>'
            '</p:Listener>' % {"enabled": self._get_xml_bool(enabled),
                               "cert_thumbprint": cert_thumbprint or ""})

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
                node = tree.find('.//cfg:%s' % tag, namespaces=ns)

                new_value = self._get_xml_bool(value)
                if node.text.lower() != new_value:
                    node.text = new_value
                    data_xml = ElementTree.tostring(tree)
                    session.Put(self._SERVICE_AUTH_URI, data_xml)
