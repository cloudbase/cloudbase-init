# Copyright 2013 Cloudbase Solutions Srl
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

import importlib
import unittest
from xml.sax import saxutils

try:
    import unittest.mock as mock
except ImportError:
    import mock

from cloudbaseinit import exception
from cloudbaseinit.tests import fake


class WinRMConfigTests(unittest.TestCase):

    def setUp(self):
        self._pywintypes_mock = mock.MagicMock()
        self._pywintypes_mock.com_error = fake.FakeComError
        self._win32com_mock = mock.MagicMock()
        self._module_patcher = mock.patch.dict(
            'sys.modules',
            {'win32com': self._win32com_mock,
             'pywintypes': self._pywintypes_mock})

        self._module_patcher.start()

        winrmconfig = importlib.import_module(
            "cloudbaseinit.utils.windows.winrmconfig")
        self._winrmconfig = winrmconfig.WinRMConfig()

    def tearDown(self):
        self._module_patcher.stop()

    def test_get_wsman_session(self):
        mock_wsman = mock.MagicMock()
        self._win32com_mock.client.Dispatch.return_value = mock_wsman

        response = self._winrmconfig._get_wsman_session()

        self._win32com_mock.client.Dispatch.assert_called_once_with(
            'WSMan.Automation')
        mock_wsman.CreateSession.assert_called_once_with()
        self.assertEqual(mock_wsman.CreateSession.return_value, response)

    @mock.patch('re.match')
    def test_get_node_tag(self, mock_match):
        mock_tag = mock.MagicMock()

        response = self._winrmconfig._get_node_tag(mock_tag)

        mock_match.assert_called_once_with("^{.*}(.*)$", mock_tag)
        self.assertEqual(mock_match().groups().__getitem__(), response)

    @mock.patch('xml.etree.ElementTree.fromstring')
    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_get_node_tag')
    def _test_parse_listener_xml(self, mock_get_node_tag, mock_fromstring,
                                 data_xml, tag=None, text='Fake'):
        mock_node = mock.MagicMock()
        mock_node.tag = tag
        mock_node.text = text
        fake_tree = [mock_node]
        mock_get_node_tag.return_value = tag
        mock_fromstring.return_value = fake_tree

        response = self._winrmconfig._parse_listener_xml(data_xml=data_xml)

        if data_xml is None:
            self.assertEqual(None, response)
        else:
            mock_fromstring.assert_called_once_with(data_xml)
            mock_get_node_tag.assert_called_once_with(tag)
            if tag is "ListeningOn":
                self.assertEqual({'ListeningOn': ['Fake']}, response)
            elif tag is "Enabled":
                if text is 'true':
                    self.assertEqual({'ListeningOn': [],
                                      'Enabled': True}, response)
                else:
                    self.assertEqual({'ListeningOn': [],
                                      'Enabled': False}, response)
            elif tag is 'Port':
                self.assertEqual({'ListeningOn': [],
                                  'Port': int(text)}, response)
            else:
                self.assertEqual({'ListeningOn': [],
                                  tag: text}, response)

    def test_parse_listener_xml_no_data(self):
        self._test_parse_listener_xml(data_xml=None)

    def test_parse_listener_xml_listening_on(self):
        self._test_parse_listener_xml(data_xml='fake data', tag="ListeningOn")

    def test_parse_listener_xml_enabled_true(self):
        self._test_parse_listener_xml(data_xml='fake data',
                                      tag="Enabled", text='true')

    def test_parse_listener_xml_enabled_false(self):
        self._test_parse_listener_xml(data_xml='fake data', tag='Enabled',
                                      text='false')

    def test_parse_listener_xml_port(self):
        self._test_parse_listener_xml(data_xml='fake data', tag='Port',
                                      text='9999')

    def test_parse_listener_xml_other_tag(self):
        self._test_parse_listener_xml(data_xml='fake data', tag='fake tag',
                                      text='fake text')

    @mock.patch('xml.etree.ElementTree.fromstring')
    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig'
                '._get_node_tag')
    def _test_parse_cert_mapping_xml(self, mock_get_node_tag,
                                     mock_fromstring, data_xml, tag=None,
                                     text='Fake'):
        mock_node = mock.MagicMock()
        mock_node.tag = tag
        mock_node.text = text
        fake_tree = [mock_node]
        mock_get_node_tag.return_value = tag
        mock_fromstring.return_value = fake_tree

        response = self._winrmconfig._parse_cert_mapping_xml(data_xml=data_xml)

        if data_xml is None:
            self.assertEqual(response, None)
        else:
            mock_fromstring.assert_called_once_with(data_xml)
            mock_get_node_tag.assert_called_once_with(tag)
            if tag is "Enabled":
                if text is 'true':
                    self.assertEqual({'Enabled': True}, response)
                else:
                    self.assertEqual({'Enabled': False}, response)
            else:
                self.assertEqual({tag: text}, response)

    def test_parse_cert_mapping_xml_no_data(self):
        self._test_parse_cert_mapping_xml(data_xml=None)

    def test_parse_cert_mapping_xml_enabled_true(self):
        self._test_parse_listener_xml(data_xml='fake data',
                                      tag="Enabled", text='true')

    def test_parse_cert_mapping_xml_enabled_false(self):
        self._test_parse_listener_xml(data_xml='fake data', tag='Enabled',
                                      text='false')

    def test_parse_cert_mapping_xml_other_tag(self):
        self._test_parse_listener_xml(data_xml='fake data', tag='fake tag',
                                      text='fake text')

    def _test_get_xml_bool(self, value):
        response = self._winrmconfig._get_xml_bool(value)
        if value:
            self.assertEqual('true', response)
        else:
            self.assertEqual('false', response)

    def test_get_xml_bool_true(self):
        self._test_get_xml_bool(value='fake value')

    def test_get_xml_bool_false(self):
        self._test_get_xml_bool(value=None)

    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_get_wsman_session')
    def _test_get_resource(self, mock_get_wsman_session, resource):
        fake_session = mock.MagicMock()
        fake_uri = 'fake:\\uri'
        fake_session.Get.side_effect = [resource]
        mock_get_wsman_session.return_value = fake_session

        if resource is exception.CloudbaseInitException:
            self.assertRaises(exception.CloudbaseInitException,
                              self._winrmconfig._get_resource,
                              fake_uri)
        else:
            response = self._winrmconfig._get_resource(fake_uri)

            mock_get_wsman_session.assert_called_once_with()
            fake_session.Get.assert_called_once_with(fake_uri)
            self.assertEqual(resource, response)

    def test_get_resource(self):
        self._test_get_resource(resource='fake resource')

    def test_get_resource_exception(self):
        self._test_get_resource(resource=exception.CloudbaseInitException)

    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_get_wsman_session')
    def test_delete_resource(self, mock_get_wsman_session):
        fake_session = mock.MagicMock()
        fake_uri = 'fake:\\uri'
        mock_get_wsman_session.return_value = fake_session

        self._winrmconfig._delete_resource(fake_uri)

        fake_session.Delete.assert_called_once_with(fake_uri)

    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_get_wsman_session')
    def test_create_resource(self, mock_get_wsman_session):
        fake_session = mock.MagicMock()
        fake_uri = 'fake:\\uri'
        mock_get_wsman_session.return_value = fake_session

        self._winrmconfig._create_resource(fake_uri, 'fake data')

        fake_session.Create.assert_called_once_with(fake_uri, 'fake data')

    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_parse_cert_mapping_xml')
    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_get_resource')
    def test_get_cert_mapping(self, mock_get_resource,
                              mock_parse_cert_mapping_xml):
        fake_dict = {'issuer': 'issuer',
                     'subject': 'subject',
                     'uri': 'fake:\\uri'}
        mock_parse_cert_mapping_xml.return_value = 'fake response'
        mock_get_resource.return_value = 'fake resource'

        response = self._winrmconfig.get_cert_mapping('issuer', 'subject',
                                                      uri='fake:\\uri')

        mock_parse_cert_mapping_xml.assert_called_with('fake resource')
        mock_get_resource.assert_called_with(
            self._winrmconfig._SERVICE_CERTMAPPING_URI % fake_dict)
        self.assertEqual('fake response', response)

    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_delete_resource')
    def test_delete_cert_mapping(self, mock_delete_resource):
        fake_dict = {'issuer': 'issuer',
                     'subject': 'subject',
                     'uri': 'fake:\\uri'}

        self._winrmconfig.delete_cert_mapping('issuer', 'subject',
                                              uri='fake:\\uri')

        mock_delete_resource.assert_called_with(
            self._winrmconfig._SERVICE_CERTMAPPING_URI % fake_dict)

    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_get_xml_bool')
    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_create_resource')
    def test_create_cert_mapping(self, mock_create_resource,
                                 mock_get_xml_bool):
        fake_dict = {'issuer': 'issuer',
                     'subject': 'subject',
                     'uri': 'fake:\\uri'}
        mock_get_xml_bool.return_value = True
        fake_password = "Pa&ssw0rd!"
        fake_username = 'fake user'
        expected_password = saxutils.escape(fake_password)
        expected_username = saxutils.escape(fake_username)

        self._winrmconfig.create_cert_mapping(
            issuer='issuer', subject='subject', username=fake_username,
            password=fake_password, uri='fake:\\uri', enabled=True)

        mock_get_xml_bool.assert_called_once_with(True)
        mock_create_resource.assert_called_once_with(
            self._winrmconfig._SERVICE_CERTMAPPING_URI % fake_dict,
            '<p:certmapping xmlns:p="http://schemas.microsoft.com/wbem/wsman/'
            '1/config/service/certmapping.xsd">'
            '<p:Enabled>%(enabled)s</p:Enabled>'
            '<p:Password>%(password)s</p:Password>'
            '<p:UserName>%(username)s</p:UserName>'
            '</p:certmapping>' % {'enabled': True,
                                  'username': expected_username,
                                  'password': expected_password})

    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_get_resource')
    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_parse_listener_xml')
    def test_get_listener(self, mock_parse_listener_xml, mock_get_resource):
        dict = {'protocol': 'HTTPS',
                'address': 'fake:\\address'}
        mock_get_resource.return_value = 'fake resource'
        mock_parse_listener_xml.return_value = 'fake response'

        response = self._winrmconfig.get_listener(protocol='HTTPS',
                                                  address="fake:\\address")

        mock_get_resource.assert_called_with(
            self._winrmconfig._SERVICE_LISTENER_URI % dict)
        mock_parse_listener_xml.assert_called_once_with('fake resource')
        self.assertEqual('fake response', response)

    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_delete_resource')
    def test_delete_listener(self, mock_delete_resource):
        dict = {'protocol': 'HTTPS',
                'address': 'fake:\\address'}

        self._winrmconfig.delete_listener(protocol='HTTPS',
                                          address="fake:\\address")

        mock_delete_resource.assert_called_with(
            self._winrmconfig._SERVICE_LISTENER_URI % dict)

    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_create_resource')
    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_get_xml_bool')
    def test_create_listener(self, mock_get_xml_bool, mock_create_resource):
        dict = {'protocol': 'HTTPS',
                'address': 'fake:\\address'}
        mock_get_xml_bool.return_value = True

        self._winrmconfig.create_listener(protocol='HTTPS',
                                          cert_thumbprint=None,
                                          address="fake:\\address",
                                          enabled=True)

        mock_create_resource.assert_called_once_with(
            self._winrmconfig._SERVICE_LISTENER_URI % dict,
            '<p:Listener xmlns:p="http://schemas.microsoft.com/'
            'wbem/wsman/1/config/listener.xsd">'
            '<p:Enabled>%(enabled)s</p:Enabled>'
            '<p:CertificateThumbPrint>%(cert_thumbprint)s'
            '</p:CertificateThumbPrint>'
            '<p:URLPrefix>wsman</p:URLPrefix>'
            '</p:Listener>' % {"enabled": True,
                               "cert_thumbprint": None})

    @mock.patch('xml.etree.ElementTree.fromstring')
    @mock.patch('xml.etree.ElementTree.tostring')
    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_get_wsman_session')
    @mock.patch('cloudbaseinit.utils.windows.winrmconfig.WinRMConfig.'
                '_get_xml_bool')
    def test_set_auth_config(self, mock_get_xml_bool, mock_get_wsman_session,
                             mock_tostring, mock_fromstring):
        mock_session = mock.MagicMock()
        mock_tree = mock.MagicMock()
        mock_node = mock.MagicMock()
        url = 'http://schemas.microsoft.com/wbem/wsman/1/config/service/auth'

        expected_find = [
            mock.call('.//cfg:Certificate', namespaces={'cfg': url}),
            mock.call('.//cfg:Kerberos', namespaces={'cfg': url}),
            mock.call('.//cfg:CbtHardeningLevel', namespaces={'cfg': url}),
            mock.call('.//cfg:Negotiate', namespaces={'cfg': url}),
            mock.call('.//cfg:CredSSP', namespaces={'cfg': url}),
            mock.call('.//cfg:Basic', namespaces={'cfg': url})]

        expected_get_xml_bool = [mock.call('certificate'),
                                 mock.call('kerberos'),
                                 mock.call('cbt_hardening_level'),
                                 mock.call('negotiate'),
                                 mock.call('credSSP'),
                                 mock.call('basic')]

        mock_get_wsman_session.return_value = mock_session
        mock_session.Get.return_value = 'fake xml'
        mock_fromstring.return_value = mock_tree
        mock_get_xml_bool.return_value = 'true'
        mock_tostring.return_value = 'fake xml'
        mock_tree.find.return_value = mock_node
        mock_node.text.lower.return_value = 'old value'

        self._winrmconfig.set_auth_config(
            basic='basic', kerberos='kerberos', negotiate='negotiate',
            certificate='certificate', credSSP='credSSP',
            cbt_hardening_level='cbt_hardening_level')

        self.assertEqual(sorted(expected_find),
                         sorted(mock_tree.find.call_args_list))
        self.assertEqual(sorted(expected_get_xml_bool),
                         sorted(mock_get_xml_bool.call_args_list))

        mock_get_wsman_session.assert_called_once_with()
        mock_session.Get.assert_called_with(
            self._winrmconfig._SERVICE_AUTH_URI)
        mock_fromstring.assert_called_once_with('fake xml')
        mock_session.Put.assert_called_with(
            self._winrmconfig._SERVICE_AUTH_URI, 'fake xml')
