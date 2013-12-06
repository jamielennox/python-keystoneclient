# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import copy
import json

import httpretty
from testscenarios import load_tests_apply_scenarios as load_tests  # noqa

from keystoneclient import exceptions
from keystoneclient.tests.v2_0 import client_fixtures
from keystoneclient.tests.v2_0 import utils


class KeystoneClientTest(utils.TestCase):

    @httpretty.activate
    def test_unscoped_init(self):
        self.stub_auth(json=client_fixtures.UNSCOPED_TOKEN)

        c = self.get_client(username='exampleuser',
                            password='password',
                            auth_url=self.TEST_URL)
        auth_ref = self.get_auth_ref(c)
        self.assertIsNotNone(auth_ref)
        self.assertFalse(auth_ref.scoped)
        self.assertFalse(auth_ref.domain_scoped)
        self.assertFalse(auth_ref.project_scoped)
        self.assertIsNone(auth_ref.trust_id)
        self.assertFalse(auth_ref.trust_scoped)

    @httpretty.activate
    def test_scoped_init(self):
        self.stub_auth(json=client_fixtures.PROJECT_SCOPED_TOKEN)

        c = self.get_client(username='exampleuser',
                            password='password',
                            tenant_name='exampleproject',
                            auth_url=self.TEST_URL)
        auth_ref = self.get_auth_ref(c)
        self.assertIsNotNone(auth_ref)
        self.assertTrue(auth_ref.scoped)
        self.assertTrue(auth_ref.project_scoped)
        self.assertFalse(auth_ref.domain_scoped)
        self.assertIsNone(auth_ref.trust_id)
        self.assertFalse(auth_ref.trust_scoped)

    @httpretty.activate
    def test_auth_ref_load(self):
        self.skipIfSession("Auth Ref loading not supported by auth plugins")
        self.stub_auth(json=client_fixtures.PROJECT_SCOPED_TOKEN)

        cl = self.get_client(username='exampleuser',
                             password='password',
                             tenant_name='exampleproject',
                             auth_url=self.TEST_URL)
        cache = json.dumps(cl.auth_ref)
        new_client = self.get_client(auth_ref=json.loads(cache))
        self.assertIsNotNone(new_client.auth_ref)
        self.assertTrue(new_client.auth_ref.scoped)
        self.assertTrue(new_client.auth_ref.project_scoped)
        self.assertFalse(new_client.auth_ref.domain_scoped)
        self.assertIsNone(new_client.auth_ref.trust_id)
        self.assertFalse(new_client.auth_ref.trust_scoped)
        self.assertEqual(new_client.username, 'exampleuser')
        self.assertIsNone(new_client.password)
        self.assertEqual(new_client.management_url,
                         'http://admin:35357/v2.0')

    @httpretty.activate
    def test_auth_ref_load_with_overridden_arguments(self):
        self.skipIfSession("Auth Ref loading not supported by auth plugins")
        self.stub_auth(json=client_fixtures.PROJECT_SCOPED_TOKEN)

        cl = self.get_client(username='exampleuser',
                             password='password',
                             tenant_name='exampleproject',
                             auth_url=self.TEST_URL)
        cache = json.dumps(cl.auth_ref)
        new_auth_url = "http://new-public:5000/v2.0"
        new_client = self.get_client(auth_ref=json.loads(cache),
                                     auth_url=new_auth_url)
        self.assertIsNotNone(new_client.auth_ref)
        self.assertTrue(new_client.auth_ref.scoped)
        self.assertTrue(new_client.auth_ref.scoped)
        self.assertTrue(new_client.auth_ref.project_scoped)
        self.assertFalse(new_client.auth_ref.domain_scoped)
        self.assertIsNone(new_client.auth_ref.trust_id)
        self.assertFalse(new_client.auth_ref.trust_scoped)
        self.assertEqual(new_client.auth_url, new_auth_url)
        self.assertEqual(new_client.username, 'exampleuser')
        self.assertIsNone(new_client.password)
        self.assertEqual(new_client.management_url,
                         'http://admin:35357/v2.0')

    def test_init_err_no_auth_url(self):
        self.assertRaises(exceptions.AuthorizationFailure,
                          self.get_client,
                          username='exampleuser',
                          password='password')

    @httpretty.activate
    def test_management_url_is_updated(self):
        second = copy.deepcopy(client_fixtures.PROJECT_SCOPED_TOKEN)
        first_url = 'http://admin:35357/v2.0'
        second_url = "http://secondurl:%d/v2.0'"

        for entry in second['access']['serviceCatalog']:
            if entry['type'] == 'identity':
                entry['endpoints'] = [{'adminURL': second_url % 35357,
                                       'internalURL': second_url % 5000,
                                       'publicURL': second_url % 6000,
                                       'region': 'RegionOne'}]

        self.stub_auth(json=client_fixtures.PROJECT_SCOPED_TOKEN)
        cl = self.get_client(username='exampleuser',
                             password='password',
                             tenant_name='exampleproject',
                             auth_url=self.TEST_URL)

        self.assertEqual(self.get_management_url(cl), first_url)

        self.stub_auth(json=second)
        cl.authenticate()

        self.assertEqual(self.get_management_url(cl), second_url % 35357)
