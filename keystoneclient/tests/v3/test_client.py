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
from keystoneclient.tests.v3 import client_fixtures
from keystoneclient.tests.v3 import utils


class KeystoneClientTest(utils.TestCase):

    @httpretty.activate
    def test_unscoped_init(self):
        self.stub_auth(json=client_fixtures.UNSCOPED_TOKEN)

        c = self.get_client(user_domain_name='exampledomain',
                            username='exampleuser',
                            password='password',
                            auth_url=self.TEST_URL)
        auth_ref = self.get_auth_ref(c)
        self.assertIsNotNone(auth_ref)
        self.assertFalse(auth_ref.domain_scoped)
        self.assertFalse(auth_ref.project_scoped)
        self.assertEqual(auth_ref.user_id,
                         'c4da488862bd435c9e6c0275a0d0e49a')

        if not self.isSession:
            self.assertEqual(c.auth_user_id,
                             'c4da488862bd435c9e6c0275a0d0e49a')

    @httpretty.activate
    def test_domain_scoped_init(self):
        self.stub_auth(json=client_fixtures.DOMAIN_SCOPED_TOKEN)

        c = self.get_client(user_id='c4da488862bd435c9e6c0275a0d0e49a',
                            password='password',
                            domain_name='exampledomain',
                            auth_url=self.TEST_URL)
        auth_ref = self.get_auth_ref(c)
        self.assertIsNotNone(auth_ref)
        self.assertTrue(auth_ref.domain_scoped)
        self.assertFalse(auth_ref.project_scoped)

        self.assertEqual(auth_ref.user_id,
                         'c4da488862bd435c9e6c0275a0d0e49a')
        self.assertEqual(auth_ref.domain_id,
                         '8e9283b7ba0b1038840c3842058b86ab')

        if not self.isSession:
            self.assertEqual(c.auth_user_id,
                             'c4da488862bd435c9e6c0275a0d0e49a')
            self.assertEqual(c.auth_domain_id,
                             '8e9283b7ba0b1038840c3842058b86ab')

    @httpretty.activate
    def test_project_scoped_init(self):
        self.stub_auth(json=client_fixtures.PROJECT_SCOPED_TOKEN),

        c = self.get_client(user_id='c4da488862bd435c9e6c0275a0d0e49a',
                            password='password',
                            user_domain_name='exampledomain',
                            project_name='exampleproject',
                            auth_url=self.TEST_URL)
        auth_ref = self.get_auth_ref(c)
        self.assertIsNotNone(auth_ref)
        self.assertFalse(auth_ref.domain_scoped)
        self.assertTrue(auth_ref.project_scoped)

        self.assertEqual(auth_ref.user_id,
                         'c4da488862bd435c9e6c0275a0d0e49a')
        self.assertEqual(auth_ref.tenant_id,
                         '225da22d3ce34b15877ea70b2a575f58')

        if not self.isSession:
            self.assertEqual(c.auth_user_id,
                             'c4da488862bd435c9e6c0275a0d0e49a')
            self.assertEqual(c.auth_tenant_id,
                             '225da22d3ce34b15877ea70b2a575f58')

    @httpretty.activate
    def test_auth_ref_load(self):
        self.skipIfSession("Auth Ref loading not supported by auth plugins")

        self.stub_auth(json=client_fixtures.PROJECT_SCOPED_TOKEN)

        c = self.get_client(user_id='c4da488862bd435c9e6c0275a0d0e49a',
                            password='password',
                            project_id='225da22d3ce34b15877ea70b2a575f58',
                            auth_url=self.TEST_URL)
        cache = json.dumps(c.auth_ref)
        new_client = self.get_client(auth_ref=json.loads(cache))
        self.assertIsNotNone(new_client.auth_ref)
        self.assertFalse(new_client.auth_ref.domain_scoped)
        self.assertTrue(new_client.auth_ref.project_scoped)
        self.assertEqual(new_client.username, 'exampleuser')
        self.assertIsNone(new_client.password)
        self.assertEqual(new_client.management_url,
                         'http://admin:35357/v3')

    @httpretty.activate
    def test_auth_ref_load_with_overridden_arguments(self):
        self.skipIfSession("Auth Ref loading not supported by auth plugins")

        new_auth_url = 'https://newkeystone.com/v3'

        self.stub_auth(json=client_fixtures.PROJECT_SCOPED_TOKEN)
        self.stub_auth(json=client_fixtures.PROJECT_SCOPED_TOKEN,
                       base_url=new_auth_url)

        c = self.get_client(user_id='c4da488862bd435c9e6c0275a0d0e49a',
                            password='password',
                            project_id='225da22d3ce34b15877ea70b2a575f58',
                            auth_url=self.TEST_URL)
        cache = json.dumps(c.auth_ref)
        new_client = self.get_client(auth_ref=json.loads(cache),
                                     auth_url=new_auth_url)
        self.assertIsNotNone(new_client.auth_ref)
        self.assertFalse(new_client.auth_ref.domain_scoped)
        self.assertTrue(new_client.auth_ref.project_scoped)
        self.assertEqual(new_client.auth_url, new_auth_url)
        self.assertEqual(new_client.username, 'exampleuser')
        self.assertIsNone(new_client.password)
        self.assertEqual(new_client.management_url,
                         'http://admin:35357/v3')

    @httpretty.activate
    def test_trust_init(self):
        self.stub_auth(json=client_fixtures.TRUST_TOKEN)

        c = self.get_client(user_domain_name='exampledomain',
                            username='exampleuser',
                            password='password',
                            auth_url=self.TEST_URL,
                            trust_id='fe0aef')
        auth_ref = self.get_auth_ref(c)
        self.assertIsNotNone(auth_ref)
        self.assertFalse(auth_ref.domain_scoped)
        self.assertFalse(auth_ref.project_scoped)
        self.assertEqual(auth_ref.trust_id, 'fe0aef')
        self.assertTrue(auth_ref.trust_scoped)
        self.assertEqual(auth_ref.user_id, '0ca8f6')

        if not self.isSession:
            self.assertEqual(c.auth_user_id, '0ca8f6')

    def test_init_err_no_auth_url(self):
        self.assertRaises(exceptions.AuthorizationFailure,
                          self.get_client,
                          username='exampleuser',
                          password='password')

    @httpretty.activate
    def test_management_url_is_updated(self):
        second = copy.deepcopy(client_fixtures.PROJECT_SCOPED_TOKEN)
        first_url = 'http://admin:35357/v3'
        second_url = "http://secondurl:%d/v3'"

        for entry in second['token']['catalog']:
            if entry['type'] == 'identity':
                entry['endpoints'] = [{
                    'url': second_url % 5000,
                    'region': 'RegionOne',
                    'interface': 'public'
                }, {
                    'url': second_url % 5000,
                    'region': 'RegionOne',
                    'interface': 'internal'
                }, {
                    'url': second_url % 35357,
                    'region': 'RegionOne',
                    'interface': 'admin'
                }]

        self.stub_auth(json=client_fixtures.PROJECT_SCOPED_TOKEN)
        cl = self.get_client(username='exampleuser',
                             password='password',
                             project_name='exampleproject',
                             auth_url=self.TEST_URL)

        self.assertEqual(self.get_management_url(cl), first_url)

        self.stub_auth(json=second)
        cl.authenticate()

        self.assertEqual(self.get_management_url(cl), second_url % 35357)
