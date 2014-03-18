# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import uuid

from keystoneclient import access
from keystoneclient.auth.identity.generic import password
from keystoneclient.auth.identity import v2
from keystoneclient.auth.identity import v3
from keystoneclient import exceptions
from keystoneclient import fixture
from keystoneclient import session
from keystoneclient.tests.auth import utils


class PasswordTests(utils.TestCase):

    TEST_URL = 'http://keystone.host:5000/'

    def setUp(self):
        super(PasswordTests, self).setUp()

        self.token_v2 = fixture.V2Token()
        self.token_v3 = fixture.V3Token()
        self.token_v3_id = uuid.uuid4().hex
        self.session = session.Session()
        self.kwargs = {'username': uuid.uuid4().hex,
                       'password': uuid.uuid4().hex}

        self.stub_url('POST', ['v2.0', 'tokens'], json=self.token_v2)
        self.stub_url('POST', ['v3', 'auth', 'tokens'],
                      headers={'X-Subject-Token': self.token_v3_id},
                      json=self.token_v3)

    def new_plugin(self, **kwargs):
        kwargs.setdefault('auth_url', self.TEST_URL)
        return password.Password(**kwargs)

    def stub_discovery(self, base_url=None, **kwargs):
        kwargs.setdefault('href', self.TEST_URL)
        disc = fixture.DiscoveryList(**kwargs)
        self.stub_url('GET', json=disc, base_url=base_url, status_code=300)

    def assertCreateV3(self, **kwargs):
        auth = self.new_plugin(**kwargs)
        auth_ref = auth.get_auth_ref(self.session)
        self.assertIsInstance(auth_ref, access.AccessInfoV3)
        self.assertEqual(self.TEST_URL + 'v3/auth/tokens',
                         self.requests.last_request.url)
        self.assertIsInstance(auth._plugin, v3.Password)
        return auth

    def assertCreateV2(self, **kwargs):
        auth = self.new_plugin(**kwargs)
        auth_ref = auth.get_auth_ref(self.session)
        self.assertIsInstance(auth_ref, access.AccessInfoV2)
        self.assertEqual(self.TEST_URL + 'v2.0/tokens',
                         self.requests.last_request.url)
        self.assertIsInstance(auth._plugin, v2.Password)
        return auth

    def assertDiscoveryFailure(self, **kwargs):
        plugin = self.new_plugin(**kwargs)
        self.assertRaises(exceptions.DiscoveryFailure,
                          plugin.get_auth_ref,
                          self.session)

    def test_create_v3_if_domain_params(self):
        self.stub_discovery()

        self.assertCreateV3(domain_id=uuid.uuid4().hex, **self.kwargs)
        self.assertCreateV3(domain_name=uuid.uuid4().hex, **self.kwargs)
        self.assertCreateV3(project_name=uuid.uuid4().hex,
                            project_domain_name=uuid.uuid4().hex,
                            **self.kwargs)
        self.assertCreateV3(project_name=uuid.uuid4().hex,
                            project_domain_id=uuid.uuid4().hex,
                            **self.kwargs)

    def test_create_v2_if_no_domain_params(self):
        self.stub_discovery()
        self.assertCreateV2(**self.kwargs)
        self.assertCreateV2(project_id=uuid.uuid4().hex, **self.kwargs)
        self.assertCreateV2(project_name=uuid.uuid4().hex, **self.kwargs)
        self.assertCreateV2(tenant_id=uuid.uuid4().hex, **self.kwargs)
        self.assertCreateV2(tenant_name=uuid.uuid4().hex, **self.kwargs)

    def test_v3_params_v2_url(self):
        self.stub_discovery(v3=False)
        self.assertDiscoveryFailure(domain_name=uuid.uuid4().hex,
                                    **self.kwargs)

    def test_v2_params_v3_url(self):
        self.stub_discovery(v2=False)
        self.assertCreateV3(**self.kwargs)

    def test_no_urls(self):
        self.stub_discovery(v2=False, v3=False)
        self.assertDiscoveryFailure(**self.kwargs)

    def test_path_based_url_v2(self):
        self.stub_url('GET', ['v2.0'], status_code=403)
        self.assertCreateV2(auth_url=self.TEST_URL + 'v2.0')

    def test_path_based_url_v3(self):
        self.stub_url('GET', ['v3'], status_code=403)
        self.assertCreateV3(auth_url=self.TEST_URL + 'v3')

    def test_disc_error_for_failure(self):
        self.stub_url('GET', [], status_code=403)
        new_plugin = self.new_plugin(username='test', password='test')
        self.assertRaises(exceptions.DiscoveryFailure,
                          new_plugin.get_auth_ref,
                          self.session)

    def test_v3_plugin_from_failure(self):
        url = self.TEST_URL + 'v3'
        self.stub_url('GET', [], base_url=url, status_code=403)
        self.assertCreateV3(auth_url=url)
