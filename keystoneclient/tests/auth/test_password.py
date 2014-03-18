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

import httpretty

from keystoneclient.auth.identity import password
from keystoneclient.auth.identity import v2
from keystoneclient.auth.identity import v3
from keystoneclient import exceptions
from keystoneclient import fixture
from keystoneclient.tests.auth import utils


class PasswordTests(utils.TestCase):

    TEST_URL = 'http://keystone.host:5000/'

    def setUp(self):
        super(PasswordTests, self).setUp()

        self.token_v2 = fixture.V2Token()
        self.token_v3 = fixture.V3Token()
        self.token_v3_id = uuid.uuid4().hex

        self.stub_url(httpretty.POST, ['v2.0', 'tokens'], json=self.token_v2)
        self.stub_url(httpretty.POST, ['v3', 'auth', 'tokens'],
                      X_Subject_Token=self.token_v3_id, json=self.token_v3)

    def new_plugin(self, **kwargs):
        kwargs.setdefault('auth_url', self.TEST_URL)
        return password.Password(**kwargs)

    def stub_discovery(self, **kwargs):
        kwargs.setdefault('href', self.TEST_URL)
        disc = fixture.DiscoveryList(**kwargs)
        self.stub_url(httpretty.GET, json=disc, status_code=300)

    def assertCreateV3(self, **kwargs):
        auth = self.new_plugin(**kwargs)
        self.assertIsInstance(auth._plugin, v3.Password)
        return auth

    def assertCreateV2(self, **kwargs):
        auth = self.new_plugin(**kwargs)
        self.assertIsInstance(auth._plugin, v2.Password)
        return auth

    def test_create_v3_if_domain_params(self):
        self.stub_discovery()
        self.assertCreateV3(username=uuid.uuid4().hex,
                            password=uuid.uuid4().hex,
                            domain_name=uuid.uuid4().hex)
