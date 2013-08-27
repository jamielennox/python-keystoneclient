# vim: tabstop=4 shiftwidth=4 softtabstop=4

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


import httpretty

from keystoneclient.auth.identity import v2 as v2_auth

from tests.v2_0 import utils


class V2AuthTests(utils.TestCase):

    def setUp(self):
        super(V2AuthTests, self).setUp()
        self.TEST_RESPONSE_DICT = {
            "access": {
                "token": {
                    "expires": "2020-01-01T00:00:10.000123Z",
                    "id": self.TEST_TOKEN,
                    "tenant": {
                        "id": self.TEST_TENANT_ID
                    },
                },
                "user": {
                    "id": self.TEST_USER
                },
                "serviceCatalog": self.TEST_SERVICE_CATALOG,
            },
        }
        self.TEST_REQUEST_BODY = {
            "auth": {
                "passwordCredentials": {
                    "username": self.TEST_USER,
                    "password": self.TEST_TOKEN,
                },
                "tenantId": self.TEST_TENANT_ID,
            },
        }

    @httpretty.activate
    def test_auth_password_success(self):
        self.stub_auth(json=self.TEST_RESPONSE_DICT)

        auth = v2_auth.Auth(username=self.TEST_USER,
                            password=self.TEST_TOKEN,
                            tenant_id=self.TEST_TENANT_ID,
                            auth_url=self.TEST_URL)
        auth.authenticate()

        self.assertTrue(auth.is_authenticated)
        self.assertRequestBodyIs(json=self.TEST_REQUEST_BODY)
        self.assertEqual(auth.get_token(), self.TEST_TOKEN)

    @httpretty.activate
    def test_auth_token_success(self):
        del self.TEST_REQUEST_BODY['auth']['passwordCredentials']
        self.TEST_REQUEST_BODY['auth']['token'] = {'id': self.TEST_TOKEN}
        self.stub_auth(json=self.TEST_RESPONSE_DICT)

        auth = v2_auth.Auth(token=self.TEST_TOKEN,
                            tenant_id=self.TEST_TENANT_ID,
                            auth_url=self.TEST_URL)
        auth.authenticate()

        self.assertTrue(auth.is_authenticated)
        self.assertRequestBodyIs(json=self.TEST_REQUEST_BODY)
        self.assertEqual(auth.get_token(), self.TEST_TOKEN)
