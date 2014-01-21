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

from keystoneclient.auth.identity import v2
from keystoneclient import exceptions
from keystoneclient import session
from keystoneclient.tests import utils


class V2IdentityPlugin(utils.TestCase):

    TEST_ROOT_URL = 'http://127.0.0.1:5000/'
    TEST_URL = '%s%s' % (TEST_ROOT_URL, 'v2.0')
    TEST_ROOT_ADMIN_URL = 'http://127.0.0.1:35357/'
    TEST_ADMIN_URL = '%s%s' % (TEST_ROOT_ADMIN_URL, 'v2.0')

    TEST_PASS = 'password'

    TEST_SERVICE_CATALOG = [{
        "endpoints": [{
            "adminURL": "http://cdn.admin-nets.local:8774/v1.0",
            "region": "RegionOne",
            "internalURL": "http://127.0.0.1:8774/v1.0",
            "publicURL": "http://cdn.admin-nets.local:8774/v1.0/"
        }],
        "type": "nova_compat",
        "name": "nova_compat"
    }, {
        "endpoints": [{
            "adminURL": "http://nova/novapi/admin",
            "region": "RegionOne",
            "internalURL": "http://nova/novapi/internal",
            "publicURL": "http://nova/novapi/public"
        }],
        "type": "compute",
        "name": "nova"
    }, {
        "endpoints": [{
            "adminURL": "http://glance/glanceapi/admin",
            "region": "RegionOne",
            "internalURL": "http://glance/glanceapi/internal",
            "publicURL": "http://glance/glanceapi/public"
        }],
        "type": "image",
        "name": "glance"
    }, {
        "endpoints": [{
            "adminURL": TEST_ADMIN_URL,
            "region": "RegionOne",
            "internalURL": "http://127.0.0.1:5000/v2.0",
            "publicURL": "http://127.0.0.1:5000/v2.0"
        }],
        "type": "identity",
        "name": "keystone"
    }, {
        "endpoints": [{
            "adminURL": "http://swift/swiftapi/admin",
            "region": "RegionOne",
            "internalURL": "http://swift/swiftapi/internal",
            "publicURL": "http://swift/swiftapi/public"
        }],
        "type": "object-store",
        "name": "swift"
    }]

    def setUp(self):
        super(V2IdentityPlugin, self).setUp()
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

    def _plugin(self, **kwargs):
        kwargs.setdefault('auth_url', self.TEST_URL)
        return v2.Auth(**kwargs)

    def _session(self, **kwargs):
        return session.Session(auth=self._plugin(**kwargs))

    def stub_auth(self, **kwargs):
        self.stub_url(httpretty.POST, ['tokens'], **kwargs)

    @httpretty.activate
    def test_authenticate_with_username_password(self):
        self.stub_auth(json=self.TEST_RESPONSE_DICT)
        s = self._session(username=self.TEST_USER, password=self.TEST_PASS)
        s.get_token()

        req = {'auth': {'passwordCredentials': {'username': self.TEST_USER,
                                                'password': self.TEST_PASS}}}
        self.assertRequestBodyIs(json=req)
        self.assertEqual(s.auth.auth_ref.auth_token, self.TEST_TOKEN)

    @httpretty.activate
    def test_authenticate_with_username_password_scoped(self):
        self.stub_auth(json=self.TEST_RESPONSE_DICT)
        s = self._session(username=self.TEST_USER, password=self.TEST_PASS,
                          tenant_id=self.TEST_TENANT_ID)
        s.get_token()

        req = {'auth': {'passwordCredentials': {'username': self.TEST_USER,
                                                'password': self.TEST_PASS},
                        'tenantId': self.TEST_TENANT_ID}}
        self.assertRequestBodyIs(json=req)
        self.assertEqual(s.auth.auth_ref.auth_token, self.TEST_TOKEN)

    @httpretty.activate
    def test_authenticate_with_token(self):
        self.stub_auth(json=self.TEST_RESPONSE_DICT)
        s = self._session(token='foo')
        s.get_token()

        req = {'auth': {'token': {'id': 'foo'}}}
        self.assertRequestBodyIs(json=req)
        self.assertEqual(s.auth.auth_ref.auth_token, self.TEST_TOKEN)

    def test_missing_auth_url(self):
        a = v2.Auth(username=self.TEST_USER, password=self.TEST_PASS)
        self.assertRaises(exceptions.AuthorizationFailure,
                          a.get_token, None)

    def test_missing_auth_params(self):
        a = self._plugin()
        self.assertRaises(exceptions.AuthorizationFailure,
                          a.get_token, None)

    @httpretty.activate
    def test_with_trust_id(self):
        self.stub_auth(json=self.TEST_RESPONSE_DICT)
        s = self._session(username=self.TEST_USER, password=self.TEST_PASS,
                          trust_id='trust')
        s.get_token()

        req = {'auth': {'passwordCredentials': {'username': self.TEST_USER,
                                                'password': self.TEST_PASS},
                        'trust_id': 'trust'}}

        self.assertRequestBodyIs(json=req)
        self.assertEqual(s.auth.auth_ref.auth_token, self.TEST_TOKEN)
