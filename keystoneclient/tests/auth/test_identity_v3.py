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

import copy

import httpretty

from keystoneclient import access
from keystoneclient.auth.identity import v3
from keystoneclient import exceptions
from keystoneclient import session
from keystoneclient.tests import utils


class V3IdentityPlugin(utils.TestCase):

    TEST_ROOT_URL = 'http://127.0.0.1:5000/'
    TEST_URL = '%s%s' % (TEST_ROOT_URL, 'v3')
    TEST_ROOT_ADMIN_URL = 'http://127.0.0.1:35357/'
    TEST_ADMIN_URL = '%s%s' % (TEST_ROOT_ADMIN_URL, 'v3')

    TEST_PASS = 'password'

    TEST_SERVICE_CATALOG = [{
        "endpoints": [{
            "url": "http://cdn.admin-nets.local:8774/v1.0/",
            "region": "RegionOne",
            "interface": "public"
        }, {
            "url": "http://127.0.0.1:8774/v1.0",
            "region": "RegionOne",
            "interface": "internal"
        }, {
            "url": "http://cdn.admin-nets.local:8774/v1.0",
            "region": "RegionOne",
            "interface": "admin"
        }],
        "type": "nova_compat"
    }, {
        "endpoints": [{
            "url": "http://nova/novapi/public",
            "region": "RegionOne",
            "interface": "public"
        }, {
            "url": "http://nova/novapi/internal",
            "region": "RegionOne",
            "interface": "internal"
        }, {
            "url": "http://nova/novapi/admin",
            "region": "RegionOne",
            "interface": "admin"
        }],
        "type": "compute"
    }, {
        "endpoints": [{
            "url": "http://glance/glanceapi/public",
            "region": "RegionOne",
            "interface": "public"
        }, {
            "url": "http://glance/glanceapi/internal",
            "region": "RegionOne",
            "interface": "internal"
        }, {
            "url": "http://glance/glanceapi/admin",
            "region": "RegionOne",
            "interface": "admin"
        }],
        "type": "image",
        "name": "glance"
    }, {
        "endpoints": [{
            "url": "http://127.0.0.1:5000/v3",
            "region": "RegionOne",
            "interface": "public"
        }, {
            "url": "http://127.0.0.1:5000/v3",
            "region": "RegionOne",
            "interface": "internal"
        }, {
            "url": TEST_ADMIN_URL,
            "region": "RegionOne",
            "interface": "admin"
        }],
        "type": "identity"
    }, {
        "endpoints": [{
            "url": "http://swift/swiftapi/public",
            "region": "RegionOne",
            "interface": "public"
        }, {
            "url": "http://swift/swiftapi/internal",
            "region": "RegionOne",
            "interface": "internal"
        }, {
            "url": "http://swift/swiftapi/admin",
            "region": "RegionOne",
            "interface": "admin"
        }],
        "type": "object-store"
    }]

    def setUp(self):
        super(V3IdentityPlugin, self).setUp()
        self.TEST_RESPONSE_DICT = {
            "token": {
                "methods": [
                    "token",
                    "password"
                ],

                "expires_at": "2020-01-01T00:00:10.000123Z",
                "project": {
                    "domain": {
                        "id": self.TEST_DOMAIN_ID,
                        "name": self.TEST_DOMAIN_NAME
                    },
                    "id": self.TEST_TENANT_ID,
                    "name": self.TEST_TENANT_NAME
                },
                "user": {
                    "domain": {
                        "id": self.TEST_DOMAIN_ID,
                        "name": self.TEST_DOMAIN_NAME
                    },
                    "id": self.TEST_USER,
                    "name": self.TEST_USER
                },
                "issued_at": "2013-05-29T16:55:21.468960Z",
                "catalog": self.TEST_SERVICE_CATALOG
            },
        }

    def _plugin(self, **kwargs):
        kwargs.setdefault('auth_url', self.TEST_URL)
        return v3.Auth(**kwargs)

    def _session(self, **kwargs):
        return session.Session(auth=self._plugin(**kwargs))

    def stub_auth(self, subject_token=None, **kwargs):
        if not subject_token:
            subject_token = self.TEST_TOKEN

        self.stub_url(httpretty.POST, ['auth', 'tokens'],
                      X_Subject_Token=subject_token, **kwargs)

    @httpretty.activate
    def test_authenticate_with_username_password(self):
        self.stub_auth(json=self.TEST_RESPONSE_DICT)
        s = self._session(username=self.TEST_USER, password=self.TEST_PASS)
        s.get_token()

        req = {'auth': {'identity':
               {'methods': ['password'],
                'password': {'user': {'name': self.TEST_USER,
                                      'password': self.TEST_PASS}}}}}

        self.assertRequestBodyIs(json=req)
        self.assertEqual(s.auth.auth_ref.auth_token, self.TEST_TOKEN)

    @httpretty.activate
    def test_authenticate_with_username_password_domain_scoped(self):
        self.stub_auth(json=self.TEST_RESPONSE_DICT)
        s = self._session(username=self.TEST_USER, password=self.TEST_PASS,
                          domain_id=self.TEST_DOMAIN_ID)
        s.get_token()

        req = {'auth': {'identity':
               {'methods': ['password'],
                'password': {'user': {'name': self.TEST_USER,
                                      'password': self.TEST_PASS}}},
               'scope': {'domain': {'id': self.TEST_DOMAIN_ID}}}}
        self.assertRequestBodyIs(json=req)
        self.assertEqual(s.auth.auth_ref.auth_token, self.TEST_TOKEN)

    @httpretty.activate
    def test_authenticate_with_username_password_project_scoped(self):
        self.stub_auth(json=self.TEST_RESPONSE_DICT)
        s = self._session(username=self.TEST_USER, password=self.TEST_PASS,
                          project_id=self.TEST_DOMAIN_ID)
        s.get_token()

        req = {'auth': {'identity':
               {'methods': ['password'],
                'password': {'user': {'name': self.TEST_USER,
                                      'password': self.TEST_PASS}}},
               'scope': {'project': {'id': self.TEST_DOMAIN_ID}}}}
        self.assertRequestBodyIs(json=req)
        self.assertEqual(s.auth.auth_ref.auth_token, self.TEST_TOKEN)
        self.assertEqual(s.auth.auth_ref.project_id, self.TEST_DOMAIN_ID)

    @httpretty.activate
    def test_authenticate_with_token(self):
        self.stub_auth(json=self.TEST_RESPONSE_DICT)
        s = self._session(token=self.TEST_TOKEN)
        s.get_token()

        req = {'auth': {'identity':
               {'methods': ['token'],
                'token': {'id': self.TEST_TOKEN}}}}

        self.assertRequestBodyIs(json=req)
        self.assertEqual(s.auth.auth_ref.auth_token, self.TEST_TOKEN)

    def test_missing_auth_url(self):
        a = v3.Auth(username=self.TEST_USER, password=self.TEST_PASS)
        self.assertRaises(exceptions.AuthorizationFailure,
                          a.get_token, None)

    def test_missing_auth_params(self):
        a = self._plugin()
        self.assertRaises(exceptions.AuthorizationFailure,
                          a.get_token, None)

    @httpretty.activate
    def test_with_expired(self):
        self.stub_auth(json=self.TEST_RESPONSE_DICT)

        d = copy.deepcopy(self.TEST_RESPONSE_DICT)
        d['token']['expires_at'] = '2000-01-01T00:00:10.000123Z'

        a = self._plugin(username='username', password='password')
        a.auth_ref = access.AccessInfo.factory(body=d)
        s = session.Session(auth=a)

        s.get_token()

        self.assertEqual(a.auth_ref['expires_at'],
                         self.TEST_RESPONSE_DICT['token']['expires_at'])

    def test_with_domain_and_project_scoping(self):
        a = self._plugin(username='username', password='password',
                         project_id='project', domain_id='domain')
        self.assertRaises(exceptions.AuthorizationFailure,
                          a.get_token, None)

    @httpretty.activate
    def test_with_trust_id(self):
        self.stub_auth(json=self.TEST_RESPONSE_DICT)
        s = self._session(username=self.TEST_USER, password=self.TEST_PASS,
                          trust_id='trust')
        s.get_token()

        req = {'auth': {'identity':
               {'methods': ['password'],
                'password': {'user': {'name': self.TEST_USER,
                                      'password': self.TEST_PASS}}},
               'scope': {'OS-TRUST:trust': {'id': 'trust'}}}}
        self.assertRequestBodyIs(json=req)
        self.assertEqual(s.auth.auth_ref.auth_token, self.TEST_TOKEN)
