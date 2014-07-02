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

import uuid

from keystoneclient.tests.v2_0 import utils
from keystoneclient.v2_0 import users


class UserTests(utils.TestCase):
    def setUp(self):
        super(UserTests, self).setUp()
        self.ADMIN_USER_ID = uuid.uuid4().hex
        self.DEMO_USER_ID = uuid.uuid4().hex
        self.TEST_USERS = {
            "users": {
                "values": [
                    {
                        "email": "None",
                        "enabled": True,
                        "id": self.ADMIN_USER_ID,
                        "name": "admin",
                    },
                    {
                        "email": "None",
                        "enabled": True,
                        "id": self.DEMO_USER_ID,
                        "name": "demo",
                    },
                ]
            }
        }

    def test_create(self):
        tenant_id = uuid.uuid4().hex
        user_id = uuid.uuid4().hex
        req_body = {
            "user": {
                "name": "gabriel",
                "password": "test",
                "tenantId": tenant_id,
                "email": "test@example.com",
                "enabled": True,
            }
        }

        resp_body = {
            "user": {
                "name": "gabriel",
                "enabled": True,
                "tenantId": tenant_id,
                "id": user_id,
                "password": "test",
                "email": "test@example.com",
            }
        }

        self.stub_url('POST', ['users'], json=resp_body)

        user = self.client.users.create(req_body['user']['name'],
                                        req_body['user']['password'],
                                        req_body['user']['email'],
                                        tenant_id=req_body['user']['tenantId'],
                                        enabled=req_body['user']['enabled'])
        self.assertIsInstance(user, users.User)
        self.assertEqual(user.id, user_id)
        self.assertEqual(user.name, "gabriel")
        self.assertEqual(user.email, "test@example.com")
        self.assertRequestBodyIs(json=req_body)

    def test_create_user_without_email(self):
        tenant_id = uuid.uuid4().hex
        req_body = {
            "user": {
                "name": "gabriel",
                "password": "test",
                "tenantId": tenant_id,
                "enabled": True,
                "email": None,
            }
        }

        user_id = uuid.uuid4().hex
        resp_body = {
            "user": {
                "name": "gabriel",
                "enabled": True,
                "tenantId": tenant_id,
                "id": user_id,
                "password": "test",
            }
        }

        self.stub_url('POST', ['users'], json=resp_body)

        user = self.client.users.create(
            req_body['user']['name'],
            req_body['user']['password'],
            tenant_id=req_body['user']['tenantId'],
            enabled=req_body['user']['enabled'])
        self.assertIsInstance(user, users.User)
        self.assertEqual(user.id, user_id)
        self.assertEqual(user.name, "gabriel")
        self.assertRequestBodyIs(json=req_body)

    def test_delete(self):
        self.stub_url('DELETE', ['users', self.ADMIN_USER_ID], status_code=204)
        self.client.users.delete(self.ADMIN_USER_ID)

    def test_get(self):
        self.stub_url('GET', ['users', self.ADMIN_USER_ID],
                      json={'user': self.TEST_USERS['users']['values'][0]})

        u = self.client.users.get(self.ADMIN_USER_ID)
        self.assertIsInstance(u, users.User)
        self.assertEqual(u.id, self.ADMIN_USER_ID)
        self.assertEqual(u.name, 'admin')

    def test_list(self):
        self.stub_url('GET', ['users'], json=self.TEST_USERS)

        user_list = self.client.users.list()
        [self.assertIsInstance(u, users.User) for u in user_list]

    def test_list_limit(self):
        self.stub_url('GET', ['users'], json=self.TEST_USERS)

        user_list = self.client.users.list(limit=1)
        self.assertQueryStringIs('limit=1')
        [self.assertIsInstance(u, users.User) for u in user_list]

    def test_list_marker(self):
        self.stub_url('GET', ['users'], json=self.TEST_USERS)

        user_list = self.client.users.list(marker='foo')
        self.assertQueryStringIs('marker=foo')
        [self.assertIsInstance(u, users.User) for u in user_list]

    def test_list_limit_marker(self):
        self.stub_url('GET', ['users'], json=self.TEST_USERS)

        user_list = self.client.users.list(limit=1, marker='foo')

        self.assertQueryStringIs('marker=foo&limit=1')
        [self.assertIsInstance(u, users.User) for u in user_list]

    def test_update(self):
        req_1 = {
            "user": {
                "id": self.DEMO_USER_ID,
                "email": "gabriel@example.com",
                "name": "gabriel",
            }
        }
        req_2 = {
            "user": {
                "id": self.DEMO_USER_ID,
                "password": "swordfish",
            }
        }
        tenant_id = uuid.uuid4().hex
        req_3 = {
            "user": {
                "id": self.DEMO_USER_ID,
                "tenantId": tenant_id,
            }
        }
        req_4 = {
            "user": {
                "id": self.DEMO_USER_ID,
                "enabled": False,
            }
        }

        self.stub_url('PUT', ['users', self.DEMO_USER_ID], json=req_1)
        self.stub_url('PUT',
                      ['users', self.DEMO_USER_ID, 'OS-KSADM', 'password'],
                      json=req_2)
        self.stub_url('PUT',
                      ['users', self.DEMO_USER_ID, 'OS-KSADM', 'tenant'],
                      json=req_3)
        self.stub_url('PUT',
                      ['users', self.DEMO_USER_ID, 'OS-KSADM', 'enabled'],
                      json=req_4)

        self.client.users.update(self.DEMO_USER_ID,
                                 name='gabriel',
                                 email='gabriel@example.com')
        self.assertRequestBodyIs(json=req_1)
        self.client.users.update_password(self.DEMO_USER_ID, 'swordfish')
        self.assertRequestBodyIs(json=req_2)
        self.client.users.update_tenant(self.DEMO_USER_ID, tenant_id)
        self.assertRequestBodyIs(json=req_3)
        self.client.users.update_enabled(self.DEMO_USER_ID, False)
        self.assertRequestBodyIs(json=req_4)

    def test_update_own_password(self):
        req_body = {
            'user': {
                'password': 'ABCD', 'original_password': 'DCBA'
            }
        }
        resp_body = {
            'access': {}
        }
        user_id = uuid.uuid4().hex
        self.stub_url('PATCH', ['OS-KSCRUD', 'users', user_id], json=resp_body)

        self.client.user_id = user_id
        self.client.users.update_own_password('DCBA', 'ABCD')
        self.assertRequestBodyIs(json=req_body)
