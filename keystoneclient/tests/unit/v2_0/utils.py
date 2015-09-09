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

from keystoneauth1 import token_endpoint
from keystoneauth1 import session

from keystoneclient.tests.unit import utils
from keystoneclient.v2_0 import client

TestResponse = utils.TestResponse


class UnauthenticatedTestCase(utils.TestCase):
    """Class used as base for unauthenticated calls."""

    TEST_ROOT_URL = 'http://127.0.0.1:5000/'
    TEST_URL = '%s%s' % (TEST_ROOT_URL, 'v2.0')
    TEST_ROOT_ADMIN_URL = 'http://127.0.0.1:35357/'
    TEST_ADMIN_URL = '%s%s' % (TEST_ROOT_ADMIN_URL, 'v2.0')


class TestCase(UnauthenticatedTestCase):

    TEST_ADMIN_IDENTITY_ENDPOINT = "http://127.0.0.1:35357/v2.0"

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
            "adminURL": TEST_ADMIN_IDENTITY_ENDPOINT,
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
        super(TestCase, self).setUp()

        s = session.Session()
        a = token_endpoint.Token(token=self.TEST_TOKEN, endpoint=self.TEST_URL)
        self.client = client.Client(session=s, auth=a)

    def stub_auth(self, **kwargs):
        self.stub_url('POST', ['tokens'], **kwargs)
