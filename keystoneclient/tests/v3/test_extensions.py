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

from keystoneclient.tests.v3 import client_fixtures
from keystoneclient.tests.v3 import utils
from keystoneclient.v3 import client

SAMPLE_DATA = {
    "extensions": [
        {
            "id": "ext-test-id",
            "name": "OS-TEST-EXT",
            "url": "http://identity:35357/v3/OS-TEST-EXT",
            "links": {
                "self": "http://identity:35357/v3/extensions/OS-TEST-EXT",
            },
            "extra": {
                "features": ["feature1", "feature5"],
            }
        },
    ],
    "links": {
        "self": "http://identity:35357/v3/extensions",
        "previous": None,
        "next": None
    }
}


class ExtensionTests(utils.TestCase):

    def setUp(self):
        self.stub_auth(json=client_fixtures.DOMAIN_SCOPED_TOKEN)
        super(ExtensionTests, self).setUp()

    @httpretty.activate
    def test_do(self):
        self.stub_auth(json=client_fixtures.PROJECT_SCOPED_TOKEN),

        self.stub_url(httpretty.GET, ['v3', 'extensions'],
                      json=SAMPLE_DATA,
                      base_url='http://admin:35357')

        c = client.Client(user_id='c4da488862bd435c9e6c0275a0d0e49a',
                          password='password',
                          user_domain_name='exampledomain',
                          project_name='exampleproject',
                          auth_url=self.TEST_URL)

        ext = c.extensions
        import ipdb; ipdb.set_trace()
