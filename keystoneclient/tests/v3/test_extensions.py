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


class ExtensionTests(utils.TestCase):

    def setUp(self):
        self.stub_auth(json=client_fixtures.DOMAIN_SCOPED_TOKEN)
        super(ExtensionTests, self).setUp()

    @httpretty.activate
    def test_do(self):
        ext = self.client.extensions
        import ipdb; ipdb.set_trace()
