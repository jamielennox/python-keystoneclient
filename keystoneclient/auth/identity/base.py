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

from keystoneclient.auth import base
from keystoneclient import exceptions


class BaseIdentityPlugin(base.BaseAuthPlugin):

    def __init__(self, auth_url, username=None, password=None, token=None):
        super(BaseIdentityPlugin, self).__init__()

        self.auth_url = auth_url
        self.username = username
        self.password = password
        self.token = token

        self.auth_ref = None

    def get_token(self):
        if not self.auth_ref:
            raise exceptions.AuthPluginUnauthenticated()

        if self.auth_ref.will_expire_soon(1):
            raise exceptions.AuthPluginUnauthenticated()

        return self.auth_ref.auth_token
