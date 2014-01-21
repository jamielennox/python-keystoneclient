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

from keystoneclient import access
from keystoneclient.auth.identity import base

from keystoneclient import exceptions


class Auth(base.BaseIdentityPlugin):

    def __init__(self,
                 auth_url=None,
                 username=None,
                 password=None,
                 token=None,
                 trust_id=None,
                 tenant_id=None,
                 tenant_name=None):
        """Construct an Identity V2 Authentication Plugin.

        :param string auth_url: Identity service endpoint for authorization.
        :param string username: Username for authentication.
        :param string password: Password for authentication.
        :param string token: Token for authentication.
        :param string trust_id: Trust ID for trust scoping.
        :param string tenant_id: Tenant ID for project scoping.
        :param string tenant_name: Tenant name for project scoping.
        """

        super(Auth, self).__init__(auth_url=auth_url,
                                   username=username,
                                   password=password,
                                   token=token,
                                   trust_id=trust_id)

        self.tenant_id = tenant_id
        self.tenant_name = tenant_name

    def get_auth_ref(self, session):
        if not self.auth_url:
            raise exceptions.AuthorizationFailure("Cannot authenticate without"
                                                  " a valid auth_url")
        headers = {}
        url = self.auth_url + "/tokens"

        if self.username and self.password:
            params = {"username": self.username, "password": self.password}
            params = {"auth": {"passwordCredentials": params}}
        elif self.token:
            headers['X-Auth-Token'] = self.token
            params = {"auth": {"token": {"id": self.token}}}
        else:
            raise exceptions.AuthorizationFailure('A username and password or '
                                                  'token is required.')

        if self.tenant_id:
            params['auth']['tenantId'] = self.tenant_id
        elif self.tenant_name:
            params['auth']['tenantName'] = self.tenant_name
        if self.trust_id:
            params['auth']['trust_id'] = self.trust_id

        resp = session.post(url, json=params, headers=headers,
                            authenticated=False)
        return access.AccessInfoV2(**resp.json()['access'])
