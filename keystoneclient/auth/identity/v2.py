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

    def __init__(self, auth_url=None, token=None, username=None, password=None,
                 tenant_id=None, tenant_name=None, trust_id=None):
        super(Auth, self).__init__(auth_url,
                                   token=token,
                                   username=username,
                                   password=password)

        self.tenant_id = tenant_id
        self.tenant_name = tenant_name
        self.trust_id = trust_id

    def do_authenticate(self, session, **kwargs):
        headers = {}

        auth_url = kwargs.get('auth_url', self.auth_url)
        username = kwargs.get('username', self.username)
        password = kwargs.get('password', self.password)
        token = kwargs.get('token', self.token)
        tenant_id = kwargs.get('tenant_id', self.tenant_id)
        tenant_name = kwargs.get('tenant_name', self.tenant_name)
        trust_id = kwargs.get('trust_id', self.trust_id)

        if not auth_url:
            raise exceptions.AuthorizationFailure("Cannot authenticate without"
                                                  " a valid auth_url")

        url = self.auth_url + "/tokens"

        if username and password:
            params = {"username": username, "password": password}
            params = {"auth": {"passwordCredentials": params}}
        elif token:
            headers['X-Auth-Token'] = token
            params = {"auth": {"token": {"id": token}}}
        else:
            raise exceptions.AuthorizationFailure('A username and password or '
                                                  'token is required.')

        if tenant_id:
            params['auth']['tenantId'] = tenant_id
        elif tenant_name:
            params['auth']['tenantName'] = tenant_name
        if trust_id:
            params['auth']['trust_id'] = trust_id

        resp = session.post(url, json=params, headers=headers,
                            authenticated=False)
        self.auth_ref = access.AccessInfoV2(**resp.json()['access'])

        return True
