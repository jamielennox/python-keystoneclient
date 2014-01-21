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

import logging

from keystoneclient import access
from keystoneclient.auth.identity import base

from keystoneclient import exceptions

_logger = logging.getLogger(__name__)


class Auth(base.BaseIdentityPlugin):

    def __init__(self,
                 auth_url=None,
                 username=None,
                 password=None,
                 token=None,
                 trust_id=None,
                 user_id=None,
                 domain_id=None,
                 domain_name=None,
                 user_domain_id=None,
                 user_domain_name=None,
                 project_id=None,
                 project_name=None,
                 project_domain_id=None,
                 project_domain_name=None):
        """Construct an Identity V3 Authentication Plugin.

        :param string auth_url: Identity service endpoint for authorization.
        :param string username: Username for authentication.
        :param string password: Password for authentication.
        :param string token: Token for authentication.
        :param string trust_id: Trust ID for trust scoping.
        :param string user_id: User ID for authentication.
        :param string domain_id: Domain ID for domain scoping.
        :param string domain_name: Domain name for domain scoping.
        :param string user_domain_id: User's domain ID for authentication.
        :param string user_domain_name: User's domain name for authentication.
        :param string project_id: Project ID for project scoping.
        :param string project_name: Project name for project scoping.
        :param string project_domain_id: Project's domain ID for project.
        :param string project_domain_name: Project's domain name for project.
        """

        super(Auth, self).__init__(auth_url=auth_url,
                                   username=username,
                                   password=password,
                                   token=token,
                                   trust_id=trust_id)

        self.user_id = user_id
        self.domain_id = domain_id
        self.domain_name = domain_name
        self.user_domain_id = user_domain_id
        self.user_domain_name = user_domain_name
        self.project_id = project_id
        self.project_name = project_name
        self.project_domain_id = project_domain_id
        self.project_domain_name = project_domain_name

    def get_auth_ref(self, session):
        if not self.auth_url:
            raise exceptions.AuthorizationFailure("Cannot authenticate without"
                                                  " a valid auth_url")

        headers = {}
        url = self.auth_url + "/auth/tokens"
        body = {'auth': {'identity': {}}}
        ident = body['auth']['identity']

        if self.token:
            headers['X-Auth-Token'] = self.token
            ident.setdefault('methods', []).append('token')
            ident['token'] = {'id': self.token}

        if self.password:
            ident.setdefault('methods', []).append('password')
            user = {'password': self.password}

            if self.user_id:
                user['id'] = self.user_id
            elif self.username:
                user['name'] = self.username

                if self.user_domain_id:
                    user['domain'] = {'id': self.user_domain_id}
                elif self.user_domain_name:
                    user['domain'] = {'name': self.user_domain_name}

            ident['password'] = {'user': user}

        if ((self.domain_id or self.domain_name) and
                (self.project_id or self.project_name)):
            raise exceptions.AuthorizationFailure('Authentication cannot be '
                                                  'scoped to both domain '
                                                  'and project.')

        if self.domain_id:
            body['auth']['scope'] = {'domain': {'id': self.domain_id}}
        elif self.domain_name:
            body['auth']['scope'] = {'domain': {'name': self.domain_name}}
        elif self.project_id:
            body['auth']['scope'] = {'project': {'id': self.project_id}}
        elif self.project_name:
            scope = body['auth']['scope'] = {'project': {}}
            scope['project']['name'] = self.project_name

            if self.project_domain_id:
                scope['project']['domain'] = {'id': self.project_domain_id}
            elif self.project_domain_name:
                scope['project']['domain'] = {'name': self.project_domain_name}

        if self.trust_id:
            scope = body['auth'].setdefault('scope', {})
            scope['OS-TRUST:trust'] = {'id': self.trust_id}

        if not ident:
            raise exceptions.AuthorizationFailure('Authentication method '
                                                  'required (e.g. password)')

        resp = session.post(url, json=body, headers=headers,
                            authenticated=False)
        return access.AccessInfoV3(resp.headers['X-Subject-Token'],
                                   **resp.json()['token'])
