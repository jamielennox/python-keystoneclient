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

    def __init__(self, auth_url=None, token=None, trust_id=None,
                 user_id=None, username=None, password=None,
                 domain_id=None, domain_name=None,
                 user_domain_id=None, user_domain_name=None,
                 project_id=None, project_name=None,
                 project_domain_id=None, project_domain_name=None):
        super(Auth, self).__init__(auth_url,
                                   token=token,
                                   username=username,
                                   password=password)

        self.trust_id = trust_id
        self.user_id = user_id
        self.domain_id = domain_id
        self.domain_name = domain_name
        self.user_domain_id = user_domain_id
        self.user_domain_name = user_domain_name
        self.project_id = project_id
        self.project_name = project_name
        self.project_domain_id = project_domain_id
        self.project_domain_name = project_domain_name

    def do_authenticate(self, session, **kwargs):
        auth_url = kwargs.get('auth_url', self.auth_url)
        password = kwargs.get('password', self.password)
        token = kwargs.get('token', self.token)

        if not auth_url:
            raise exceptions.AuthorizationFailure("Cannot authenticate without"
                                                  " a valid auth_url")

        headers = {}
        url = auth_url + "/auth/tokens"
        body = {'auth': {'identity': {}}}
        ident = body['auth']['identity']

        if token:
            headers['X-Auth-Token'] = token
            ident.setdefault('methods', []).append('token')
            ident['token'] = {'id': token}

        if password:
            ident.setdefault('methods', []).append('password')
            user = {'password': password}

            user_id = kwargs.get('user_id', self.user_id)
            username = kwargs.get('username', self.username)

            if user_id:
                user['id'] = user_id
            elif username:
                user['name'] = username

                user_domain_id = kwargs.get('user_domain_id',
                                            self.user_domain_id)
                user_domain_name = kwargs.get('user_domain_name',
                                              self.user_domain_name)

                if user_domain_id:
                    user['domain'] = {'id': user_domain_id}
                elif user_domain_name:
                    user['domain'] = {'name': user_domain_name}

            ident['password'] = {'user': user}

        domain_id = kwargs.get('domain_id', self.domain_id)
        domain_name = kwargs.get('domain_name', self.domain_name)
        project_id = kwargs.get('project_id', self.project_id)
        project_name = kwargs.get('project_name', self.project_name)

        if ((domain_id or domain_name) and (project_id or project_name)):
            raise exceptions.AuthorizationFailure('Authentication cannot be '
                                                  'scoped to both domain '
                                                  'and project.')

        if domain_id:
            body['auth']['scope'] = {'domain': {'id': domain_id}}
        elif domain_name:
            body['auth']['scope'] = {'domain': {'name': domain_name}}
        elif project_id:
            body['auth']['scope'] = {'project': {'id': project_id}}
        elif project_name:
            scope = body['auth']['scope'] = {'project': {}}
            scope['project']['name'] = project_name

            project_domain_id = kwargs.get('project_domain_id',
                                           self.project_domain_id)
            project_domain_name = kwargs.get('project_domain_name',
                                             self.project_domain_name)

            if project_domain_id:
                scope['project']['domain'] = {'id': project_domain_id}
            elif project_domain_name:
                scope['project']['domain'] = {'name': project_domain_name}

        trust_id = kwargs.get('trust_id', self.trust_id)

        if trust_id:
            scope = body['auth'].setdefault('scope', {})
            scope['OS-TRUST:trust'] = {'id': trust_id}

        if not ident:
            raise exceptions.AuthorizationFailure('Authentication method '
                                                  'required (e.g. password)')

        resp = session.post(url, json=body, headers=headers,
                            authenticated=False)
        self.auth_ref = access.AccessInfoV3(resp.headers['X-Subject-Token'],
                                            **resp.json()['token'])
