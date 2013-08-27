# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC
#
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


class Auth(base.IdentityBasePlugin):

    opt_names = ['auth_url',
                 'user_id',
                 'username',
                 'user_domain_id',
                 'user_domain_name',
                 'password',
                 'domain_id',
                 'domain_name',
                 'project_id',
                 'project_name',
                 'project_domain_id',
                 'project_domain_name',
                 'token',
                 'endpoint',
                 'trust_id']

    def do_authenticate(self, session):
        if not self.auth_url:
            raise exceptions.AuthorizationFailure

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
            raise ValueError('Authentication cannot be scoped to both domain'
                             ' and project.')

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

        if not (ident or token):
            raise ValueError('Authentication method required (e.g. password)')

        resp = self._request(session, url, 'POST', json=body, headers=headers)
        self.auth_ref = access.AccessInfo.factory(resp, resp.json())
