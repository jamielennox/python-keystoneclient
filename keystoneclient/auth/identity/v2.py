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
from keystoneclient.auth.identity import base as base
from keystoneclient import exceptions

_logger = logging.getLogger(__name__)


class Auth(base.IdentityBasePlugin):

    opt_names = ['auth_url',
                 'endpoint',
                 'token',
                 'username',
                 'password',
                 'tenant_id',
                 'tenant_name']

    def do_authenticate(self, session):
        if not self.auth_url:
            raise exceptions.AuthorizationFailure

        headers = {}
        url = self.auth_url + "/tokens"
        if self.token:
            headers['X-Auth-Token'] = self.token
            params = {"auth": {"token": {"id": self.token}}}
        elif self.username and self.password:
            params = {"username": self.username, "password": self.password}
            params = {"auth": {"passwordCredentials": params}}
        else:
            raise ValueError('A username and password or token is required.')

        if self.tenant_id:
            params['auth']['tenantId'] = self.tenant_id
        elif self.tenant_name:
            params['auth']['tenantName'] = self.tenant_name

        resp = self._request(session, url, 'POST',
                             json=params, headers=headers)

        self.auth_ref = access.AccessInfo.factory(resp, resp.json())
