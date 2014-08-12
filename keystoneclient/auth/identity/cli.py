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

import getpass
import sys

from keystoneclient.auth import base as auth_base
from keystoneclient.auth.identity.generic import base as generic_base
from keystoneclient.auth.identity.generic import password
from keystoneclient.auth.identity.generic import token
from keystoneclient import exceptions


class Cli(auth_base.ProxyBasePlugin):

    _BASE_PARAMS = frozenset(['trust_id',
                              'tenant_id', 'tenant_name',
                              'project_id', 'project_name',
                              'project_domain_id', 'project_domain_name',
                              'domain_id', 'domain_name'])

    def __init__(self, **kwargs):
        super(Cli, self).__init__()

        self._auth_url = kwargs.pop('auth_url', None)

        self._username = kwargs.pop('username', None)
        self._user_domain_id = kwargs.pop('user_domain_id', None)
        self._user_domain_name = kwargs.pop('user_domain_name', None)
        self._password = kwargs.pop('password', None)

        self._token = kwargs.pop('token', None)

        self._params = {}
        for param in self._BASE_PARAMS:
            try:
                self._params[param] = kwargs.pop(param)
            except KeyError:
                pass

        if kwargs:
            raise TypeError('Unexpected Arguments: %s' %
                            ', '.join(kwargs.keys()))

        self._plugin = None

    def create_plugin(self, session):
        if not self._auth_url:
            raise Exception()

        has_username = any([self._username,
                            self._user_domain_id,
                            self._user_domain_name])

        if not self._password and has_username:
            # No password, If we've got a tty, try prompting for it
            if hasattr(sys.stdin, 'isatty') and sys.stdin.isatty():
                # Check for Ctl-D
                try:
                    self._password = getpass.getpass('OS Password: ')
                except EOFError:
                    pass

            # No password because we didn't have a tty or the
            # user Ctl-D when prompted?
            if not self._password:
                msg = 'Expecting a password provided via either --os-password'
                msg += ', env[OS_PASSWORD], or prompted response.'
                raise exceptions.DiscoveryFailure(msg)

        if self._password:
            return password.Password(self._auth_url,
                                     username=self._username,
                                     password=self._password,
                                     user_domain_id=self._user_domain_id,
                                     user_domain_name=self._user_domain_name,
                                     **self._params)

        if self._token:
            return token.Token(self._auth_url, self._token, **self._params)

        raise exceptions.DiscoveryFailure('Expecting an authentication method')

    @classmethod
    def get_options(cls):
        options = super(Cli, cls).get_options()

        options.extend(generic_base.get_options())
        options.extend(password.get_options())
        options.extend(token.get_options())

        return options
