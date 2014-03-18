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

from oslo.config import cfg

from keystoneclient.auth.identity import base
from keystoneclient.auth.identity import v2
from keystoneclient.auth.identity import v3
from keystoneclient import exceptions
from keystoneclient import utils


class Password(base.BaseIdentityPlugin):

    @utils.positional()
    def __init__(self, auth_url, username=None, user_id=None, password=None,
                 domain_id=None, domain_name=None, tenant_id=None,
                 tenant_name=None, project_id=None, project_name=None,
                 project_domain_id=None, project_domain_name=None,
                 user_domain_id=None, user_domain_name=None, trust_id=None):
        super(Password, self).__init__(auth_url=auth_url)

        self._username = username
        self._user_id = user_id
        self._password = password
        self._domain_id = domain_id
        self._domain_name = domain_name
        self._project_id = project_id or tenant_id
        self._project_name = project_name or tenant_name
        self._project_domain_id = project_domain_id
        self._project_domain_name = project_domain_name
        self._user_domain_id = user_domain_id
        self._user_domain_name = user_domain_name
        self._trust_id = trust_id

        self._plugin = None

    def _get_v2_password(self, url):
        return v2.Password(auth_url=url,
                           username=self._username,
                           password=self._password,
                           tenant_id=self._project_id,
                           tenant_name=self._project_name,
                           trust_id=self._trust_id)

    def _get_v3_password(self, url):
        return v3.Password(auth_url=url,
                           user_id=self._user_id,
                           username=self._username,
                           user_domain_id=self._user_domain_id,
                           user_domain_name=self._user_domain_name,
                           password=self._password,
                           trust_id=self._trust_id,
                           domain_id=self._domain_id,
                           domain_name=self._domain_name,
                           project_id=self._project_id,
                           project_name=self._project_name,
                           project_domain_id=self._project_domain_id,
                           project_domain_name=self._project_domain_name)

    def _get_plugin(self, session):
        disc = self.get_discovery(session, self.auth_url, authenticated=False)
        v2_url = disc.url_for((2, 0))
        v3_url = disc.url_for((3, 0))

        if (self._domain_id or self._domain_name or
                self._project_domain_id or self._project_domain_name or
                self._user_domain_id or self._user_domain_name):
            # The user is providing information that is specific to a v3 auth
            # plugin so they must want to use v3.
            if not v3_url:
                # FIXME(jamielennox): raise something more appropriate
                raise exceptions.DiscoveryFailure()

            return self._get_v3_password(v3_url)

        elif v2_url:
            # No domain information was provided at all. This probably means
            # that the user wants v2 auth - or it makes no difference.
            return self._get_v2_password(v2_url)

        elif v3_url:
            # hmm, i don't have v3 specific information but v2 is not available
            # so i should at least try against v3.
            return self._get_v3_password(v3_url)

        # so there were no URLs that i could use for auth of any version.
        # FIXME(jamielennox): raise something more appropriate
        raise exceptions.DiscoveryFailure()

    def get_auth_ref(self, session, **kwargs):
        if not self._plugin:
            self._plugin = self._get_plugin(session)

        return self._plugin.get_auth_ref(session, **kwargs)

    @classmethod
    def get_options(cls):
        options = super(Password, cls).get_options()

        options.extend([
            cfg.StrOpt('user-id', help='User ID'),
            cfg.StrOpt('user-name', dest='username', help='Username',
                       deprecated_name='username'),
            cfg.StrOpt('user-domain-id', help="User's domain id"),
            cfg.StrOpt('user-domain-name', help="User's domain name"),
            cfg.StrOpt('password', help="User's password"),
            cfg.StrOpt('domain-id', help='Domain ID to scope to'),
            cfg.StrOpt('domain-name', help='Domain name to scope to'),
            cfg.StrOpt('project-id', help='Project ID to scope to'),
            cfg.StrOpt('project-name', help='Project name to scope to'),
            cfg.StrOpt('project-domain-id',
                       help='Domain ID containing project'),
            cfg.StrOpt('project-domain-name',
                       help='Domain name containing project'),
            cfg.StrOpt('trust-id', help='Trust ID'),
        ])

        return options
