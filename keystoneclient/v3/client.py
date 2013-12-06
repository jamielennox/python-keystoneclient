# Copyright 2011 Nebula, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import logging

from keystoneclient.auth.identity import v3 as v3_auth
from keystoneclient import exceptions
from keystoneclient import httpclient
from keystoneclient.openstack.common import jsonutils
from keystoneclient.v3.contrib import trusts
from keystoneclient.v3 import credentials
from keystoneclient.v3 import domains
from keystoneclient.v3 import endpoints
from keystoneclient.v3 import groups
from keystoneclient.v3 import policies
from keystoneclient.v3 import projects
from keystoneclient.v3 import roles
from keystoneclient.v3 import services
from keystoneclient.v3 import users


_logger = logging.getLogger(__name__)


class Client(httpclient.HTTPClient):
    """Client for the OpenStack Identity API v3.

    :param string user_id: User ID for authentication. (optional)
    :param string username: Username for authentication. (optional)
    :param string user_domain_id: User's domain ID for authentication.
                                  (optional)
    :param string user_domain_name: User's domain name for authentication.
                                    (optional)
    :param string password: Password for authentication. (optional)
    :param string token: Token for authentication. (optional)
    :param string domain_id: Domain ID for domain scoping. (optional)
    :param string domain_name: Domain name for domain scoping. (optional)
    :param string project_id: Project ID for project scoping. (optional)
    :param string project_name: Project name for project scoping. (optional)
    :param string project_domain_id: Project's domain ID for project
                                     scoping. (optional)
    :param string project_domain_name: Project's domain name for project
                                       scoping. (optional)
    :param string tenant_name: Tenant name. (optional)
                               The tenant_name keyword argument is deprecated,
                               use project_name instead.
    :param string tenant_id: Tenant id. (optional)
                             The tenant_id keyword argument is deprecated,
                             use project_id instead.
    :param string auth_url: Identity service endpoint for authorization.
    :param string region_name: Name of a region to select when choosing an
                               endpoint from the service catalog.
    :param string endpoint: A user-supplied endpoint URL for the identity
                            service.  Lazy-authentication is possible for API
                            service calls if endpoint is set at
                            instantiation. (optional)
    :param integer timeout: Allows customization of the timeout for client
                            http requests. (optional)

    Example::

        >>> from keystoneclient.v3 import client
        >>> keystone = client.Client(user_domain_name=DOMAIN_NAME,
        ...                          username=USER,
        ...                          password=PASS,
        ...                          project_domain_name=PROJECT_DOMAIN_NAME,
        ...                          project_name=PROJECT_NAME,
        ...                          auth_url=KEYSTONE_URL)
        ...
        >>> keystone.projects.list()
        ...
        >>> user = keystone.users.get(USER_ID)
        >>> user.delete()

    """

    version = 'v3'

    def __init__(self, **kwargs):
        """Initialize a new client for the Keystone v3 API."""
        super(Client, self).__init__(**kwargs)

        self.credentials = credentials.CredentialManager(self)
        self.endpoints = endpoints.EndpointManager(self)
        self.domains = domains.DomainManager(self)
        self.groups = groups.GroupManager(self)
        self.policies = policies.PolicyManager(self)
        self.projects = projects.ProjectManager(self)
        self.roles = roles.RoleManager(self)
        self.services = services.ServiceManager(self)
        self.users = users.UserManager(self)
        self.trusts = trusts.TrustManager(self)

        if self.management_url is None:
            self.authenticate()

    def serialize(self, entity):
        return jsonutils.dumps(entity, sort_keys=True)

    def process_token(self):
        """Extract and process information from the new auth_ref.

        And set the relevant authentication information.
        """
        super(Client, self).process_token()
        if self.auth_ref.domain_scoped:
            if not self.auth_ref.domain_id:
                raise exceptions.AuthorizationFailure(
                    "Token didn't provide domain_id")
            if self.management_url is None and self.auth_ref.management_url:
                self.management_url = self.auth_ref.management_url[0]
            self.domain_name = self.auth_ref.domain_name
            self.domain_id = self.auth_ref.domain_id

    def get_raw_token_from_identity_service(self, session, auth_url, **kwargs):
        """Authenticate against the v3 Identity API.

        :returns: access.AccessInfo if authentication was successful.
        :raises: AuthorizationFailure if unable to authenticate or validate
                 the existing authorization token
        :raises: Unauthorized if authentication fails due to invalid token

        """
        try:
            auth = v3_auth.Auth(auth_url)
            auth.do_authenticate(session, **kwargs)
            return auth.auth_ref
        except (exceptions.AuthorizationFailure, exceptions.Unauthorized):
            _logger.debug('Authorization failed.')
            raise
        except Exception as e:
            raise exceptions.AuthorizationFailure('Authorization failed: '
                                                  '%s' % e)
