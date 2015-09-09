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

from keystoneclient import httpclient
from keystoneclient.v3 import auth
from keystoneclient.v3.contrib import endpoint_filter
from keystoneclient.v3.contrib import endpoint_policy
from keystoneclient.v3.contrib import federation
from keystoneclient.v3.contrib import oauth1
from keystoneclient.v3.contrib import simple_cert
from keystoneclient.v3.contrib import trusts
from keystoneclient.v3 import credentials
from keystoneclient.v3 import domains
from keystoneclient.v3 import ec2
from keystoneclient.v3 import endpoints
from keystoneclient.v3 import groups
from keystoneclient.v3 import policies
from keystoneclient.v3 import projects
from keystoneclient.v3 import regions
from keystoneclient.v3 import role_assignments
from keystoneclient.v3 import roles
from keystoneclient.v3 import services
from keystoneclient.v3 import tokens
from keystoneclient.v3 import users


class Client(httpclient.HTTPClient):
    """Client for the OpenStack Identity API v3."""

    version = 'v3'

    def __init__(self, **kwargs):
        """Initialize a new client for the Keystone v3 API."""
        super(Client, self).__init__(**kwargs)

        self.auth = auth.AuthManager(self._adapter)
        self.credentials = credentials.CredentialManager(self._adapter)
        self.ec2 = ec2.EC2Manager(self._adapter)
        self.endpoint_filter = endpoint_filter.EndpointFilterManager(
            self._adapter)
        self.endpoint_policy = endpoint_policy.EndpointPolicyManager(
            self._adapter)
        self.endpoints = endpoints.EndpointManager(self._adapter)
        self.domains = domains.DomainManager(self._adapter)
        self.federation = federation.FederationManager(self._adapter)
        self.groups = groups.GroupManager(self._adapter)
        self.oauth1 = oauth1.create_oauth_manager(self._adapter)
        self.policies = policies.PolicyManager(self._adapter)
        self.projects = projects.ProjectManager(self._adapter)
        self.regions = regions.RegionManager(self._adapter)
        self.role_assignments = (
            role_assignments.RoleAssignmentManager(self._adapter))
        self.roles = roles.RoleManager(self._adapter)
        self.services = services.ServiceManager(self._adapter)
        self.simple_cert = simple_cert.SimpleCertManager(self._adapter)
        self.tokens = tokens.TokenManager(self._adapter)
        self.trusts = trusts.TrustManager(self._adapter)
        self.users = users.UserManager(self._adapter)
