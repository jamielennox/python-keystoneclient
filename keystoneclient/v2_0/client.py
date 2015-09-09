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

from keystoneclient import httpclient
from keystoneclient.v2_0 import certificates
from keystoneclient.v2_0 import ec2
from keystoneclient.v2_0 import endpoints
from keystoneclient.v2_0 import extensions
from keystoneclient.v2_0 import roles
from keystoneclient.v2_0 import services
from keystoneclient.v2_0 import tenants
from keystoneclient.v2_0 import tokens
from keystoneclient.v2_0 import users


_logger = logging.getLogger(__name__)


class Client(httpclient.HTTPClient):
    """Client for the OpenStack Keystone v2.0 API.
    """

    version = 'v2.0'

    def __init__(self, **kwargs):
        super(Client, self).__init__(**kwargs)

        self.certificates = certificates.CertificatesManager(self._adapter)
        self.endpoints = endpoints.EndpointManager(self._adapter)
        self.extensions = extensions.ExtensionManager(self._adapter)
        self.roles = roles.RoleManager(self._adapter)
        self.services = services.ServiceManager(self._adapter)
        self.tokens = tokens.TokenManager(self._adapter)
        self.users = users.UserManager(self._adapter, self.roles)

        self.tenants = tenants.TenantManager(self._adapter,
                                             self.roles, self.users)

        # extensions
        self.ec2 = ec2.CredentialsManager(self._adapter)
