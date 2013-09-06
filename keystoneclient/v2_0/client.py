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

from keystoneclient.auth import _legacy
from keystoneclient import httpclient
from keystoneclient.v2_0 import ec2
from keystoneclient.v2_0 import endpoints
from keystoneclient.v2_0 import roles
from keystoneclient.v2_0 import services
from keystoneclient.v2_0 import tenants
from keystoneclient.v2_0 import tokens
from keystoneclient.v2_0 import users


_logger = logging.getLogger(__name__)


class Client(httpclient.HTTPClient):
    """Client for the OpenStack Keystone v2.0 API.

    :param session: A ClientSession object for communication. (optional)
    :param string username: Username for authentication. (optional)
    :param string password: Password for authentication. (optional)
    :param string token: Token for authentication. (optional)
    :param string tenant_id: Tenant id. (optional)
    :param string tenant_name: Tenant name. (optional)
    :param string auth_url: Keystone service endpoint for authorization.
    :param string region_name: Name of a region to select when choosing an
                               endpoint from the service catalog.
    :param string endpoint: A user-supplied endpoint URL for the keystone
                            service.  Lazy-authentication is possible for API
                            service calls if endpoint is set at
                            instantiation.(optional)
    :param integer timeout: Allows customization of the timeout for client
                            http requests. (optional)
    :param string original_ip: The original IP of the requesting user
                               which will be sent to Keystone in a
                               'Forwarded' header. (optional)
    :param string cert: Path to the Privacy Enhanced Mail (PEM) file which
                        contains the corresponding X.509 client certificate
                        needed to established two-way SSL connection with
                        the identity service. (optional)
    :param string key: Path to the Privacy Enhanced Mail (PEM) file which
                       contains the unencrypted client private key needed
                       to established two-way SSL connection with the
                      identity service. (optional)
    :param string cacert: Path to the Privacy Enhanced Mail (PEM) file which
                          contains the trusted authority X.509 certificates
                          needed to established SSL connection with the
                          identity service. (optional)
    :param boolean insecure: Does not perform X.509 certificate validation
                             when establishing SSL connection with identity
                             service. default: False (optional)
    :param dict auth_ref: To allow for consumers of the client to manage their
                          own caching strategy, you may initialize a client
                          with a previously captured auth_reference (token)
    :param boolean debug: Enables debug logging of all request and responses
                          to keystone. default False (option)

    .. warning::

    If debug is enabled, it may show passwords in plain text as a part of its
    output.


    The client can be created and used like a user or in a strictly
    bootstrap mode. Normal operation expects a username, password, auth_url,
    and tenant_name or id to be provided. Other values will be lazily loaded
    as needed from the service catalog.

    Example::

        >>> from keystoneclient.v2_0 import client
        >>> keystone = client.Client(username=USER,
        ...                          password=PASS,
        ...                          tenant_name=TENANT_NAME,
        ...                          auth_url=KEYSTONE_URL)
        >>> keystone.tenants.list()
        ...
        >>> user = keystone.users.get(USER_ID)
        >>> user.delete()

    Once authenticated, you can store and attempt to re-use the
    authenticated token. the auth_ref property on the client
    returns as a dictionary-like-object so that you can export and
    cache it, re-using it when initiating another client::

        >>> from keystoneclient.v2_0 import client
        >>> keystone = client.Client(username=USER,
        ...                          password=PASS,
        ...                          tenant_name=TENANT_NAME,
        ...                          auth_url=KEYSTONE_URL)
        >>> auth_ref = keystone.auth_ref
        >>> # pickle or whatever you like here
        >>> new_client = client.Client(auth_ref=auth_ref)

    Alternatively, you can provide the administrative token configured in
    keystone and an endpoint to communicate with directly. See
    (``admin_token`` in ``keystone.conf``) In this case, authenticate()
    is not needed, and no service catalog will be loaded.

    Example::

        >>> from keystoneclient.v2_0 import client
        >>> admin_client = client.Client(
        ...     token='12345secret7890',
        ...     endpoint='http://localhost:35357/v2.0')
        >>> keystone.tenants.list()

    """

    version = 'v2.0'
    legacy_auth_wrapper = _legacy.V2Auth

    def __init__(self, session=None, **kwargs):
        """Initialize a new client for the Keystone v2.0 API."""
        super(Client, self).__init__(session=session, **kwargs)

        self.endpoints = endpoints.EndpointManager(self)
        self.roles = roles.RoleManager(self)
        self.services = services.ServiceManager(self)
        self.tenants = tenants.TenantManager(self)
        self.tokens = tokens.TokenManager(self)
        self.users = users.UserManager(self)

        # extensions
        self.ec2 = ec2.CredentialsManager(self)

        if not session and not self.endpoint:
            self.authenticate()
