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

try:
    import keyring
    import pickle
except ImportError:
    keyring = None
    pickle = None


from keystoneclient import access
from keystoneclient.auth.identity import base
from keystoneclient.auth.identity import v2
from keystoneclient.auth.identity import v3
from keystoneclient import exceptions

_logger = logging.getLogger(__name__)


class AuthWrapper(base.IdentityBasePlugin):

    opt_names = ['username',
                 'password',
                 'auth_url',
                 'region_name',
                 'endpoint',
                 'token',
                 'user_id',
                 'user_domain_id',
                 'user_domain_name',
                 'domain_id',
                 'domain_name',
                 'project_id',
                 'project_name',
                 'project_domain_id',
                 'project_domain_name',
                 'trust_id']

    auth_class = None

    def __init__(self, use_keyring=False, force_new_token=False,
                 stale_duration=None, tenant_id=None,
                 tenant_name=None, **kwargs):
        """Construct a new http client

        :param string user_id: User ID for authentication. (optional)
        :param string username: Username for authentication. (optional)
        :param string user_domain_id: User's domain ID for authentication.
                                      (optional)
        :param string user_domain_name: User's domain name for authentication.
                                        (optional)
        :param string password: Password for authentication. (optional)
        :param string domain_id: Domain ID for domain scoping. (optional)
        :param string domain_name: Domain name for domain scoping. (optional)
        :param string project_id: Project ID for project scoping. (optional)
        :param string project_name: Project name for project scoping.
                                    (optional)
        :param string project_domain_id: Project's domain ID for project
                                         scoping. (optional)
        :param string project_domain_name: Project's domain name for project
                                           scoping. (optional)
        :param string auth_url: Identity service endpoint for authorization.
        :param string region_name: Name of a region to select when choosing an
                                   endpoint from the service catalog.
        :param string endpoint: A user-supplied endpoint URL for the identity
                                service.  Lazy-authentication is possible for
                                API service calls if endpoint is set at
                                instantiation. (optional)
        :param string token: Token for authentication. (optional)
        :param dict auth_ref: To allow for consumers of the client to manage
                              their own caching strategy, you may initialize a
                              client with a previously captured auth_reference
                              (token). If there are keyword arguments passed
                              that also exist in auth_ref, the value from the
                              argument will take precedence.
        :param boolean use_keyring: Enables caching auth_ref into keyring.
                                    default: False (optional)
        :param boolean force_new_token: Keyring related parameter, forces
                                       request for new token.
                                       default: False (optional)
        :param integer stale_duration: Gap in seconds to determine if token
                                       from keyring is about to expire.
                                       default: 30 (optional)
        :param string tenant_name: Tenant name. (optional)
                                   The tenant_name keyword argument is
                                   deprecated, use project_name instead.
        :param string tenant_id: Tenant id. (optional)
                                 The tenant_id keyword argument is
                                 deprecated, use project_id instead.
        :param string trust_id: Trust ID for trust scoping. (optional)

        """
        # set baseline defaults

        try:
            auth_ref = kwargs['auth_ref']
        except KeyError:
            pass
        else:
            auth_ref = access.AccessInfo.factory(**auth_ref)
            kwargs['auth_ref'] = auth_ref

            auth_ref_args = ['user_id', 'username', 'user_domain_id',
                             'domain_id', 'domain_name', 'project_id',
                             'project_name', 'project_domain_id',
                             'trust_id']

            self.version = auth_ref.version
            kwargs.setdefault('auth_url', auth_ref.auth_url[0])
            kwargs.setdefault('endpoint', auth_ref.management_url[0])
            kwargs.setdefault('token', auth_ref.auth_token)

            for arg in auth_ref_args:
                kwargs.setdefault(arg, getattr(auth_ref, arg))

        if not ('user_id' in kwargs or 'user_domain_name' in kwargs):
            kwargs.setdefault('user_domain_id', 'default')

        if not ('project_id' in kwargs or 'project_domain_name' in kwargs):
            kwargs.setdefault('project_domain_id', 'default')

        super(AuthWrapper, self).__init__(**kwargs)

        if self.auth_url:
            self.auth_url = self.auth_url.rstrip('/')
        if self.endpoint:
            self.endpoint = self.endpoint.rstrip('/')

        self.domain = ''

        # keyring setup
        if use_keyring and keyring is None:
            _logger.warning('Failed to load keyring modules.')
        self.use_keyring = use_keyring and keyring is not None
        self.force_new_token = force_new_token
        self.stale_duration = stale_duration or access.STALE_TOKEN_DURATION
        self.stale_duration = int(self.stale_duration)

    def get_endpoint(self, management=True, **kwargs):
        if not management:
            return self.auth_url

        if management and self.endpoint:
            return self.endpoint

        if management and not self.endpoint:
            raise exceptions.AuthorizationFailure(
                'Current authorization does not have a known management url')

        return self.endpoint

    def do_authenticate(self, session):
        return self._authenticate(session=session)

    def _authenticate(self, token=None, tenant_name=None, tenant_id=None,
                      session=None, password=None, **kwargs):
        """Authenticate user.

        Uses the data provided at instantiation to authenticate against
        the Identity server. This may use either a username and password
        or token for authentication. If a tenant name or id was provided
        then the resulting authenticated client will be scoped to that
        tenant and contain a service catalog of available endpoints.

        With the v2.0 API, if a tenant name or ID is not provided, the
        authentication token returned will be 'unscoped' and limited in
        capabilities until a fully-scoped token is acquired.

        With the v3 API, if a domain name or id was provided then the resulting
        authenticated client will be scoped to that domain. If a project name
        or ID is not provided, and the authenticating user has a default
        project configured, the authentication token returned will be 'scoped'
        to the default project. Otherwise, the authentication token returned
        will be 'unscoped' and limited in capabilities until a fully-scoped
        token is acquired.

        With the v3 API, with the OS-TRUST extension enabled, the trust_id can
        be provided to allow project-specific role delegation between users

        If successful, sets the self.auth_ref and self.auth_token with
        the returned token. If not already set, will also set
        self.endpoint from the details provided in the token.

        :returns: ``True`` if authentication was successful.
        :raises: AuthorizationFailure if unable to authenticate or validate
                 the existing authorization token
        :raises: ValueError if insufficient parameters are used.

        If keyring is used, token is retrieved from keyring instead.
        Authentication will only be necessary if any of the following
        conditions are met:

        * keyring is not used
        * if token is not found in keyring
        * if token retrieved from keyring is expired or about to
          expired (as determined by stale_duration)
        * if force_new_token is true

        """

        args = ['auth_url', 'user_id', 'username', 'user_domain_id',
                'user_domain_name', 'domain_id', 'domain_name', 'project_id',
                'project_name', 'project_domain_id', 'project_domain_name',
                'trust_id']

        if tenant_id:
            kwargs.setdefault('project_id', tenant_id)
        if tenant_name:
            kwargs.setdefault('project_name', tenant_name)

        identity_kwargs = dict([(arg, kwargs.get(arg) or self._opts.get(arg))
                                for arg in args])

        if not token:
            token = self.token
            if (not token and self.auth_ref and not
                    self.auth_ref.will_expire_soon(self.stale_duration)):
                token = self.auth_ref.auth_token

        identity_kwargs['token'] = token

        (keyring_key, auth_ref) = self.get_auth_ref_from_keyring(
            **identity_kwargs)
        new_token_needed = False
        if auth_ref is None or self.force_new_token:
            new_token_needed = True
            identity_kwargs['password'] = password or self.password
            self.auth_ref = self.get_raw_token_from_identity_service(
                session=session, **identity_kwargs)
        else:
            self.auth_ref = auth_ref
        self.process_token()
        if new_token_needed:
            self.store_auth_ref_into_keyring(keyring_key)
        return True

    def _build_keyring_key(self, **kwargs):
        """Create a unique key for keyring.

        Used to store and retrieve auth_ref from keyring.

        Returns a slash-separated string of values ordered by key name.

        """
        return '/'.join([kwargs[k] or '?' for k in sorted(kwargs.keys())])

    def get_auth_ref_from_keyring(self, **kwargs):
        """Retrieve auth_ref from keyring.

        If auth_ref is found in keyring, (keyring_key, auth_ref) is returned.
        Otherwise, (keyring_key, None) is returned.

        :returns: (keyring_key, auth_ref) or (keyring_key, None)
        :returns: or (None, None) if use_keyring is not set in the object

        """
        keyring_key = None
        auth_ref = None
        if self.use_keyring:
            keyring_key = self._build_keyring_key(**kwargs)
            try:
                auth_ref = keyring.get_password("keystoneclient_auth",
                                                keyring_key)
                if auth_ref:
                    auth_ref = pickle.loads(auth_ref)
                    if auth_ref.will_expire_soon(self.stale_duration):
                        # token has expired, don't use it
                        auth_ref = None
            except Exception as e:
                auth_ref = None
                _logger.warning('Unable to retrieve token from keyring %s' % (
                    e))
        return (keyring_key, auth_ref)

    def store_auth_ref_into_keyring(self, keyring_key):
        """Store auth_ref into keyring.

        """
        if self.use_keyring:
            try:
                keyring.set_password("keystoneclient_auth",
                                     keyring_key,
                                     pickle.dumps(self.auth_ref))
            except Exception as e:
                _logger.warning("Failed to store token into keyring %s" % (e))

    def process_token(self):
        """Extract and process information from the new auth_ref.

        And set the relevant authentication information.
        """
        # if we got a response without a service catalog, set the local
        # list of tenants for introspection, and leave to client user
        # to determine what to do. Otherwise, load up the service catalog
        if self.auth_ref.project_scoped:
            if not self.auth_ref.tenant_id:
                raise exceptions.AuthorizationFailure(
                    "Token didn't provide tenant_id")
            if self.endpoint is None and self.auth_ref.management_url:
                self.endpoint = self.auth_ref.management_url[0]
            self.project_name = self.auth_ref.tenant_name
            self.project_id = self.auth_ref.tenant_id

        if not self.auth_ref.user_id:
            raise exceptions.AuthorizationFailure(
                "Token didn't provide user_id")

        self.user_id = self.auth_ref.user_id

        self.auth_domain_id = self.auth_ref.domain_id
        self.auth_tenant_id = self.auth_ref.tenant_id
        self.auth_user_id = self.auth_ref.user_id

    def get_raw_token_from_identity_service(self, session=None, **kwargs):
        """Authenticate against the Identity API and get a token.

        Not implemented here because auth protocols should be API
        version-specific.

        Expected to authenticate or validate an existing authentication
        reference already associated with the client. Invoking this call
        *always* makes a call to the Identity service.

        :returns: (``resp``, ``body``)

        """
        if not self.auth_class:
            raise NotImplementedError

        kwargs = self.modify_auth_kwargs(**kwargs)

        auth_kwargs = dict([(k, v) for k, v in kwargs.iteritems()
                            if k in self.auth_class.opt_names])

        try:
            auth = self.auth_class(**auth_kwargs)
            auth.authenticate(session)
            return auth.auth_ref
        except (exceptions.AuthorizationFailure, exceptions.Unauthorized):
            _logger.debug('Authorization failed.')
            raise
        except Exception as e:
            raise exceptions.AuthorizationFailure('Authorization failed: '
                                                  '%s' % e)

    def modify_auth_kwargs(self, **kwargs):
        return kwargs


class V2Auth(AuthWrapper):

    auth_class = v2.Auth

    def modify_auth_kwargs(self, project_id=None, project_name=None, **kwargs):
        if project_name:
            kwargs['tenant_name'] = project_name
        if project_id:
            kwargs['tenant_id'] = project_id

        return super(V2Auth, self).modify_auth_kwargs(**kwargs)


class V3Auth(AuthWrapper):

    auth_class = v3.Auth

    def process_token(self):
        """Extract and process information from the new auth_ref.

        And set the relevant authentication information.
        """
        super(V3Auth, self).process_token()
        if self.auth_ref.domain_scoped:
            if not self.auth_ref.domain_id:
                raise exceptions.AuthorizationFailure(
                    "Token didn't provide domain_id")
            if not self.endpoint and self.auth_ref.management_url:
                self.endpoint = self.auth_ref.management_url[0]
            self.domain_name = self.auth_ref.domain_name
            self.domain_id = self.auth_ref.domain_id
