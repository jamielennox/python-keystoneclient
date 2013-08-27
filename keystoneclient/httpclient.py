# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 Jacob Kaplan-Moss
# Copyright 2011 OpenStack LLC.
# Copyright 2011 Piston Cloud Computing, Inc.
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
"""
OpenStack Client interface. Handles the REST calls and responses.
"""

import logging
import urlparse

# Python 2.5 compat fix
if not hasattr(urlparse, 'parse_qsl'):
    import cgi
    urlparse.parse_qsl = cgi.parse_qsl


from keystoneclient.auth import _legacy
from keystoneclient import base
from keystoneclient.openstack.common import jsonutils
from keystoneclient import session as client_session
from keystoneclient import utils


_logger = logging.getLogger(__name__)

# deprecated moves
USER_AGENT = client_session.USER_AGENT
request = client_session.request


class HTTPClient(base.BaseClient):

    deprecated_identity_variables = (_legacy.AuthWrapper.opt_names +
                                     ['auth_ref',
                                      # related to token caching
                                      'stale_duration',
                                      'force_new_token',
                                      'use_keyring'])

    # NOTE(jamielennox): deprecated session lists are different as what is
    # accepted as a kwarg is not the same as how it is saved on the object.
    deprecated_session_variables = ['original_ip',
                                    'cert',
                                    'timeout',
                                    'verify',
                                    'debug',
                                    'auth_plugin']

    deprecated_session_kwargs = ['cacert',
                                 'insecure',
                                 'timeout',
                                 'cert',
                                 'key',
                                 'debug',
                                 'original_ip']

    deprecated_identity_others = [
        # token fetching and authentication
        'process_token',

        # keyring functions, for testing purposes
        '_build_keyring_key',
        'get_auth_ref_from_keyring',
        'store_auth_ref_into_keyring',

        # process_token sets variables, used by shell
        'auth_domain_id',
        'auth_tenant_id',
        'auth_user_id',

        # appears to be completely unused
        'domain'
    ]

    legacy_auth_wrapper = _legacy.AuthWrapper

    def __init__(self, session=None, tenant_id=None, tenant_name=None,
                 **kwargs):
        """Construct a new http client

        :param session: A ClientSession object to use for communication.
        """
        # extract connection parameters out of kwargs before passing to auth.

        identity_kwargs = dict()
        session_kwargs = dict()

        if tenant_id:
            kwargs.setdefault('project_id', tenant_id)
        if tenant_name:
            kwargs.setdefault('project_name', tenant_name)

        for arg in kwargs.keys():
            if arg in self.deprecated_identity_variables:
                identity_kwargs[arg] = kwargs.pop(arg)
            elif arg in self.deprecated_session_kwargs:
                session_kwargs[arg] = kwargs.pop(arg)

        if not session:
            session_kwargs['auth_plugin'] = self.legacy_auth_wrapper(
                **identity_kwargs)

            session_kwargs['verify'] = session_kwargs.pop('cacert', True)
            if session_kwargs.pop('insecure', False):
                session_kwargs['verify'] = False

            cert = session_kwargs.pop('cert', None)
            key = session_kwargs.pop('key', None)

            if cert and key:
                session_kwargs['cert'] = (cert, key)
            elif cert:
                _logger.warn("Client cert was provided without corresponding "
                             "key. Ignoring.")

            session = client_session.ClientSession(**session_kwargs)
        else:
            if identity_kwargs:
                _logger.info("Can't use both identity arguments and a "
                             "session. Ignoring arguments: %s",
                             ",".join(identity_kwargs.keys()))

            if session_kwargs:
                _logger.info("Can't use both session arguments and a "
                             "session. Ignoring arguments: %s",
                             ",".join(session_kwargs.keys()))

        super(HTTPClient, self).__init__(session)

        # logging setup
        # TODO(jamielennox): where should this live now?
        self.debug_log = self.session.debug
        if self.debug_log and not _logger.handlers:
            ch = logging.StreamHandler()
            _logger.setLevel(logging.DEBUG)
            _logger.addHandler(ch)
            if hasattr(requests, 'logging'):
                requests.logging.getLogger(requests.__name__).addHandler(ch)

    def __getattr__(self, name):
        if name in self.deprecated_identity_variables or \
                name in self.deprecated_identity_others:
            utils.deprecated_msg(name, "It can be accessed from auth_plugin")
            return getattr(self.session.auth_plugin, name)
        elif name in self.deprecated_session_variables:
            utils.deprecated_msg(name, "It can be accessed from session")
            return getattr(self.session, name)
        else:
            raise AttributeError("Unknown Attribute: %s" % name)

    def __setattr__(self, name, val):
        if name in self.deprecated_identity_variables or \
                name in self.deprecated_identity_others:
            utils.deprecated_msg(name, "It can be accessed from auth_plugin")
            setattr(self.session.auth_plugin, name, val)
        elif name in self.deprecated_session_variables:
            utils.deprecated_msg(name, "It can be accessed from session")
            setattr(self.session, name)
        else:
            super(HTTPClient, self).__setattr__(name, val)

    @property
    @utils.deprecated
    def verify_cert(self):
        return self.session.verify

    @verify_cert.setter
    @utils.deprecated
    def verify_cert(self, value):
        self.session.verify = value

    @property
    @utils.deprecated
    def management_url(self):
        return self.auth_plugin.endpoint

    @management_url.setter
    @utils.deprecated
    def management_url(self, val):
        self.auth_plugin.endpoint = val

    @property
    @utils.deprecated
    def auth_token(self):
        if not self.session.auth_plugin.is_authenticated:
            self.session.authenticate()

        return self.session.auth_plugin.get_token()

    @auth_token.setter
    @utils.deprecated
    def auth_token(self, value):
        self.session.auth_plugin.token = value

    @auth_token.deleter
    @utils.deprecated
    def auth_token(self):
        del self.session.auth_plugin.token

    @property
    @utils.deprecated
    def tenant_id(self):
        """Provide read-only backwards compatibility for tenant_id.
           This is deprecated, use project_id instead.
        """
        return self.project_id

    @property
    @utils.deprecated
    def tenant_name(self):
        """Provide read-only backwards compatibility for tenant_name.
           This is deprecated, use project_name instead.
        """
        return self.project_name

    def authenticate(self, **kwargs):
        return self.session.auth_plugin._authenticate(session=self.session,
                                                      **kwargs)

    @utils.deprecated
    def get_raw_token_from_identity_service(self, auth_url, **kwargs):
        kwargs['auth_url'] = auth_url
        return self.session.auth_plugin.get_raw_token_from_identity_service(
            session=self.session, **kwargs)

    @utils.deprecated
    def serialize(self, entity):
        return jsonutils.dumps(entity)

    @property
    @utils.deprecated
    def service_catalog(self):
        """Returns this client's service catalog."""
        return self.auth_ref.service_catalog

    @utils.deprecated
    def has_service_catalog(self):
        """Returns True if this client provides a service catalog."""
        return self.auth_ref.has_service_catalog()

    @staticmethod
    def _decode_body(resp):
        if resp.text:
            try:
                body_resp = jsonutils.loads(resp.text)
            except (ValueError, TypeError):
                body_resp = None
                _logger.debug("Could not decode JSON from body: %s"
                              % resp.text)
        else:
            _logger.debug("No body was returned.")
            body_resp = None

        return body_resp

    @utils.deprecated
    def request(self, url, method, **kwargs):
        """Send an http request with the specified characteristics.

        Wrapper around requests.request to handle tasks such as
        setting headers, JSON encoding/decoding, and error handling.
        """
        try:
            kwargs['json'] = kwargs.pop('body')
        except KeyError:
            pass

        resp = self.session.request(url, method, **kwargs)

        # NOTE(jamielennox): The requests lib will handle the majority of
        # redirections. Where it fails is when POSTs are redirected which
        # is apparently something handled differently by each browser which
        # requests forces us to do the most compliant way (which we don't want)
        # see: https://en.wikipedia.org/wiki/Post/Redirect/Get
        if resp.status_code in (301, 302, 305):
            # Redirected. Reissue the request to the new location.
            return self.request(resp.headers['location'], method, **kwargs)

        return resp, self._decode_body(resp)

    def _cs_request(self, url, method, **kwargs):
        """Makes an authenticated request to keystone endpoint by
        concatenating self.management_url and url and passing in method and
        any associated kwargs.

        This is only left here because test code relies upon stubbing this
        method.
        """
        resp = self.client_request(url, method, **kwargs)
        return resp, self._decode_body(resp)

    def client_request(self, url, method, **kwargs):
        try:
            kwargs['json'] = kwargs.pop('body')
        except KeyError:
            pass

        kwargs.setdefault('authenticated', True)
        resp = super(HTTPClient, self).client_request(url, method, **kwargs)

        if resp.status_code in (301, 302, 305):
            # Redirected. Reissue the request to the new location.
            resp = self.client_request(resp.headers['location'],
                                       method, **kwargs)

        return resp

    @utils.deprecated
    def get(self, url, **kwargs):
        return self._cs_request(url, 'GET', **kwargs)

    @utils.deprecated
    def head(self, url, **kwargs):
        return self._cs_request(url, 'HEAD', **kwargs)

    @utils.deprecated
    def post(self, url, **kwargs):
        return self._cs_request(url, 'POST', **kwargs)

    @utils.deprecated
    def put(self, url, **kwargs):
        return self._cs_request(url, 'PUT', **kwargs)

    @utils.deprecated
    def patch(self, url, **kwargs):
        return self._cs_request(url, 'PATCH', **kwargs)

    @utils.deprecated
    def delete(self, url, **kwargs):
        return self._cs_request(url, 'DELETE', **kwargs)
