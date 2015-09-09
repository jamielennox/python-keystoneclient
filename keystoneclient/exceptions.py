# Copyright 2010 Jacob Kaplan-Moss
# Copyright 2011 Nebula, Inc.
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
"""Exception definitions."""

from keystoneauth1 import exceptions
from keystoneclient.i18n import _


ClientException = exceptions.ClientException


class ValidationError(ClientException):
    """Error in validation on API client side."""
    pass


class UnsupportedVersion(ClientException):
    """User is trying to use an unsupported version of the API."""
    pass


class CommandError(ClientException):
    """Error in CLI tool."""
    pass


class AuthorizationFailure(ClientException):
    """Cannot authorize API client."""
    pass


class ConnectionError(ClientException):
    """Cannot connect to API service."""
    pass


class ConnectionRefused(ConnectionError):
    """Connection refused while trying to connect to API service."""
    pass


class NoUniqueMatch(ClientException):
    """Multiple entities found instead of one."""
    pass


class CertificateConfigError(Exception):
    """Error reading the certificate."""
    def __init__(self, output):
        self.output = output
        msg = _('Unable to load certificate.')
        super(CertificateConfigError, self).__init__(msg)


class CMSError(Exception):
    """Error reading the certificate."""
    def __init__(self, output):
        self.output = output
        msg = _('Unable to sign or verify data.')
        super(CMSError, self).__init__(msg)


class SSLError(ConnectionRefused):
    """An SSL error occurred."""


class DiscoveryFailure(ClientException):
    """Discovery of client versions failed."""


class VersionNotAvailable(DiscoveryFailure):
    """Discovery failed as the version you requested is not available."""


class MethodNotImplemented(ClientException):
    """Method not implemented by the keystoneclient API."""


class MissingAuthPlugin(ClientException):
    """An authenticated request is required but no plugin available."""


class NoMatchingPlugin(ClientException):
    """There were no auth plugins that could be created from the parameters
    provided.

    :param str name: The name of the plugin that was attempted to load.

    .. py:attribute:: name

        The name of the plugin that was attempted to load.
    """

    def __init__(self, name):
        self.name = name
        msg = _('The plugin %s could not be found') % name
        super(NoMatchingPlugin, self).__init__(msg)


class UnsupportedParameters(ClientException):
    """A parameter that was provided or returned is not supported.

    :param list(str) names: Names of the unsupported parameters.

    .. py:attribute:: names

        Names of the unsupported parameters.
    """

    def __init__(self, names):
        self.names = names

        m = _('The following parameters were given that are unsupported: %s')
        super(UnsupportedParameters, self).__init__(m % ', '.join(self.names))


class InvalidResponse(ClientException):
    """The response from the server is not valid for this request."""

    def __init__(self, response):
        super(InvalidResponse, self).__init__()
        self.response = response
