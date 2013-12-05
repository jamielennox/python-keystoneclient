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

import abc
import six


@six.add_metaclass(abc.ABCMeta)
class BaseAuthPlugin(object):
    """The basic structure of an authentication plugin."""

    @abc.abstractmethod
    def get_token(self, session):
        """Obtain a token.

        How the token is obtained is up to the plugin. If it is still valid
        it may be re-used, retrieved from cache or invoke an authentication
        request against a server.
        """

    @abc.abstractmethod
    def get_endpoint(self, session, service_type=None,
                     endpoint_type=None, **kwargs):
        """Return an endpoint for the client.

        The endpoint should reflect the type of service required, whether it
        should use the public, admin or private url.

        :param Session session: The session object that the auth_plugin
                                belongs to. (optional)
        :param string service_type: The service type to query the URL for.
                                    (optional)
        :param string endpoint_type: The endpoint type to query a URL for.
                                     (optional)
        """
