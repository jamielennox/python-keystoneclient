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
    def get_token(self):
        """Return a token.

        It is the auth plugin's responsibility to cache the token if required.
        """

    @abc.abstractmethod
    def get_endpoint(self, service=None, endpoint_type=None, **kwargs):
        """Return an endpoint for the client.

        The endpoint should reflect the type of service required, whether it
        should use the public, admin or private url.
        """

    @abc.abstractmethod
    def do_authenticate(self, session, **kwargs):
        """Authenticate and obtain a token.

        Authenticate does not have to return anything, it is considered
        successful if it does not raise any exceptions.

        Session should be provided wherever possible, otherwise a one time
        session will be constructed.

        Provided kwargs are passed through to the authentication call. There
        are no required or standard kwargs and are here to provide any extra
        information to the call.

        :param session: A session object so the plugin can make HTTP calls.
                        This parameter should be considered an optional
                        positional argument.
        """
