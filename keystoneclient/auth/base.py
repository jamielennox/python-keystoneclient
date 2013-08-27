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

from keystoneclient import session as client_session


class BaseAuthPlugin(object):
    """The basic structure of an authentication plugin."""

    opt_names = []

    def __init__(self, **kwargs):
        self._opts = dict()
        for k, v in kwargs.iteritems():
            if k in self.opt_names:
                self._opts[k] = v
            else:
                raise TypeError("Unexpected keyword argument '%s'" % k)

    def __getattr__(self, name):
        if name in self.opt_names:
            return self._opts.get(name)
        else:
            raise AttributeError("No attribute named: '%s'" % name)

    def __setattr__(self, name, val):
        if name in self.opt_names:
            self._opts[name] = val
        else:
            super(BaseAuthPlugin, self).__setattr__(name, val)

    def __delattr__(self, name):
        if name in self.opt_names:
            try:
                del self._opts[name]
            except KeyError:
                raise AttributeError("No such Attribute: %s" % name)
        else:
            super(BaseAuthPlugin, self).__delattr__(name)

    def get_token(self):
        """Return a token.

        It is the auth plugin's responsibility to cache the token if required.
        """

        raise NotImplementedError

    def get_endpoint(self, **kwargs):
        """Return an endpoint for the client.

        The endpoint should reflect the type of service required, whether it
        should use the public, admin or private url.
        """

        raise NotImplementedError

    def authenticate(self, session=None):
        """Authenticate and obtain a token.

        Authenticate does not have to return anything, it is considered
        successful if it does not raise any exceptions.

        :param session: A session object so the plugin can make HTTP calls.
        """

        if not session:
            session = client_session.ClientSession()

        return self.do_authenticate(session)

    def do_authenticate(self, session):
        raise NotImplementedError

    @property
    def is_authenticated(self):
        """True if there is a currently valid token.
        """
        raise NotImplementedError
