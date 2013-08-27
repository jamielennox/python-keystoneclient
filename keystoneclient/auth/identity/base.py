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

from keystoneclient.auth import base
from keystoneclient import exceptions

_logger = logging.getLogger(__name__)


class IdentityBasePlugin(base.BaseAuthPlugin):

    def __init__(self, auth_ref=None, **kwargs):
        super(IdentityBasePlugin, self).__init__(**kwargs)
        self.auth_ref = auth_ref

    @property
    def is_authenticated(self):
        if self.endpoint and self.token:
            return True

        if not self.auth_ref:
            return False

        return not self.auth_ref.will_expire_soon()

    def get_token(self):
        if not self.is_authenticated:
            raise exceptions.NoAuthentication

        if self.token:
            return self.token

        if self.auth_ref:
            return self.auth_ref.auth_token

    def get_endpoint(self, **kwargs):
        if not self.is_authenticated:
            raise exceptions.NoAuthentication

        if self.endpoint:
            return self.endpoint

        if self.auth_ref.management_url:
            return self.auth_ref.management_url[0]

    @classmethod
    def _request(cls, session, url, method, **kwargs):
        resp = session.request(url, method, **kwargs)

        if resp.status_code in (301, 302, 305) and 'location' in resp.headers:
            # Redirected. Reissue the request to the new location.
            resp = cls._request(session, resp.headers['location'],
                                method, **kwargs)

        return resp
