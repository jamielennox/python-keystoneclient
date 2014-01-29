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
import logging
import six

from keystoneclient.auth import base

LOG = logging.getLogger(__name__)


def _trim_path(url):
    url_parts = list(urlparse.urlsplit(url))
    path_parts = filter(None, url_parts[2].split('/'))

    if path_parts:
        url_parts[2] = '/'.join(path_parts[:-1])
        return urlparse.urlunsplit(url_parts)


@six.add_metaclass(abc.ABCMeta)
class BaseIdentityPlugin(base.BaseAuthPlugin):

    def __init__(self,
                 auth_url=None,
                 username=None,
                 password=None,
                 token=None,
                 trust_id=None):

        super(BaseIdentityPlugin, self).__init__()

        self.auth_url = auth_url
        self.username = username
        self.password = password
        self.token = token
        self.trust_id = trust_id

        self.auth_ref = None
        self._endpoint_cache = {}

    @abc.abstractmethod
    def get_auth_ref(self, session):
        """Obtain a token from an OpenStack Identity Service.

        This method is overridden by the various token version plugins.

        This function should not be called independently and is expected to be
        invoked via the do_authenticate function.

        :returns AccessInfo: Token access information.
        """

    def current_auth_ref(self, session):
        if not self.auth_ref or self.auth_ref.will_expire_soon(1):
            self.auth_ref = self.get_auth_ref(session)

        return self.auth_ref

    def get_token(self, session):
        return self.current_auth_ref(session).auth_token

    def get_endpoint(self, session, service_type=None, endpoint_type=None,
                     endpoint_version=None, region_name=None, unstable=False,
                     **kwargs):
        if not endpoint_type:
            endpoint_type = 'public'

        url = self.current_auth_ref(session).service_catalog.url_for(
            service_type=service_type,
            endpoint_type=endpoint_type,
            region_name=region_name)

        endpoint_data = None
        try:
            endpoint_data = self._endpoint_cache[url]
        except KeyError:
            try:
                endpoint_data = discover.SimpleDiscover(session, url)
            except DiscoveryFailure:
                new_url = _trim_path(url)
                if new_url:
                    endpoint_data = discover.SimpleDiscover(session, new_url)
                    self._endpoint_cache[new_url] = endpoint_data

            self._endpoint_cache[url] = endpoint_data

        data = endpoint_data._get_endpoint_version(version=endpoint_version,
                                                   unstable=unstable)
        return data['url']
