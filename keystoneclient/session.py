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

import requests
import six

from keystoneclient import exceptions
from keystoneclient.openstack.common import jsonutils

USER_AGENT = 'python-keystoneclient'

_logger = logging.getLogger(__name__)


def request(url, method='GET', **kwargs):
    return Session().request(url, method=method, **kwargs)


class Session(object):

    user_agent = None

    def __init__(self, auth=None, session=None, original_ip=None, verify=True,
                 cert=None, timeout=None, debug=False, user_agent=None):
        """Maintains client communication state and common functionality.

        As much as possible the parameters to this class reflect and are passed
        directly to the requests library.

        :param string original_ip: The original IP of the requesting user
                                   which will be sent to identity service in a
                                   'Forwarded' header. (optional)
        :param verify: The verification arguments to pass to requests. These
                       are of the same form as requests expects, so True or
                       False to verify (or not) against system certificates or
                       a path to a bundle or CA certs to check against.
                       (optional, defaults to True)
        :param cert: A client certificate to pass to requests. These are of the
                     same form as requests expects. Either a single filename
                     containing both the certificate and key or a tuple
                     containing the path to the certificate then a path to the
                     key. (optional)
        :param float timeout: A timeout to pass to requests. This should be a
                              numerical value indicating some amount
                              (or fraction) of seconds or 0 for no timeout.
                              (optional, defaults to 0)
        :param string user_agent: A User-Agent header string to use for the
                                  request. If not provided a default is used.
                                  (optional, defaults to
                                  'python-keystoneclient')
        """
        if not session:
            session = requests.Session()

        self.auth = auth
        self.session = session
        self.original_ip = original_ip
        self.verify = verify
        self.cert = cert
        self.timeout = None
        self.debug = debug

        if timeout is not None:
            self.timeout = float(timeout)

        # don't override the class variable if none provided
        if user_agent is not None:
            self.user_agent = user_agent

    def request(self, url, method, json=None, original_ip=None, debug=None,
                logger=None, user_agent=None, authenticated=None, **kwargs):
        """Send an HTTP request with the specified characteristics.

        Wrapper around `requests.Session.request` to handle tasks such as
        setting headers, JSON encoding/decoding, and error handling.

        Arguments that are not handled are passed through to the requests
        library.

        :param string url: Fully qualified URL of HTTP request
        :param string method: The http method to use. (eg. 'GET', 'POST')
        :param string original_ip: Mark this request as forwarded for this ip.
                                   (optional)
        :param dict headers: Headers to be included in the request. (optional)
        :param bool debug: Enable debug logging. (Defaults to False)
        :param kwargs: any other parameter that can be passed to
             requests.Session.request (such as `headers`) or `json`
             that will be encoded as JSON and used as `data` argument
        :param logging.Logger logger: A logger to output to. (optional)
        :param json: Some data to be represented as JSON. (optional)
        :param string user_agent: A user_agent to use for the request. If
                                  present will override one present in headers.
                                  (optional)

        :raises exceptions.ClientException: For connection failure, or to
                                            indicate an error response code.

        :returns: The response to the request.
        """

        headers = kwargs.setdefault('headers', dict())

        if authenticated is None:
            authenticated = self.auth is not None

        if authenticated:
            if not self.auth:
                raise exceptions.MissingAuthPlugin("Token Required")

            token = self.auth.get_token()

            if not token:
                raise exceptions.AuthorizationFailure("No token Available")

            headers['X-Auth-Token'] = token

        if self.cert:
            kwargs.setdefault('cert', self.cert)

        if self.timeout is not None:
            kwargs.setdefault('timeout', self.timeout)

        if user_agent:
            headers['User-Agent'] = user_agent
        elif self.user_agent:
            user_agent = headers.setdefault('User-Agent', self.user_agent)
        else:
            user_agent = headers.setdefault('User-Agent', USER_AGENT)

        if self.original_ip:
            headers.setdefault('Forwarded',
                               'for=%s;by=%s' % (self.original_ip, user_agent))

        if json is not None:
            headers['Content-Type'] = 'application/json'
            kwargs['data'] = jsonutils.dumps(json)

        if not logger:
            logger = _logger

        if debug is None:
            debug = self.debug

        kwargs.setdefault('verify', self.verify)

        if debug:
            string_parts = ['curl -i']

            if method:
                string_parts.extend([' -X ', method])

            string_parts.extend([' ', url])

            if headers:
                for header in six.iteritems(headers):
                    string_parts.append(' -H "%s: %s"' % header)

            logger.debug('REQ: %s', ''.join(string_parts))

            data = kwargs.get('data')
            if data:
                logger.debug('REQ BODY: %s', data)

        try:
            resp = self.session.request(method, url, **kwargs)
        except requests.exceptions.SSLError:
            msg = 'SSL exception connecting to %s' % url
            raise exceptions.SSLError(msg)
        except requests.exceptions.Timeout:
            msg = 'Request to %s timed out' % url
            raise exceptions.Timeout(msg)
        except requests.exceptions.ConnectionError:
            msg = 'Unable to establish connection to %s' % url
            raise exceptions.ConnectionError(msg)

        if debug:
            logger.debug('RESP: [%s] %s\nRESP BODY: %s\n',
                         resp.status_code, resp.headers, resp.text)

        if resp.status_code >= 400:
            logger.debug('Request returned failure status: %s',
                         resp.status_code)
            raise exceptions.from_response(resp, method, url)

        return resp

    def head(self, url, **kwargs):
        return self.request(url, 'HEAD', **kwargs)

    def get(self, url, **kwargs):
        return self.request(url, 'GET', **kwargs)

    def post(self, url, **kwargs):
        return self.request(url, 'POST', **kwargs)

    def put(self, url, **kwargs):
        return self.request(url, 'PUT', **kwargs)

    def delete(self, url, **kwargs):
        return self.request(url, 'DELETE', **kwargs)

    def patch(self, url, **kwargs):
        return self.request(url, 'PATCH', **kwargs)

    def do_authenticate(self, **kwargs):
        if not self.auth:
            raise exceptions.MissingAuthPlugin("No plugin to authenticate")

        kwargs['session'] = self
        return self.auth.do_authenticate(**kwargs)
