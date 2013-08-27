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

from keystoneclient import exceptions
from keystoneclient.openstack.common import jsonutils
from keystoneclient import utils

USER_AGENT = 'python-keystoneclient'

_logger = logging.getLogger(__name__)


def request(url, method='GET', headers=None, original_ip=None, debug=False,
            logger=None, json=None, **kwargs):
    """Perform a http request with standard settings.

    A wrapper around requests.request that adds standard headers like
    User-Agent and provides optional debug logging of the request.

    Arguments that are not handled are passed through to the requests library.

    :param string url: The url to make the request of.
    :param string method: The http method to use. (eg. 'GET', 'POST')
    :param dict headers: Headers to be included in the request. (optional)
    :param string original_ip: Mark this request as forwarded for this ip.
                               (optional)
    :param bool debug: Enable debug logging. (Defaults to False)
    :param logging.Logger logger: A logger to output to. (optional)
    :param json data: Some data to be represented as json. (optional)

    :raises exceptions.ClientException: For connection failure, or to indicate
                                        an error response code.

    :returns: The response to the request.
    """

    if not headers:
        headers = dict()

    if not logger:
        logger = _logger

    user_agent = headers.setdefault('User-Agent', USER_AGENT)

    if original_ip:
        headers['Forwarded'] = "for=%s;by=%s" % (original_ip, user_agent)

    if json is not None:
        headers['Content-Type'] = 'application/json'
        kwargs['data'] = jsonutils.dumps(json)

    if debug:
        string_parts = ['curl -i']

        if method:
            string_parts.append(' -X %s' % method)

        string_parts.append(' %s' % url)

        if headers:
            for header in headers.iteritems():
                string_parts.append(' -H "%s: %s"' % header)

        logger.debug("REQ: %s" % "".join(string_parts))

        data = kwargs.get('data')
        if data:
            logger.debug("REQ BODY: %s\n" % data)

    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            **kwargs)
    except requests.ConnectionError:
        msg = 'Unable to establish connection to %s' % url
        raise exceptions.ClientException(msg)

    if debug:
        logger.debug("RESP: [%s] %s\nRESP BODY: %s\n",
                     resp.status_code, resp.headers, resp.text)

    if resp.status_code >= 400:
        logger.debug("Request returned failure status: %s",
                     resp.status_code)
        raise exceptions.from_response(resp, method, url)

    return resp


class ClientSession(object):

    user_agent = None

    def __init__(self, auth_plugin=None, original_ip=None, verify=True,
                 cert=None, timeout=None, debug=False, user_agent=None):
        """A simple class which holds the basic request information.

        As much as possible the parameters to this class reflect and are passed
        directly to the requests library.

        :param auth_plugin: An object providing token and endpoints
                            authentication for the session.
        :param string original_ip: The original IP of the requesting user
                                   which will be sent to identity service in a
                                   'Forwarded' header. (optional)
        :param verify: The verification arguments to pass to requests. These
                       are of the same form as requests expects, so True or
                       False to verify (or not) against system certificates or
                       a path to a bundle or CA certs to check against.
        :param cert: A client certificate to pass to requests. These are of the
                     same form as requests expects. Either a single file
                     containing both the certificate and key or a tuple
                     containing the path to the certificate then a path to the
                     key.
        :timeout: A timeout to pass to requests. This should be a numerical
                  value indicating some amount (or fraction) of seconds.
        """
        self.auth_plugin = auth_plugin
        self.original_ip = original_ip
        self.verify = verify
        self.cert = cert
        self.timeout = None
        if timeout is not None:
            self.timeout = float(timeout)
        self.debug = debug

        # don't override the class variable if none provided
        if user_agent:
            self.user_agent = user_agent

    def request(self, url, method, authenticated=False, **kwargs):
        """Send an http request with the specified characteristics.

        Wrapper around `requests.Session.request` to handle tasks such as
        setting headers, JSON encoding/decoding, and error handling.

        :param string url: URL of HTTP request
        :param string method: method of HTTP request
        :param bool authenticated: True if the request should contain a token.
                                   (optional)
        :param kwargs: any other parameter that can be passed to
'            requests.Session.request (such as `headers`) or `json`
             that will be encoded as JSON and used as `data` argument
        """
        if self.user_agent:
            headers = kwargs.setdefault('headers', {})
            headers.setdefault('User-Agent', self.user_agent)
        if self.cert:
            kwargs.setdefault('cert', self.cert)
        if self.timeout is not None:
            kwargs.setdefault('timeout', self.timeout)
        if self.original_ip:
            kwargs.setdefault('original_ip', self.original_ip)
        if authenticated:
            if not self.auth_plugin:
                raise TypeError("An auth_plugin needs to be provided to "
                                "make authenticated requests")

            headers = kwargs.setdefault('headers', {})
            headers.setdefault('X-Auth-Token', self.auth_plugin.get_token())

        kwargs.setdefault('verify', self.verify)
        kwargs.setdefault('debug', self.debug)

        return request(url, method=method, **kwargs)

    def client_request(self, client, path, method, management=True, **kwargs):
        """Make a request on behalf of a client.

        The endpoint will be resolved from the catalog taking information from
        kwargs and the client.

        :param client: The client that wants to make the request.
        :param path: A URL segment that the client wants to access.
        :param method: The HTTP method to use.
        :param management: If this is a management operation. (optional)
        """
        if not self.auth_plugin:
            raise TypeError("An auth_plugin needs to be provided to the "
                            "session to make client requests")

        endpoint = self.auth_plugin.get_endpoint(management=management)
        url = utils.join_url(endpoint, path)
        kwargs.setdefault('authenticated', True)
        return self.request(url, method, **kwargs)

    def authenticate(self):
        """Convenience function to call the current auth plugin's authenticate
        using the current session for communicating
        """
        return self.auth_plugin.authenticate(self)

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
