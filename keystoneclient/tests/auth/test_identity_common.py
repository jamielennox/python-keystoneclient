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
import datetime
import uuid

import httpretty
import six

from keystoneclient import access
from keystoneclient.auth.identity import v2
from keystoneclient.auth.identity import v3
from keystoneclient import fixture
from keystoneclient.openstack.common import jsonutils
from keystoneclient.openstack.common import timeutils
from keystoneclient import session
from keystoneclient.tests import utils


@six.add_metaclass(abc.ABCMeta)
class CommonIdentityTests(object):

    TEST_ROOT_URL = 'http://127.0.0.1:5000/'
    TEST_ROOT_ADMIN_URL = 'http://127.0.0.1:35357/'

    TEST_COMPUTE_PUBLIC = 'http://nova/novapi/public'
    TEST_COMPUTE_INTERNAL = 'http://nova/novapi/internal'
    TEST_COMPUTE_ADMIN = 'http://nova/novapi/admin'

    TEST_PASS = uuid.uuid4().hex

    def setUp(self):
        super(CommonIdentityTests, self).setUp()

        httpretty.reset()
        httpretty.enable()
        self.addCleanup(httpretty.disable)

        self.TEST_URL = '%s%s' % (self.TEST_ROOT_URL, self.version)
        self.TEST_ADMIN_URL = '%s%s' % (self.TEST_ROOT_ADMIN_URL, self.version)
        self.TEST_DISCOVERY = fixture.DiscoveryList(href=self.TEST_ROOT_URL)

        self.stub_auth_data()

    @abc.abstractmethod
    def create_auth_plugin(self, **kwargs):
        """Create an auth plugin that makes sense for the auth data.

        It doesn't really matter what auth mechanism is used but it should be
        appropriate to the API version.
        """

    @abc.abstractmethod
    def get_auth_data(self, **kwargs):
        """Return fake authentication data.

        This should register a valid token response and ensure that the compute
        endpoints are set to TEST_COMPUTE_PUBLIC, _INTERNAL and _ADMIN.
        """

    def stub_auth_data(self, **kwargs):
        token = self.get_auth_data(**kwargs)
        self.stub_auth(json=token)

    @abc.abstractproperty
    def version(self):
        """The API version being tested."""

    def test_discovering(self):
        self.stub_url(httpretty.GET, [],
                      base_url=self.TEST_COMPUTE_ADMIN,
                      json=self.TEST_DISCOVERY)

        body = 'SUCCESS'

        # which gives our sample values
        self.stub_url(httpretty.GET, ['path'],
                      body=body, status=200)

        a = self.create_auth_plugin()
        s = session.Session(auth=a)

        resp = s.get('/path', endpoint_filter={'service_type': 'compute',
                                               'interface': 'admin',
                                               'version': self.version})

        self.assertEqual(200, resp.status_code)
        self.assertEqual(body, resp.text)

        new_body = 'SC SUCCESS'
        # if we don't specify a version, we use the URL from the SC
        self.stub_url(httpretty.GET, ['path'],
                      base_url=self.TEST_COMPUTE_ADMIN,
                      body=new_body, status=200)

        resp = s.get('/path', endpoint_filter={'service_type': 'compute',
                                               'interface': 'admin'})

        self.assertEqual(200, resp.status_code)
        self.assertEqual(new_body, resp.text)

    def test_discovery_uses_session_cache(self):
        # register responses such that if the discovery URL is hit more than
        # once then the response will be invalid and not point to COMPUTE_ADMIN
        disc_body = jsonutils.dumps(self.TEST_DISCOVERY)
        disc_responses = [httpretty.Response(body=disc_body, status=200),
                          httpretty.Response(body='', status=500)]
        httpretty.register_uri(httpretty.GET,
                               self.TEST_COMPUTE_ADMIN,
                               responses=disc_responses)

        body = 'SUCCESS'
        self.stub_url(httpretty.GET, ['path'], body=body, status=200)

        # now either of the two plugins I use, it should not cause a second
        # request to the discovery url.
        s = session.Session()
        a = self.create_auth_plugin()
        b = self.create_auth_plugin()

        for auth in (a, b):
            resp = s.get('/path',
                         auth=auth,
                         endpoint_filter={'service_type': 'compute',
                                          'interface': 'admin',
                                          'version': self.version})

            self.assertEqual(200, resp.status_code)
            self.assertEqual(body, resp.text)

    def test_discovery_uses_plugin_cache(self):
        # register responses such that if the discovery URL is hit more than
        # once then the response will be invalid and not point to COMPUTE_ADMIN
        disc_body = jsonutils.dumps(self.TEST_DISCOVERY)
        disc_responses = [httpretty.Response(body=disc_body, status=200),
                          httpretty.Response(body='', status=500)]
        httpretty.register_uri(httpretty.GET,
                               self.TEST_COMPUTE_ADMIN,
                               responses=disc_responses)

        body = 'SUCCESS'
        self.stub_url(httpretty.GET, ['path'], body=body, status=200)

        # now either of the two sessions I use, it should not cause a second
        # request to the discovery url.
        sa = session.Session()
        sb = session.Session()
        auth = self.create_auth_plugin()

        for sess in (sa, sb):
            resp = sess.get('/path',
                            auth=auth,
                            endpoint_filter={'service_type': 'compute',
                                             'interface': 'admin',
                                             'version': self.version})

            self.assertEqual(200, resp.status_code)
            self.assertEqual(body, resp.text)

    def test_discovering_with_no_data(self):
        # which returns discovery information pointing to TEST_URL but there is
        # no data there.
        self.stub_url(httpretty.GET, [],
                      base_url=self.TEST_COMPUTE_ADMIN,
                      status=400)

        # so the url that will be used is the same TEST_COMPUTE_ADMIN
        body = 'SUCCESS'
        self.stub_url(httpretty.GET, ['path'],
                      base_url=self.TEST_COMPUTE_ADMIN, body=body, status=200)

        a = self.create_auth_plugin()
        s = session.Session(auth=a)

        resp = s.get('/path', endpoint_filter={'service_type': 'compute',
                                               'interface': 'admin',
                                               'version': self.version})

        self.assertEqual(200, resp.status_code)
        self.assertEqual(body, resp.text)

    def test_reauthenticate(self):
        expires = timeutils.utcnow() - datetime.timedelta(minutes=20)
        expired_token = self.get_auth_data(expires=expires)
        expired_auth_ref = access.AccessInfo.factory(body=expired_token)

        body = 'SUCCESS'
        self.stub_url(httpretty.GET, ['path'],
                      base_url=self.TEST_COMPUTE_ADMIN, body=body, status=200)

        a = self.create_auth_plugin()
        a.auth_ref = expired_auth_ref

        s = session.Session(auth=a)
        self.assertIsNot(expired_auth_ref, a.get_access(s))

    def test_no_reauthenticate(self):
        expires = timeutils.utcnow() - datetime.timedelta(minutes=20)
        expired_token = self.get_auth_data(expires=expires)
        expired_auth_ref = access.AccessInfo.factory(body=expired_token)

        body = 'SUCCESS'
        self.stub_url(httpretty.GET, ['path'],
                      base_url=self.TEST_COMPUTE_ADMIN, body=body, status=200)

        a = self.create_auth_plugin(reauthenticate=False)
        a.auth_ref = expired_auth_ref

        s = session.Session(auth=a)
        self.assertIs(expired_auth_ref, a.get_access(s))


class V3(CommonIdentityTests, utils.TestCase):

    @property
    def version(self):
        return 'v3'

    def get_auth_data(self, **kwargs):
        token = fixture.V3Token(**kwargs)
        region = 'RegionOne'

        svc = token.add_service('identity')
        svc.add_standard_endpoints(admin=self.TEST_ADMIN_URL, region=region)

        svc = token.add_service('compute')
        svc.add_standard_endpoints(admin=self.TEST_COMPUTE_ADMIN,
                                   public=self.TEST_COMPUTE_PUBLIC,
                                   internal=self.TEST_COMPUTE_INTERNAL,
                                   region=region)

        return token

    def stub_auth(self, subject_token=None, **kwargs):
        if not subject_token:
            subject_token = self.TEST_TOKEN

        self.stub_url(httpretty.POST, ['auth', 'tokens'],
                      X_Subject_Token=subject_token, **kwargs)

    def create_auth_plugin(self, **kwargs):
        kwargs.setdefault('auth_url', self.TEST_URL)
        kwargs.setdefault('username', self.TEST_USER)
        kwargs.setdefault('password', self.TEST_PASS)
        return v3.Password(**kwargs)


class V2(CommonIdentityTests, utils.TestCase):

    @property
    def version(self):
        return 'v2.0'

    def create_auth_plugin(self, **kwargs):
        kwargs.setdefault('auth_url', self.TEST_URL)
        kwargs.setdefault('username', self.TEST_USER)
        kwargs.setdefault('password', self.TEST_PASS)
        return v2.Password(**kwargs)

    def get_auth_data(self, **kwargs):
        token = fixture.V2Token(**kwargs)
        region = 'RegionOne'

        svc = token.add_service('identity')
        svc.add_endpoint(self.TEST_ADMIN_URL, region=region)

        svc = token.add_service('compute')
        svc.add_endpoint(public=self.TEST_COMPUTE_PUBLIC,
                         internal=self.TEST_COMPUTE_INTERNAL,
                         admin=self.TEST_COMPUTE_ADMIN,
                         region=region)

        return token

    def stub_auth(self, **kwargs):
        self.stub_url(httpretty.POST, ['tokens'], **kwargs)
