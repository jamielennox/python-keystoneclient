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


import httpretty
import mock
import requests

from keystoneclient import session

from tests import utils


class SessionTests(utils.TestCase):

    TEST_URL = 'http://127.0.0.1:5000/'

    @httpretty.activate
    def test_get(self):
        self.session = session.ClientSession()
        self.stub_url(httpretty.GET, body='response')
        resp = self.session.get(self.TEST_URL)

        self.assertEqual(resp.text, 'response')
        self.assertTrue(resp.ok)

    @httpretty.activate
    def test_post(self):
        self.session = session.ClientSession()
        self.stub_url(httpretty.POST, body='response')
        resp = self.session.post(self.TEST_URL, json={'hello': 'world'})

        self.assertEqual(resp.text, 'response')
        self.assertTrue(resp.ok)
        self.assertRequestBodyIs(json={'hello': 'world'})

    @httpretty.activate
    def test_http_session_opts(self):
        self.session = session.ClientSession(cert='cert.pem', timeout=5,
                                             verify='certs')

        with mock.patch.object(requests, 'request') as mocked:
            self.session.post(self.TEST_URL, data='value')

            mock_args, mock_kwargs = mocked.call_args

            self.assertEqual(mock_args[0], 'POST')
            self.assertEqual(mock_args[1], self.TEST_URL)
            self.assertEqual(mock_kwargs['data'], 'value')
            self.assertEqual(mock_kwargs['cert'], 'cert.pem')
            self.assertEqual(mock_kwargs['verify'], 'certs')
