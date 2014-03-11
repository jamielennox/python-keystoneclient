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

import mock
import six
import stevedore

from oslo.config import cfg

from keystoneclient.auth import base
from keystoneclient.auth import conf
from keystoneclient.auth import param
from keystoneclient import exceptions
from keystoneclient.openstack.common.fixture import config
from keystoneclient.tests import utils


class MockPlugin(base.BaseAuthPlugin):

    INT_DESC = 'test int'
    FLOAT_DESC = 'test float'
    BOOL_DESC = 'test bool'

    def __init__(self, **kwargs):
        self._data = kwargs

    def __getitem__(self, key):
        return self._data[key]

    def get_token(self, *args, **kwargs):
        return 'aToken'

    def get_endpoint(self, *args, **kwargs):
        return 'http://test'

    @classmethod
    def get_cfgs(cls):
        return [
            cfg.IntOpt('aInt', help=cls.INT_DESC),
            cfg.BoolOpt('aBool', help=cls.BOOL_DESC),
            cfg.FloatOpt('aFloat', help=cls.FLOAT_DESC),
        ]

    @classmethod
    def get_params(cls):
        return [
            param.Param('aInt', type=int, description=cls.INT_DESC),
            param.Param('aBool', type=bool, description=cls.BOOL_DESC),
            param.Param('aFloat', type=float, description=cls.FLOAT_DESC),
        ]


class MockManager(object):

    def __init__(self, driver):
        self.driver = driver


class ConfTests(utils.TestCase):

    GROUP = 'auth'
    V2PASS = 'v2password'
    V3TOKEN = 'v3token'

    def setUp(self):
        super(ConfTests, self).setUp()
        self.conf_fixture = self.useFixture(config.Config())
        self.register(self.GROUP)

    def register(self, group=None):
        # NOTE(jamielennox): whilst it works just fine to load all this stuff
        # from a config file when trying to do overrides and in testing you can
        # set the value unless it has been defined first. That means we need to
        # do a whole lot of config option registering that will be done
        # automatically when actually trying to use the from_config functions.
        # These need to match EXACTLY the options that are registered by the
        # conf option or else you will get a conflict.

        conf.register_conf_options(self.conf_fixture.conf, group=self.GROUP)
        self.conf_fixture.conf.register_group(cfg.OptGroup(group))
        opts = [cfg.StrOpt('name', help='Name of the plugin to load'),
                cfg.StrOpt('section', help='Plugin Section')]
        self.conf_fixture.register_opts(opts, group=group)

        # there is no need for the group name to be the same as the auth plugin
        # it just simplifies the testing to have it that way.
        self.conf_fixture.conf.register_group(cfg.OptGroup(self.V2PASS))
        v2passwordopts = [cfg.StrOpt('username',
                                     help='Username to login with'),
                          cfg.StrOpt('password',
                                     help='Password to use'),
                          cfg.StrOpt('trust_id',
                                     help='Trust ID'),
                          cfg.StrOpt('tenant_id',
                                     help='Tenant ID'),
                          cfg.StrOpt('tenant_name',
                                     help='Tenant Name')]
        self.conf_fixture.register_opts(v2passwordopts, group=self.V2PASS)

        self.conf_fixture.conf.register_group(cfg.OptGroup(self.V3TOKEN))
        v3tokenopts = [cfg.StrOpt('token',
                                  help='Token to authenticate with'),
                       cfg.StrOpt('trust_id',
                                  help='Trust ID'),
                       cfg.StrOpt('domain_id',
                                  help='Domain ID to scope to'),
                       cfg.StrOpt('domain_name',
                                  help='Domain name to scope to'),
                       cfg.StrOpt('user_domain_id',
                                  help="User's domain id"),
                       cfg.StrOpt('user_domain_name',
                                  help="User's domain name"),
                       cfg.StrOpt('project_id',
                                  help='Project ID to scope to'),
                       cfg.StrOpt('project_name',
                                  help='Project name to scope to'),
                       cfg.StrOpt('project_domain_id',
                                  help='Domain ID containing project'),
                       cfg.StrOpt('project_domain_name',
                                  help='Domain name containing project')]
        self.conf_fixture.register_opts(v3tokenopts, group=self.V3TOKEN)

    def test_loading_v2(self):
        self.conf_fixture.config(name=self.V2PASS,
                                 section=self.V2PASS,
                                 group=self.GROUP)
        self.conf_fixture.config(username='user',
                                 password='pass',
                                 trust_id='trust',
                                 tenant_id='tenant',
                                 group=self.V2PASS)

        a = conf.plugin_from_conf(self.conf_fixture.conf, self.GROUP)

        self.assertEqual('user', a.username)
        self.assertEqual('pass', a.password)
        self.assertEqual('trust', a.trust_id)
        self.assertEqual('tenant', a.tenant_id)

    def test_loading_v3(self):
        self.conf_fixture.config(name=self.V3TOKEN,
                                 section=self.V3TOKEN,
                                 group=self.GROUP)
        self.conf_fixture.config(token='token',
                                 trust_id='trust',
                                 project_id='project',
                                 project_domain_name='domain',
                                 group=self.V3TOKEN)

        a = conf.plugin_from_conf(self.conf_fixture.conf, self.GROUP)

        self.assertEqual('token', a.auth_methods[0].token)
        self.assertEqual('trust', a.trust_id)
        self.assertEqual('project', a.project_id)
        self.assertEqual('domain', a.project_domain_name)

    def test_loading_invalid_plugin(self):
        self.conf_fixture.config(name='invalid',
                                 section=self.V3TOKEN,
                                 group=self.GROUP)

        self.assertRaises(exceptions.NoMatchingPlugin,
                          conf.plugin_from_conf,
                          self.conf_fixture.conf,
                          self.GROUP)

    def test_loading_with_no_data(self):
        self.assertRaises(exceptions.NoMatchingPlugin,
                          conf.plugin_from_conf,
                          self.conf_fixture.conf,
                          self.GROUP)

    @mock.patch('stevedore.DriverManager')
    def test_other_params(self, driver_manager):
        driver_name = 'pluginName'
        driver_manager.return_value = MockManager(MockPlugin)

        vals = {'aInt': 88,
                'aFloat': 88.88,
                'aBool': False}

        self.conf_fixture.register_opts(MockPlugin.get_cfgs(),
                                        group=self.GROUP)
        self.conf_fixture.config(name=driver_name, group=self.GROUP, **vals)

        a = conf.plugin_from_conf(self.conf_fixture.conf, self.GROUP)

        for k, v in six.iteritems(vals):
            self.assertEqual(v, a[k])

        driver_manager.assert_called_once_with(
            namespace='keystoneclient.auth.plugin',
            name=driver_name,
            invoke_on_load=False)

    @mock.patch('stevedore.DriverManager')
    def test_bad_params(self, driver_manager):

        class BadPlugin(MockPlugin):

            @classmethod
            def get_params(cls):
                p = super(BadPlugin, cls).get_params()
                # tuples are currently not a type we allow
                p.append(param.Param('invalid', type=tuple))
                return p

        driver_name = 'pluginName'
        driver_manager.return_value = MockManager(BadPlugin)
        self.conf_fixture.config(name=driver_name, group=self.GROUP)

        self.conf_fixture.register_opts(MockPlugin.get_cfgs(),
                                        group=self.GROUP)
        self.assertRaises(TypeError,
                          conf.plugin_from_conf,
                          self.conf_fixture.conf,
                          self.GROUP)

    def test_plugins_are_all_params(self):
        manager = stevedore.ExtensionManager('keystoneclient.auth.plugin',
                                             invoke_on_load=False,
                                             propagate_map_exceptions=True)

        def inner(driver):
            for p in driver.plugin.get_params():
                self.assertIsInstance(p, param.Param)

        manager.map(inner)
