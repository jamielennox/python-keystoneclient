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

import functools

import stevedore

from keystoneclient import exceptions

PLUGIN_NAMESPACE = 'keystoneclient.auth.plugin'

try:
    from oslo.config import cfg
except ImportError:
    cfg = None


def _require_cfg(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not cfg:
            raise ImportError('oslo.config is not available')

        return f(*args, **kwargs)
    return wrapper


@_require_cfg
def register_conf_options(conf, group):
    opts = [cfg.StrOpt('name', help='Name of the plugin to load'),
            cfg.StrOpt('section', help='Plugin Section')]

    conf.register_group(cfg.OptGroup(group))
    conf.register_opts(opts, group=group)


@_require_cfg
def plugin_from_conf(conf, group, **kwargs):
    """Load a plugin from an oslo.config CONF object.

    This takes the config option and the group that the options are registered
    in. We define two options in this group:

     - name: the name of the auth plugin that will be used for authentication.
     - section: the group from which further auth plugin options should be
         taken. If section is not provided then the auth plugin options will be
         taken from the same group as provided in the parameters.

    Each plugin will register there own required options and so there is no
    standard list and the plugin should be consulted.

    :param conf: An oslo.config conf object.
    :param string group: The group name that options should be read from.

    :returns plugin: An authentication Plugin.

    :raises exceptions.NoMatchingPlugin: if a plugin cannot be created.
    """
    register_conf_options(conf=conf, group=group)

    name = conf[group].name
    if not name:
        raise exceptions.NoMatchingPlugin('No plugin name provided for config')

    # Load the class object from a setuptools entrypoint
    try:
        mgr = stevedore.DriverManager(
            namespace=PLUGIN_NAMESPACE,
            name=name,
            invoke_on_load=False)
    except RuntimeError:
        msg = 'The plugin %s could not be found' % name
        raise exceptions.NoMatchingPlugin(msg)

    # plugins are allowed to specify a 'section' which is the group that auth
    # options should be taken from. If not present they come from the same
    # group as where the plugin name is defined.
    if conf[group].section:
        group = conf[group].section
        conf.register_group(cfg.OptGroup(group))

    # convert the auth plugin parameters into oslo.config options.
    for param in mgr.driver.get_params():
        if param.type == str:
            opt_type = cfg.StrOpt
        elif param.type == bool:
            opt_type = cfg.BoolOpt
        elif param.type == int:
            opt_type = cfg.IntOpt
        elif param.type == float:
            opt_type = cfg.FloatOpt
        else:
            raise TypeError('Invalid parameter type %s on %s.%s' %
                            (param.type.__name__, mgr.driver, param.param))

        # create and register the option
        opt = opt_type(name=param.name,
                       dest=param.param,
                       default=param.default,
                       help=param.description)

        conf.register_opt(opt, group=group)

        # once the option has been registered it can be read out
        kwargs.setdefault(param.param, conf[group][param.param])

    return mgr.driver(**kwargs)
