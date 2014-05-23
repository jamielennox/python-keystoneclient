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

import argparse

import stevedore

PLUGIN_NAMESPACE = 'keystoneclient.auth.plugin'


def _register_opts(ext, parser):
    try:
        get_params = ext.plugin.get_params
    except AttributeError:
        return

    for param in get_params():
        name = param.name.replace('_', '-')
        parser.add_argument('--%s' % name,
                            dest=param.param,
                            type=param.type,
                            help=param.description)


def _load_from_opts(ext, args):
    try:
        get_params = ext.plugin.get_params
    except AttributeError:
        return

    params = {}

    # param, param, param, param
    for param in get_params():
        params[param.param] = getattr(args, param.param)

    return ext.plugin(**params)


def _load_plugins(name):
    return stevedore.named.NamedExtensionManager(
        PLUGIN_NAMESPACE,
        [name],
        invoke_on_load=False,
        propagate_map_exceptions=True)


def register_cli_options(parser, argv):
    in_parser = argparse.ArgumentParser(add_help=False)

    for p in (in_parser, parser):
        p.add_argument('--os-auth-plugin',
                       metavar='<name>',
                       help='The auth plugin to load')

    options, args = in_parser.parse_known_args(argv)
    plugins = _load_plugins(options.os_auth_plugin)

    try:
        plugins.map(_register_opts, parser)
    except RuntimeError:
        return None

# def register_cli_options_for_name(parser, name):
#     plugins = _load_plugins(name)
#
#     try:
#         plugins.map(_register_opts, parser)
#     except RuntimeError:
#         return None


def plugin_from_cli(args):
    if not args.os_auth_plugin:
        return None

    plugins = _load_plugins(args.os_auth_plugin)

    try:
        return plugins.map(_load_from_opts, args)[0]
    except RuntimeError:
        return None
