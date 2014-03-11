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

from keystoneclient import utils


class Param(object):

    @utils.positional()
    def __init__(self, param, type=str, default=None,
                 description=None, name=None, display_name=None):
        """Construct a new authentication parameter object.

        Params describe the available parameters to an authentication
        plugin so that a plugin may be queried and automatically integrated
        with plugin factories like loading from a config file or from a CLI.

        Each Param object is one parameter that an authentication plugin
        accepts.

        :param str param: The name of the parameter as it will be passed as a
                          keyword argument to the plugin constructor.
        :param type type: The type of parameter. This is a python type object
                          (eg str, int).
        :param default: The default value for this argument if not provided.
        :param str name: The name of the parameter. This is what will be
                         presented to users. Defaults to ``param``.
        :param str display_name: A human readable name. This can be thought of
                                 similar to a short description.
        :param str description: A description of what the parameter does. This
                                can be used for example by help texts.
        """
        self.param = param
        self.name = name or self.param
        self.display_name = display_name or self.name
        self.description = description or self.display_name
        self.type = type
        self.default = default
