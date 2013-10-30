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
import stevedore

logger = logging.getLogger(__name__)

_KNOWN_MANAGERS = None


def _load_extension(ext, managers):
    _KNOWN_MANAGERS[ext.plugin.ident] = ext.obj
    _KNOWN_MANAGERS[ext.name] = ext.obj


def _managers():
    global _KNOWN_MANAGERS

    if _KNOWN_MANAGERS is None:
        ext_manager = stevedore.enabled.EnabledExtensionManager(
            check_func=self._check_enable_ext,
            namespace='keystoneclient.v3.extension',
            invoke_on_load=True,
            invoke_args=(self.client,))

        _KNOWN_MANAGERS = dict()
        ext_manager.map(_load_extension)

    return _KNOWN_MANAGERS


@six.add_metaclass(abc.ABCMeta)
class Extension(object):
    pass


class ExtensionManager(object):

    def __init__(self, client):
        self.client = client
        self._managers = None

    @property
    def managers(self):
        if self._managers is None:
            resp, body = self.client.get('/extensions')

            ext_manager = stevedore.enabled.EnabledExtensionManager(
                check_func=self._check_enable_ext,
                namespace='keystoneclient.v3.extension',
                invoke_on_load=True,
                invoke_args=(self.client,))

            self._managers = dict()
            ext_manager.map(_load_extension, self._managers)

        return self._managers

    def _check_enable_ext(self, ext):
        known = ['OS-TRUST', 'OS-OAUTH']

        try:
            return ext.plugin.ident in known
        except AttributeError:
            logger.warn("Trying to load a plugin which didn't have an ident")
            return False

    def __getitem__(self, name):
        return self.managers[name]

    def __contains__(self, name):
        return name in self.managers
