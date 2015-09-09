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

from keystoneclient import _discover
from keystoneclient import session as client_session


# functions needed from the private file that can be made public
def normalize_version_number(version):
    """Turn a version representation into a tuple.

    Takes a string, tuple or float which represent version formats we can
    handle and converts them into a (major, minor) version tuple that we can
    actually use for discovery.

    e.g. 'v3.3' gives (3, 3)
         3.1 gives (3, 1)

    :param version: Inputted version number to try and convert.

    :returns: A usable version tuple
    :rtype: tuple

    :raises TypeError: if the inputted version cannot be converted to tuple.
    """
    return _discover.normalize_version_number(version)


def version_match(required, candidate):
    """Test that an available version is a suitable match for a required
    version.

    To be suitable a version must be of the same major version as required
    and be at least a match in minor/patch level.

    eg. 3.3 is a match for a required 3.1 but 4.1 is not.

    :param tuple required: the version that must be met.
    :param tuple candidate: the version to test against required.

    :returns: True if candidate is suitable False otherwise.
    :rtype: bool
    """
    return _discover.version_match(required, candidate)


def available_versions(url, session=None, **kwargs):
    """Retrieve raw version data from a url."""
    if not session:
        session = client_session.Session._construct(kwargs)

    return _discover.get_version_data(session, url)


Discover = _discover.Discover


def add_catalog_discover_hack(service_type, old, new):
    """Adds a version removal rule for a particular service.

    Originally deployments of OpenStack would contain a versioned endpoint in
    the catalog for different services. E.g. an identity service might look
    like ``http://localhost:5000/v2.0``. This is a problem when we want to use
    a different version like v3.0 as there is no way to tell where it is
    located. We cannot simply change all service catalogs either so there must
    be a way to handle the older style of catalog.

    This function adds a rule for a given service type that if part of the URL
    matches a given regular expression in *old* then it will be replaced with
    the *new* value. This will replace all instances of old with new. It should
    therefore contain a regex anchor.

    For example the included rule states::

        add_catalog_version_hack('identity', re.compile('/v2.0/?$'), '/')

    so if the catalog retrieves an *identity* URL that ends with /v2.0 or
    /v2.0/ then it should replace it simply with / to fix the user's catalog.

    :param str service_type: The service type as defined in the catalog that
                             the rule will apply to.
    :param re.RegexObject old: The regular expression to search for and replace
                               if found.
    :param str new: The new string to replace the pattern with.
    """
    _discover._VERSION_HACKS.add_discover_hack(service_type, old, new)
