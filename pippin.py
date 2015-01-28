import collections
import contextlib
import copy
import itertools
import os
import shutil
import tempfile

from distutils import version as dist_version

from pip import req as pip_req
import pkg_resources

import argparse
import requests
import six
from six.moves import urllib

import pip

try:
    from pip import util as pip_util
except ImportError:
    from pip import utils as pip_util


_FINDER_URL_TPL = 'http://pypi.python.org/pypi/%s/json'

# Egg info cache and url fetch caches...
_EGGS_DETAILED = {}
_FINDER_LOOKUPS = {}
_KNOWN_BUSTED = set()


def make_busted_key(req, gathered):
    def _req_cmp(a, b):
        return cmp(a.key, b.key)
    gathered_reqs = [r.req for r in six.itervalues(gathered)]
    if req not in gathered_reqs:
        gathered_reqs.append(req)
    gathered_reqs = sorted(gathered_reqs, cmp=_req_cmp)
    return "\n".join([str(r) for r in gathered_reqs])


class RequirementException(Exception):
    pass


class NotFoundException(Exception):
    pass


_MatchedRequirement = collections.namedtuple('_MatchedRequirement',
                                             ['string_version',
                                              'parsed_version',
                                              'origin_url',
                                              'origin_filename'])

def req_key(req):
    return req.req.key


@contextlib.contextmanager
def tempdir(**kwargs):
    # This seems like it was only added in python 3.2
    # Make it since its useful...
    # See: http://bugs.python.org/file12970/tempdir.patch
    tdir = tempfile.mkdtemp(**kwargs)
    try:
        yield tdir
    finally:
        shutil.rmtree(tdir)


def get_directory_details(path):
    if not os.path.isdir(path):
        raise IOError("Can not detail non-existent directory %s" % (path))
    req = pip_req.InstallRequirement.from_line(path)
    req.source_dir = path
    req.run_egg_info()
    dependencies = []
    for d in req.requirements():
        if not d.startswith("-e") and d.find("#"):
            d = d.split("#")[0]
        d = d.strip()
        if d:
            dependencies.append(d)
    details = {
        'req': req.req,
        'dependencies': dependencies,
        'name': req.name,
        'pkg_info': req.pkg_info(),
        'dependency_links': req.dependency_links,
        'version': req.installed_version,
    }
    return details


def get_archive_details(filename):
    if not os.path.isfile(filename):
        raise IOError("Can not detail non-existent file %s" % (filename))
    cache_key = "f:%s:%s" % (os.path.basename(filename),
                             os.path.getsize(filename))
    if cache_key in _EGGS_DETAILED:
        return _EGGS_DETAILED[cache_key]
    with tempdir() as a_dir:
        arch_filename = os.path.join(a_dir, os.path.basename(filename))
        shutil.copyfile(filename, arch_filename)
        extract_to = os.path.join(a_dir, 'build')
        os.makedirs(extract_to)
        pip_util.unpack_file(arch_filename, extract_to,
                             content_type='', link='')
        details = get_directory_details(extract_to)
    _EGGS_DETAILED[cache_key] = details
    return details


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-r", "--requirement",
        dest="requirements",
        nargs="+",
        default=[],
        metavar="<file>",
        help="Analyze all the packages listed in the given requirements file")
    return parser


def parse_requirements(options):
    all_requirements = {}
    for filename in options.requirements:
        try:
            for req in pip_req.parse_requirements(filename):
                all_requirements.setdefault(req_key(req), []).append(req)
        except Exception as ex:
            raise RequirementException("Cannot parse `%s': %s" % (filename, ex))
    return all_requirements


def find_versions(pkg_name):
    def sorter(r1, r2):
        return cmp(r1[1], r2[1])
    url = _FINDER_URL_TPL % (urllib.parse.quote(pkg_name))
    if url in _FINDER_LOOKUPS:
        return _FINDER_LOOKUPS[url]
    resp = requests.get(url)
    resp_data = resp.json()
    releases = []
    for v, release_infos in six.iteritems(resp_data['releases']):
        rel = rel_fn = None
        for r in release_infos:
            if r['packagetype'] == 'sdist':
                rel = r['url']
                rel_fn = r['filename']
        if not all([rel, rel_fn]):
            print("ERROR: no sdist found for '%s==%s'" % (pkg_name, v))
            continue
        try:
            releases.append(_MatchedRequirement(
                             str(v), dist_version.LooseVersion(v),
                             rel, rel_fn))
        except ValueError:
            print("ERROR: failed parsing '%s==%s'" % (pkg_name, v))
    _FINDER_LOOKUPS[url] = sorted(releases, cmp=sorter)
    return _FINDER_LOOKUPS[url]


def dump_requirements(requirements):
    for k in six.iterkeys(requirements):
        k_restrictions = []
        if isinstance(requirements[k], (list, tuple)):
            for r in requirements[k]:
                if r.req.specs:
                    k_restrictions.extend(["".join(s) for s in r.req.specs])
        else:
            r = requirements[k]
            k_restrictions.extend(["".join(s) for s in r.req.specs])
        if k_restrictions:
            print("- %s %s" % (k, k_restrictions))
        else:
            print("- %s" % (k))


def fetch_details(req):
    origin_filename = req.origin_filename
    origin_url = req.origin_url
    path = os.path.join(os.getcwd(), '.download', origin_filename)
    if not os.path.exists(path):
        resp = requests.get(origin_url)
        with open(path, 'wb') as fh:
            fh.write(resp.content)
    return get_archive_details(path)


def match_available(req, available):
    looked_in = []
    useables = []
    for a in reversed(available):
        v = a.string_version
        if v in req:
            line = "%s==%s" % (req.key, v)
            m_req = pip_req.InstallRequirement.from_line(line)
            print("Found '%s' as able to satisfy '%s'" % (m_req, req))
            m_req.origin_url = a.origin_url
            m_req.origin_filename = a.origin_filename
            useables.append(m_req)
        else:
            looked_in.append(v)
    if not useables:
        raise NotFoundException("No requirement found that"
                                " matches '%s' (tried %s)" % (req, looked_in))
    else:
        return useables


def is_compatible_alongside(req, gathered):
    print("Checking if '%s' is compatible along-side:" % req)
    for name, other_req in six.iteritems(gathered):
        print(" - %s==%s" % (name, other_req.details['version']))
        for other_dep in other_req.details['dependencies']:
            print("  + %s" % (other_dep))
    req_details = req.details
    req = req.req
    for name, other_req in six.iteritems(gathered):
        if req.key == name:
            if req_details['version'] not in other_req.req:
                print("Conflict: '%s' not in '%s'"
                      % (req_details['version'], other_req))
                return False
        for other_dep in other_req.details['dependencies']:
            other_dep_req = pkg_resources.Requirement.parse(other_dep)
            if other_dep_req.key == req.key:
                if req_details['version'] not in other_dep_req:
                    print("Conflict: '%s' not in '%s'"
                          % (req_details['version'], other_dep_req))
                    return False
    return True


def probe(requirements, gathered):
    if not requirements:
        return {}
    requirements = copy.deepcopy(requirements)
    gathered = copy.deepcopy(gathered)
    # Pick one of the requirements, get a version that works with the current
    # known siblings (other requirements that are requested along side this
    # requirement) and then recurse trying to get another requirement that
    # will work, if this is not possible, backtrack and try a different
    # version instead (and repeat)...
    pkg_name, pkg_requirements = requirements.popitem()
    for req in pkg_requirements:
        print("Searching for pypi requirement that matches '%s'" % (req.req))
        possibles = match_available(req.req, find_versions(pkg_name))
        for m in possibles:
            if not hasattr(m, 'details'):
                try:
                    m.details = fetch_details(m)
                except pip.exceptions.InstallationError as e:
                    print("ERROR: failed detailing '%s'" % (m))
                    e_blob = str(e)
                    for line in e_blob.splitlines():
                        print(" %s" % line)
            if not hasattr(m, 'details'):
                continue
            if  make_busted_key(m.req, gathered) in _KNOWN_BUSTED:
                print("Skipping '%s' as it is known to not work..." % m.req)
                continue
            print("Matched '%s'" % m)
            old_requirements = copy.deepcopy(requirements)
            if m.details['dependencies']:
                for m_dep in m.details['dependencies']:
                    m_req = pip_req.InstallRequirement.from_line(m_dep)
                    requirements.setdefault(req_key(m_req), []).append(m_req)
            local_compat = is_compatible_alongside(m, gathered)
            if local_compat:
                gathered[pkg_name] = m
                try:
                    result = probe(requirements, gathered)
                except RequirementException as e:
                    print("Undoing decision to select '%s' since we"
                          " %s that work along side it..." % (m, e))
                    gathered.pop(pkg_name)
                    requirements = old_requirements
                    _KNOWN_BUSTED.add(make_busted_key(m.req, gathered))
                else:
                    gathered.update(result)
                    return gathered
            else:
                print("ERROR: '%s' was not found to be compatible with the"
                      " currently gathered requirements (trying a"
                      " different version)..." % req)
                requirements = old_requirements
                _KNOWN_BUSTED.add(m.req)
    failed_requirements = []
    for req in pkg_requirements:
        if req.req not in failed_requirements:
            failed_requirements.append(req.req)
    raise RequirementException("failed finding any valid matches"
                               " for %s" % failed_requirements)


def main():
    parser = create_parser()
    options = parser.parse_args()
    if not options.requirements:
        parser.error("At least one requirement file must be provided")
    initial = parse_requirements(options)
    print("Initial package set:")
    dump_requirements(initial)
    for d in ['.download']:
        if not os.path.isdir(os.path.join(os.getcwd(), d)):
            os.makedirs(os.path.join(os.getcwd(), d))
    matches = probe(initial, {})
    print("Deep package set:")
    dump_requirements(matches)


if __name__ == "__main__":
    main()
