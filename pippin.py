# -*- coding: utf-8 -*-

#    Copyright (C) 2015 Yahoo! Inc. All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from __future__ import print_function

import collections
import contextlib
import hashlib
import json
import os
import shutil
import sys
import tempfile

from distutils import version as dist_version

from pip import req as pip_req
import pkg_resources

import argparse
import requests
import six
from six.moves import urllib

try:
    from pip import util as pip_util
except ImportError:
    from pip import utils as pip_util


_FINDER_URL_TPL = 'http://pypi.python.org/pypi/%s/json'

# Egg info cache and url fetch caches...
_EGGS_DETAILED = {}
_FINDER_LOOKUPS = {}
_EGGS_FAILED_DETAILED = {}
_KNOWN_FAILURES = set()

# Only select the X prior versions for checking compatiblity if there
# are many possible versions (this reduces the search space to something
# more amenable/manageable).
_MAX_PRIOR_VERSIONS = 3


class RequirementException(Exception):
    pass


class PriorRequirementException(RequirementException):
    pass


class NotFoundException(Exception):
    pass


_MatchedRequirement = collections.namedtuple('_MatchedRequirement',
                                             ['string_version',
                                              'parsed_version',
                                              'origin_url',
                                              'origin_filename',
                                              'origin_size'])


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


def get_archive_details(filename, filesize, prefix=""):
    if not os.path.isfile(filename):
        raise IOError("Can not detail non-existent file %s" % (filename))
    cache_key = "f:%s:%s" % (os.path.basename(filename), filesize)
    if cache_key in _EGGS_FAILED_DETAILED:
        exc_type, exc_value, exc_traceback = _EGGS_FAILED_DETAILED[cache_key]
        six.reraise(exc_type, exc_value, exc_traceback)
    try:
        return _EGGS_DETAILED[cache_key]
    except KeyError:
        print("%sExtracting egg-info from '%s'" % (prefix,
                                                   os.path.basename(filename)))
        with tempdir() as a_dir:
            arch_filename = os.path.join(a_dir, os.path.basename(filename))
            shutil.copyfile(filename, arch_filename)
            extract_to = os.path.join(a_dir, 'build')
            os.makedirs(extract_to)
            pip_util.unpack_file(arch_filename, extract_to,
                                 content_type='', link='')
            try:
                details = get_directory_details(extract_to)
            except Exception:
                # Don't bother saving the traceback (we don't care about it...)
                exc_type, exc_value, exc_traceback = sys.exc_info()
                _EGGS_FAILED_DETAILED[cache_key] = (exc_type, exc_value, None)
                raise
            else:
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
    parser.add_argument(
        "-s", "--scratch",
        dest="scratch",
        default=os.getcwd(),
        metavar="<path>",
        help="Scratch path (used for caching downloaded data)"
             " [default: %s]" % (os.getcwd()))
    parser.add_argument(
        "--verbose",
        dest="verbose",
        action='store_true',
        default=False,
        help="Enable verbose output")
    return parser


def download_url_to(url, save_path, size=None, prefix=""):
    if size is not None:
        kb_size = size // 1024
        print("%sDownloading '%s' (%skB) -> '%s'" % (prefix, url,
                                                     kb_size, save_path))
    else:
        print("%sDownloading '%s' -> '%s'" % (prefix, url, save_path))
    resp = requests.get(url)
    with open(save_path, 'wb') as fh:
        fh.write(resp.content)
    return resp.content


def parse_requirements(options):
    all_requirements = {}
    for filename in options.requirements:
        try:
            for req in pip_req.parse_requirements(filename):
                all_requirements.setdefault(req_key(req), []).append(req)
        except Exception as ex:
            raise RequirementException("Cannot parse `%s': %s"
                                       % (filename, ex))
    return all_requirements


def find_versions(pkg_name, options, prefix=""):
    def sorter(r1, r2):
        return cmp(r1[1], r2[1])
    url = _FINDER_URL_TPL % (urllib.parse.quote(pkg_name))
    if url in _FINDER_LOOKUPS:
        return _FINDER_LOOKUPS[url]
    version_path = os.path.join(options.scratch,
                                ".versions", "%s.json" % pkg_name)
    if os.path.exists(version_path):
        with open(version_path, 'rb') as fh:
            resp_data = json.loads(fh.read())
    else:
        resp_data = json.loads(download_url_to(url,
                                               version_path, prefix=prefix))
    releases = []
    for v, release_infos in six.iteritems(resp_data['releases']):
        rel = rel_fn = rel_size = None
        for r in release_infos:
            if r['packagetype'] == 'sdist':
                rel = r['url']
                rel_fn = r['filename']
                rel_size = r['size']
        if not all([rel, rel_fn, rel_size]):
            print("%sERROR: no sdist found for '%s==%s'"
                  % (prefix, pkg_name, v), file=sys.stderr)
            continue
        try:
            releases.append(_MatchedRequirement(
                            str(v), dist_version.LooseVersion(v),
                            rel, rel_fn, rel_size))
        except ValueError:
            print("%sERROR: failed parsing '%s==%s'"
                  % (prefix, pkg_name, v), file=sys.stderr)
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
            if len(k_restrictions) == 1:
                print("- %s%s" % (k, k_restrictions[0]))
            else:
                print("- %s %s" % (k, k_restrictions))
        else:
            print("- %s" % (k))


def fetch_details(req, options, prefix=""):
    origin_filename = req.origin_filename
    origin_url = req.origin_url
    download_path = os.path.join(options.scratch,
                                 '.download', origin_filename)
    if not os.path.exists(download_path):
        download_url_to(origin_url, download_path,
                        size=req.origin_size, prefix=prefix)
    return get_archive_details(download_path, req.origin_size,
                               prefix=prefix)


def match_available(req, available, options, prefix=""):
    looked_in = []
    useables = []
    for a in reversed(available):
        v = a.string_version
        if v in req:
            line = "%s==%s" % (req.key, v)
            m_req = pip_req.InstallRequirement.from_line(line)
            if options.verbose:
                print("%sFound '%s' as able to satisfy '%s'"
                      % (prefix, m_req, req))
            m_req.origin_url = a.origin_url
            m_req.origin_filename = a.origin_filename
            m_req.origin_size = a.origin_size
            useables.append(m_req)
            if len(useables) == _MAX_PRIOR_VERSIONS:
                break
        else:
            looked_in.append(v)
    if not useables:
        raise NotFoundException("No requirement found that"
                                " matches '%s' (tried %s)" % (req, looked_in))
    else:
        return useables


def is_compatible_alongside(req, gathered, options, prefix=""):
    if options.verbose:
        print("%sChecking if '%s' is compatible along-side:" % (prefix, req))
        for name, other_req in six.iteritems(gathered):
            print("%s - %s==%s" % (prefix, name, other_req.details['version']))
            for other_dep in other_req.details['dependencies']:
                print("%s  + %s" % (prefix, other_dep))
    req_details = req.details
    req = req.req
    for name, other_req in six.iteritems(gathered):
        if req.key == name:
            if req_details['version'] not in other_req.req:
                print("%sConflict: '%s==%s' not in '%s'"
                      % (prefix, req_details['name'],
                         req_details['version'], other_req))
                return False
        for other_dep in other_req.details['dependencies']:
            other_dep_req = pkg_resources.Requirement.parse(other_dep)
            if other_dep_req.key == req.key:
                if req_details['version'] not in other_dep_req:
                    print("%sConflict: '%s==%s' not in '%s' (required by '%s')"
                          % (prefix, req_details['name'],
                             req_details['version'],
                             other_dep_req, other_req))
                    return False
    return True


def hash_gathered(gathered):
    def sorter(a, b):
        return cmp(a.key, b.key)
    all_reqs = []
    for name, other_req in six.iteritems(gathered):
        all_reqs.append(other_req.req)
    all_reqs = sorted(all_reqs, cmp=sorter)
    buf = six.StringIO()
    for req in all_reqs:
        buf.write(req)
        buf.write("\n")
    buf = buf.getvalue().strip()
    return hashlib.md5(buf).hexdigest()


def save_failure(gathered):
    _KNOWN_FAILURES.add(hash_gathered(gathered))


def check_prior_failed(gathered):
    if hash_gathered(gathered) in _KNOWN_FAILURES:
        raise PriorRequirementException("already found this combination"
                                        " fails in a prior run")


def probe(requirements, gathered, options, indent=0):
    if not requirements:
        return {}

    def copy_requirements(requirements):
        cloned = {}
        for pkg_name, pkg_requirements in six.iteritems(requirements):
            cloned_pkg_requirements = cloned.setdefault(pkg_name, [])
            cloned_pkg_requirements.extend(pkg_requirements)
        return cloned

    def copy_gathered(gathered):
        return gathered.copy()

    prefix = " " * indent
    requirements = copy_requirements(requirements)
    gathered = copy_gathered(gathered)
    # Pick one of the requirements, get a version that works with the current
    # known siblings (other requirements that are requested along side this
    # requirement) and then recurse trying to get another requirement that
    # will work, if this is not possible, backtrack and try a different
    # version instead (and repeat)...
    pkg_name, pkg_requirements = requirements.popitem()
    tried_and_failed = set()
    while pkg_requirements:
        pkg_req = pkg_requirements.pop(0)
        if pkg_req.req in tried_and_failed:
            continue
        if options.verbose:
            print("%sSearching for pypi requirement that matches '%s'"
                  % (prefix, pkg_req.req))
        possibles = match_available(pkg_req.req,
                                    find_versions(pkg_name, options,
                                                  prefix=prefix),
                                    options,
                                    prefix=prefix)
        before_mutation_requirements = copy_requirements(requirements)
        for m in possibles:
            if not hasattr(m, 'details'):
                try:
                    m.details = fetch_details(m, options, prefix=prefix)
                except Exception as e:
                    print("%sERROR: failed detailing '%s'"
                          % (prefix, m), file=sys.stderr)
                    e_blob = str(e)
                    for line in e_blob.splitlines():
                        print("%s %s" % (prefix, line), file=sys.stderr)
            if not hasattr(m, 'details'):
                continue
            print("%sTrying '%s'" % (prefix, m))
            if m.details['dependencies']:
                for m_dep in m.details['dependencies']:
                    m_req = pip_req.InstallRequirement.from_line(m_dep)
                    m_req_key = req_key(m_req)
                    existing_reqs = requirements.setdefault(m_req_key, [])
                    existing_reqs.append(m_req)
            local_compat = is_compatible_alongside(m, gathered, options,
                                                   prefix=prefix)
            if local_compat:
                print("%sPicking '%s'" % (prefix, m))
                gathered[pkg_name] = m
                try:
                    check_prior_failed(gathered)
                    result = probe(requirements, gathered, options,
                                   indent=indent+1)
                except RequirementException as e:
                    if not isinstance(e, PriorRequirementException):
                        print("%sUndoing decision to select '%s' since we"
                              " %s that work along side it + the currently"
                              " gathered requirements..." % (prefix, m, e))
                        save_failure(gathered)
                    else:
                        print("%sUndoing decision to select '%s' since we"
                              " %s..." % (prefix, m, e))
                    gathered.pop(pkg_name)
                    requirements = before_mutation_requirements
                else:
                    gathered.update(result)
                    return gathered
            else:
                print("%sFailed: '%s' was not found to be compatible with the"
                      " currently gathered requirements (trying a"
                      " different version)..." % (prefix, pkg_req))
                requirements = before_mutation_requirements
        tried_and_failed.add(pkg_req.req)
    raise RequirementException("failed finding any valid matches"
                               " for %s" % list(tried_and_failed))


def main():
    parser = create_parser()
    options = parser.parse_args()
    if not options.requirements:
        parser.error("At least one requirement file must be provided")
    initial = parse_requirements(options)
    print("Initial package set:")
    dump_requirements(initial)
    for d in ['.download', '.versions']:
        scratch_path = os.path.join(options.scratch, d)
        if not os.path.isdir(scratch_path):
            os.makedirs(scratch_path)
    print("Probing for a valid set...")
    matches = probe(initial, {}, options, indent=1)
    print("Deep package set:")
    dump_requirements(matches)


if __name__ == "__main__":
    main()
