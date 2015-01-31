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

try:
    from collections import OrderedDict  # noqa
except ImportError:
    from ordereddict import OrderedDict  # noqa

import collections
import contextlib
import json
import os
import shutil
import sys
import tempfile
import traceback

from distutils import version as dist_version

from pip import req as pip_req

import argparse
import requests
import six
from six.moves import urllib

try:
    from pip import util as pip_util  # noqa
except ImportError:
    from pip import utils as pip_util  # noqa


_FINDER_URL_TPL = 'http://pypi.python.org/pypi/%s/json'

# Egg info cache and url fetch caches...
_EGGS_DETAILED = {}
_FINDER_LOOKUPS = {}
_EGGS_FAILED_DETAILED = {}


class RequirementException(Exception):
    pass


class NotFoundException(Exception):
    pass


_MatchedRelease = collections.namedtuple('_MatchedRelease',
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


def get_archive_details(filename, filesize, options, prefix=""):
    if not os.path.isfile(filename):
        raise IOError("Can not detail non-existent file %s" % (filename))
    cache_key = "f:%s:%s" % (os.path.basename(filename), filesize)
    if cache_key in _EGGS_FAILED_DETAILED:
        exc_type, exc_value, exc_traceback = _EGGS_FAILED_DETAILED[cache_key]
        six.reraise(exc_type, exc_value, exc_traceback)
    try:
        return _EGGS_DETAILED[cache_key]
    except KeyError:
        if options.verbose:
            print("%s: Extracting egg-info from '%s'"
                  % (prefix, os.path.basename(filename)))
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
        "--no-verbose",
        dest="verbose",
        action='store_false',
        default=True,
        help="Disable verbose output")
    return parser


def download_url_to(url, save_path, options, size=None, prefix=""):
    if size is not None:
        kb_size = size // 1024
        if options.verbose:
            print("%s: Downloading '%s' (%skB) -> '%s'" % (prefix, url,
                                                           kb_size, save_path))
    else:
        if options.verbose:
            print("%s: Downloading '%s' -> '%s'" % (prefix, url, save_path))
    resp = requests.get(url)
    with open(save_path, 'wb') as fh:
        fh.write(resp.content)
    return resp.content


def parse_requirements(options):
    all_requirements = OrderedDict()
    for filename in options.requirements:
        try:
            for req in pip_req.parse_requirements(filename):
                all_requirements.setdefault(req_key(req), []).append(req)
        except Exception as ex:
            raise IOError("Cannot parse '%s': %s" % (filename, ex))
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
                                               version_path,
                                               options, prefix=prefix))
    releases = []
    for v, release_infos in six.iteritems(resp_data['releases']):
        rel = rel_fn = rel_size = None
        for r in release_infos:
            if r['packagetype'] == 'sdist':
                rel = r['url']
                rel_fn = r['filename']
                rel_size = r['size']
        if not all([rel, rel_fn, rel_size]):
            print("ERROR: no sdist found for '%s==%s'"
                  % (pkg_name, v), file=sys.stderr)
            continue
        try:
            m_rel = _MatchedRelease(
                v, dist_version.LooseVersion(v),
                rel, rel_fn, rel_size)
            releases.append(m_rel)
        except ValueError:
            print("ERROR: failed parsing '%s==%s'"
                  % (pkg_name, v), file=sys.stderr)
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
        download_url_to(origin_url, download_path, options,
                        size=req.origin_size, prefix=prefix)
    return get_archive_details(download_path, req.origin_size, options,
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
                print("%s: Found '%s' as able to satisfy '%s'"
                      % (prefix, m_req, req))
            m_req.origin_url = a.origin_url
            m_req.origin_filename = a.origin_filename
            m_req.origin_size = a.origin_size
            useables.append(m_req)
        else:
            looked_in.append(v)
    if not useables:
        raise NotFoundException("No requirement found that"
                                " matches '%s' (tried %s)" % (req, looked_in))
    else:
        return useables


def deep_iter_dependencies(pkg_req, chain,
                           options, prefix=""):
    for _c in chain:
        prefix += "."
    pkg_name = req_key(pkg_req)
    possibles = match_available(pkg_req.req,
                                find_versions(pkg_name, options,
                                              prefix=prefix),
                                options,
                                prefix=prefix)
    for m in possibles:
        if m.req in chain:
            continue
        m_chain = list(chain)
        m_chain.append(m.req)
        yield m, m_chain
        if not hasattr(m, 'details'):
            try:
                m.details = fetch_details(m, options, prefix=prefix)
            except Exception as e:
                print("ERROR: failed detailing '%s'"
                      % (m), file=sys.stderr)
                e_blob = str(e)
                for line in e_blob.splitlines():
                    print("%s" % (line), file=sys.stderr)
        if not hasattr(m, 'details'):
            continue
        for other_dep in m.details.get('dependencies', []):
            d_req = pip_req.InstallRequirement.from_line(other_dep)
            for d_d_req, d_chain in deep_iter_dependencies(d_req, m_chain,
                                                           options=options,
                                                           prefix=prefix):
                yield d_d_req, d_chain


def check_is_compatible_alongside(pkg_req, gathered,
                                  options, probe_level=1,
                                  compat_level=1):
    prefix = '%s:%s (c)' % (probe_level, compat_level)
    if options.verbose:
        print("%s: Checking if '%s' is compatible along-side:" % (prefix,
                                                                  pkg_req))
        for name, other_req in six.iteritems(gathered):
            print("%s: - %s==%s" % (prefix, name,
                                    other_req.details['version']))
            for other_dep in other_req.details['dependencies']:
                print("%s:  + %s" % (prefix, other_dep))
    for req_name, other_req in six.iteritems(gathered):
        # If we conflict with the currently gathred requirements, give up...
        if req_key(pkg_req) == req_name:
            if pkg_req.details['version'] not in other_req.req:
                raise RequirementException("'%s==%s' not in '%s'"
                                           % (pkg_req.details['name'],
                                              pkg_req.details['version'],
                                              other_req))
    # Search the versions of this package which will work and now deeply
    # expand there dependencies to see if any of those cause issues...
    possibles = match_available(pkg_req.req,
                                find_versions(pkg_req.details['name'],
                                              options, prefix=prefix),
                                options,
                                prefix=prefix)
    passed = 0
    for m in possibles:
        if not hasattr(m, 'details'):
            try:
                m.details = fetch_details(m, options,
                                          prefix=prefix)
            except Exception as e:
                print("ERROR: failed detailing '%s'"
                      % (m), file=sys.stderr)
                e_blob = str(e)
                for line in e_blob.splitlines():
                    print("%s" % (line), file=sys.stderr)
        if not hasattr(m, 'details'):
            continue
        failed = False
        for dep in m.details['dependencies']:
            d_req = pip_req.InstallRequirement.from_line(dep)
            requirements = {
                req_key(d_req): [d_req],
            }
            try:
                probe(requirements, gathered,
                      options, probe_level=probe_level+1,
                      compat_level=compat_level)
            except RequirementException:
                failed = True
                break
        if not failed:
            passed += 1
    if not passed:
        raise RequirementException("No working requirement found"
                                   " for '%s'" % pkg_req.details['name'])


def probe(requirements, gathered, options,
          probe_level=1, compat_level=1):
    if not requirements:
        return gathered
    # Pick one of the requirements, get a version that works with the
    # current known siblings (other requirements that are requested along
    # side this requirement) and then recurse trying to get another
    # requirement that will work, if this is not possible, backtrack and
    # try a different version instead (and repeat)...
    prefix = '%s:%s (p)' % (probe_level, compat_level)
    gathered = gathered.copy()
    requirements = requirements.copy()
    pkg_name, pkg_requirements = requirements.popitem()
    print("%s: Probing for valid match for %s [%s]"
          % (prefix, pkg_name, ",".join([str(r) for r in pkg_requirements])))
    for pkg_req in pkg_requirements:
        possibles = match_available(pkg_req.req,
                                    find_versions(pkg_name, options,
                                                  prefix=prefix),
                                    options,
                                    prefix=prefix)
        for m in possibles:
            if not hasattr(m, 'details'):
                try:
                    m.details = fetch_details(m, options, prefix=prefix)
                except Exception as e:
                    print("ERROR: failed detailing '%s'"
                          % (m), file=sys.stderr)
                    e_blob = str(e)
                    for line in e_blob.splitlines():
                        print("%s" % (line), file=sys.stderr)
            if not hasattr(m, 'details'):
                continue
            gathered[pkg_name] = m
            try:
                check_is_compatible_alongside(m, gathered, options,
                                              probe_level=probe_level,
                                              compat_level=compat_level+1)
                result = probe(requirements, gathered,
                               options,
                               probe_level=probe_level+1,
                               compat_level=compat_level)
            except RequirementException as e:
                if options.verbose:
                    print("%s: Undoing decision to select '%s'"
                          " due to %s" % (prefix, m, e))
                gathered.pop(pkg_name)
            else:
                gathered.update(result)
                return gathered
    raise RequirementException("No working requirement found for '%s'"
                               % pkg_name)


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
    matches = OrderedDict()
    try:
        matches = probe(initial, matches, options)
    except Exception:
        traceback.print_exc(file=sys.stdout)
    else:
        print("Deep package set:")
        dump_requirements(matches)


if __name__ == "__main__":
    main()
