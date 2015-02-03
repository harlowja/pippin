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
import logging
import os
import shutil
import sys
import tempfile
import traceback

from distutils import version as dist_version

from pip import req as pip_req

from pkgtools.pypi import PyPIJson
from pkgtools.pypi import real_name as pypi_real_name

import argparse
import requests
import six

LOG = logging.getLogger('pippin')

try:
    from pip import util as pip_util  # noqa
except ImportError:
    from pip import utils as pip_util  # noqa


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


def download_url_to(url, save_path):
    resp = requests.get(url)
    with open(save_path, 'wb') as fh:
        fh.write(resp.content)
    return resp.content


def parse_requirements(options):
    requirements = OrderedDict()
    for filename in options.requirements:
        try:
            entries = list(pip_req.parse_requirements(filename))
            for req in reversed(entries):
                if req_key(req) in requirements:
                    raise ValueError("Currently only one requirement for '%s'"
                                     " is allowed, merging is not currently"
                                     " supported" % req_key(req))
                requirements[req_key(req)] = req
        except Exception as ex:
            raise IOError("Cannot parse '%s': %s" % (filename, ex))
    return requirements


class EggDetailer(object):
    def __init__(self, options):
        self.options = options
        self.egg_cache = {}
        self.egg_fail_cache = {}

    def _get_directory_details(self, path):
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

    def _get_archive_details(self, filename, filesize):
        if not os.path.isfile(filename):
            raise IOError("Can not detail non-existent file %s" % (filename))
        cache_key = "f:%s:%s" % (os.path.basename(filename), filesize)
        if cache_key in self.egg_fail_cache:
            exc_type, exc_value, exc_traceback = self.egg_fail_cache[cache_key]
            six.reraise(exc_type, exc_value, exc_traceback)
        try:
            return self.egg_cache[cache_key]
        except KeyError:
            with tempdir() as a_dir:
                arch_filename = os.path.join(a_dir, os.path.basename(filename))
                shutil.copyfile(filename, arch_filename)
                extract_to = os.path.join(a_dir, 'build')
                os.makedirs(extract_to)
                pip_util.unpack_file(arch_filename, extract_to,
                                     content_type='', link='')
                try:
                    details = self._get_directory_details(extract_to)
                except Exception:
                    # Don't bother saving the traceback (we don't care
                    # about it...)
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    self.egg_fail_cache[cache_key] = (exc_type,
                                                      exc_value, None)
                    raise
                else:
                    self.egg_cache[cache_key] = details
                    return details

    def fetch(self, req):
        origin_filename = req.origin_filename
        origin_url = req.origin_url
        download_path = os.path.join(self.options.scratch,
                                     '.download', origin_filename)
        if not os.path.exists(download_path):
            download_url_to(origin_url, download_path)
        return self._get_archive_details(download_path, req.origin_size)


class PackageFinder(object):
    MAX_VERSIONS = 5

    def __init__(self, options):
        self.options = options
        self.no_sdist_cache = set()
        self.no_parse_cache = set()

    def match_available(self, pkg_req):
        looked_in = []
        useables = []
        available = self._find_releases(req_key(pkg_req))
        req = pkg_req.req
        for a in reversed(available):
            v = a.string_version
            if v in req:
                line = "%s==%s" % (req_key(pkg_req), v)
                m_req = pip_req.InstallRequirement.from_line(line)
                m_req.origin_url = a.origin_url
                m_req.origin_filename = a.origin_filename
                m_req.origin_size = a.origin_size
                useables.append(m_req)
                if len(useables) == self.MAX_VERSIONS:
                    break
            else:
                looked_in.append(v)
        if not useables:
            raise NotFoundException("No requirement found that"
                                    " matches '%s' (tried %s)" % (pkg_req,
                                                                  looked_in))
        else:
            return useables

    def _find_releases(self, pkg_name):
        def sorter(r1, r2):
            return cmp(r1[1], r2[1])
        version_path = os.path.join(self.options.scratch,
                                    ".versions", "%s.json" % pkg_name)
        shown_before = False
        if os.path.exists(version_path):
            shown_before = True
            with open(version_path, 'rb') as fh:
                pkg_data = json.loads(fh.read())
        else:
            real_pkg_name = pypi_real_name(pkg_name)
            if not real_pkg_name:
                raise ValueError("No pypi package named '%s' found" % pkg_name)
            pypi = PyPIJson(real_pkg_name, fast=True)
            pypi_data = pypi.retrieve()
            pkg_data = {}
            releases = pypi_data.get('releases', {})
            for version, release_urls in six.iteritems(releases):
                if not release_urls:
                    continue
                pkg_data[version] = release_urls
            if not pkg_data:
                raise ValueError("No pypi package release information for"
                                 " '%s' found" % pkg_name)
            with open(version_path, 'wb') as fh:
                fh.write(json.dumps(pkg_data, indent=4))
        releases = []
        for version, release_urls in six.iteritems(pkg_data):
            rel = rel_fn = rel_size = None
            for r in release_urls:
                if r['packagetype'] == 'sdist':
                    rel = r['url']
                    rel_fn = r['filename']
                    rel_size = r['size']
            rel_identity = "%s==%s" % (pkg_name, version)
            if not all([rel, rel_fn, rel_size]):
                if rel_identity not in self.no_sdist_cache:
                    LOG.warn("No sdist found for '%s==%s'", pkg_name, version)
                    self.no_sdist_cache.add(rel_identity)
            else:
                try:
                    m_rel = _MatchedRelease(
                        version, dist_version.LooseVersion(version),
                        rel, rel_fn, rel_size)
                    releases.append(m_rel)
                except ValueError:
                    if rel_identity not in self.no_parse_cache:
                        LOG.warn("Failed parsing '%s==%s'", pkg_name, version,
                                 exc_info=True)
                        self.no_parse_cache.add(rel_identity)
        releases = sorted(releases, cmp=sorter)
        if LOG.isEnabledFor(logging.DEBUG) and not shown_before:
            for rel in releases:
                LOG.debug("Found '%s' on pypi", rel.origin_url)
        return releases


class DeepExpander(object):
    def __init__(self, finder, detailer, options):
        self.options = options
        self.finder = finder
        self.detailer = detailer
        self.egg_fail_cache = set()

    def expand(self, pkg_req):
        possibles = self.finder.match_available(pkg_req)
        candidates = []
        for m in possibles:
            if not hasattr(m, 'details'):
                try:
                    m.details = self.detailer.fetch(m)
                except Exception as e:
                    if m.req not in self.egg_fail_cache:
                        LOG.warn("Failed detailing '%s'", m)
                        e_blob = str(e)
                        for line in e_blob.splitlines():
                            LOG.warn(line)
                        self.egg_fail_cache.add(m.req)
            if not hasattr(m, 'details'):
                continue
            deep_requirements = OrderedDict()
            dep_count = len(m.details['dependencies'])
            for dep in reversed(m.details['dependencies']):
                d_req = pip_req.InstallRequirement.from_line(
                    dep,
                    comes_from="dependency of %s (entry %s)" % (m, dep_count))
                deep_requirements[req_key(d_req)] = self.expand(d_req)
                dep_count -= 1
            candidates.append((m, deep_requirements))
        return candidates


def probe(requirements, options):
    if not requirements:
        return {}
    print("Expanding all requirements dependencies (deeply) and"
          " finding matching versions that will be installable.")
    print("Please wait...")
    finder = PackageFinder(options)
    detailer = EggDetailer(options)
    expander = DeepExpander(finder, detailer, options)
    expanded_requirements = OrderedDict()
    gathered = {}
    for (pkg_name, pkg_req) in six.iteritems(requirements):
        expanded_requirements[pkg_name] = (pkg_req, expander.expand(pkg_req))
    return gathered


def main():
    def req_cmp(a, b):
        return cmp(req_key(a), req_key(b))
    parser = create_parser()
    options = parser.parse_args()
    if not options.requirements:
        parser.error("At least one requirement file must be provided")
    if options.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(levelname)s: @%(name)s : %(message)s')
    else:
        logging.basicConfig(level=logging.INFO,
                            format='%(levelname)s: @%(name)s : %(message)s')
    initial = parse_requirements(options)
    for d in ['.download', '.versions']:
        scratch_path = os.path.join(options.scratch, d)
        if not os.path.isdir(scratch_path):
            os.makedirs(scratch_path)
    print("Initial package set:")
    for r in sorted(list(six.itervalues(initial)), cmp=req_cmp):
        print(" - %s" % r)
    print("Probing for a valid set...")
    try:
        matches = probe(initial, options)
    except Exception:
        traceback.print_exc(file=sys.stdout)
    else:
        print("Expanded package set:")
        for r in sorted(list(six.itervalues(matches)), cmp=req_cmp):
            print(" - %s" % r)


if __name__ == "__main__":
    main()
