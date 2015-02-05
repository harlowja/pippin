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
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile

from distutils import version as dist_version

import argparse
import networkx as nx
from networkx.algorithms import traversal
from pip import req as pip_req
from pkgtools.pypi import PyPIJson
from pkgtools.pypi import real_name as pypi_real_name
import requests
import six

LOG = logging.getLogger('pippin')

# Default URL downloading/fetching timeout...
TIMEOUT = 5.0

try:
    from pip import util as pip_util  # noqa
except ImportError:
    from pip import utils as pip_util  # noqa


class RequirementException(Exception):
    pass


class NotFoundException(Exception):
    pass


def parse_line(line, comes_from="???"):
    if line.startswith('-e') or line.startswith('--editable'):
        if line.startswith('-e'):
            line = line[2:].strip()
        else:
            line = line[len('--editable'):].strip().lstrip('=')
        req = pip_req.InstallRequirement.from_editable(line,
                                                       comes_from=comes_from)
    else:
        req = pip_req.InstallRequirement.from_line(line,
                                                   comes_from=comes_from)
    return req


class DiGraph(nx.DiGraph):
    """A directed graph subclass with useful utility functions."""
    def __init__(self, data=None, name=''):
        super(DiGraph, self).__init__(name=name, data=data)
        self.frozen = False

    def pformat(self):
        """Pretty formats your graph into a string.

        This pretty formatted string representation includes many useful
        details about your graph, including; name, type, frozeness, node count,
        nodes, edge count, edges, graph density and graph cycles (if any).
        """
        lines = []
        lines.append("Name: %s" % self.name)
        lines.append("Type: %s" % type(self).__name__)
        lines.append("Frozen: %s" % nx.is_frozen(self))
        lines.append("Nodes: %s" % self.number_of_nodes())
        for n in self.nodes_iter():
            lines.append("  - %s" % n)
        lines.append("Edges: %s" % self.number_of_edges())
        for (u, v, e_data) in self.edges_iter(data=True):
            if e_data:
                lines.append("  %s -> %s (%s)" % (u, v, e_data))
            else:
                lines.append("  %s -> %s" % (u, v))
        lines.append("Density: %0.3f" % nx.density(self))
        cycles = list(nx.cycles.recursive_simple_cycles(self))
        lines.append("Cycles: %s" % len(cycles))
        for cycle in cycles:
            buf = six.StringIO()
            buf.write("%s" % (cycle[0]))
            for i in range(1, len(cycle)):
                buf.write(" --> %s" % (cycle[i]))
            buf.write(" --> %s" % (cycle[0]))
            lines.append("  %s" % buf.getvalue())
        return os.linesep.join(lines)


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


def check_is_compatible_alongside(pkg_req, gathered):
    # If we conflict with the currently gathered requirements, give up...
    for req_name, other_req in six.iteritems(gathered):
        if req_key(pkg_req) == req_name:
            if pkg_req.details['version'] not in other_req.req:
                raise RequirementException("'%s==%s' not in '%s'"
                                           % (pkg_req.details['name'],
                                              pkg_req.details['version'],
                                              other_req))


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
        "-v", "--verbose",
        dest="verbose",
        action='store_true',
        default=False,
        help="Enable verbose output")
    parser.add_argument(
        "-t", "--timeout",
        dest="timeout",
        type=float,
        default=float(TIMEOUT),
        help="Connection timeout (default: %s)" % TIMEOUT)
    return parser


def download_url_to(url, options, save_path):
    resp = requests.get(url, timeout=options.timeout)
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
        req = parse_line(path)
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
            LOG.debug("Downloading '%s' -> '%s'", origin_url, download_path)
            download_url_to(origin_url, self.options, download_path)
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
                m_req = parse_line(line)
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
        def req_func(url, timeout=None):
            LOG.debug("Downloading '%s'", url)
            r = requests.get(url, timeout=timeout)
            return r.content
        def sorter(r1, r2):
            return cmp(r1[1], r2[1])
        version_path = os.path.join(self.options.scratch,
                                    ".versions", "%s.json" % pkg_name)
        if os.path.exists(version_path):
            with open(version_path, 'rb') as fh:
                pkg_data = json.loads(fh.read())
        else:
            real_pkg_name = pypi_real_name(pkg_name,
                                           timeout=self.options.timeout)
            if not real_pkg_name:
                raise ValueError("No pypi package named '%s' found" % pkg_name)
            pypi = PyPIJson(real_pkg_name, fast=True)
            pypi_data = pypi.retrieve(timeout=self.options.timeout,
                                      req_func=req_func)
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
        return sorted(releases, cmp=sorter)


class DeepExpander(object):
    def __init__(self, finder, detailer, options):
        self.options = options
        self.finder = finder
        self.detailer = detailer
        self.egg_fail_cache = set()

    def expand_many(self, pkg_reqs):
        graph = DiGraph()
        pkg_direct_deps = []
        for pkg_req in pkg_reqs:
            pkg_direct_deps.append(self._expand(pkg_req, graph))
        for pkg_req, direct_deps in zip(pkg_reqs, pkg_direct_deps):
            if not graph.has_node(pkg_req.req):
                graph.add_node(pkg_req.req, req=pkg_req)
            for m in direct_deps:
                if m.req != pkg_req.req:
                    graph.add_edge(pkg_req.req, m.req)
        return graph

    def _expand(self, pkg_req, graph):
        if graph.has_node(pkg_req.req):
            return [pkg_req]
        else:
            LOG.debug("Expanding matches for %s", pkg_req)
            graph.add_node(pkg_req.req, req=pkg_req)
        useables = []
        for m in self.finder.match_available(pkg_req):
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
            useables.append(m)
            graph.add_node(m.req, req=m, exact=True)
            if m.req != pkg_req.req:
                graph.add_edge(pkg_req.req, m.req)
            for dep in m.details['dependencies']:
                dep_req = parse_line(dep)
                dep_sols = []
                for dep_sol in self._expand(dep_req, graph):
                    graph.add_edge(m.req, dep_sol.req)
                    dep_sols.append(dep_sol)
                if not dep_sols:
                    raise ValueError("No solutions found for required"
                                     " dependency '%s' for '%s'"
                                     " (originating from requirement '%s')"
                                     % (dep_req, m, pkg_req))
        if not useables:
            raise ValueError("No working solutions found for required"
                             " requirement '%s'" % (pkg_req))
        return useables


def expand(requirements, options):
    if not requirements:
        return {}
    print("Expanding all requirements dependencies (deeply) and"
          " finding matching versions that will be installable into a"
          " directed graph...")
    print("Please wait...")
    # Cache it in the scratch dir to avoid recomputing...
    buf = six.StringIO()
    for (pkg_name, pkg_req) in six.iteritems(requirements):
        buf.write(pkg_req.req)
        buf.write("\n")
    graph_name = hashlib.md5(buf.getvalue().strip()).hexdigest()
    graph_name += str(PackageFinder.MAX_VERSIONS)
    graph_pickled_filename = os.path.join(
        options.scratch, '.graphs', "%s.gpickle" % graph_name)
    if os.path.exists(graph_pickled_filename):
        print("Loading prior graph from '%s" % graph_pickled_filename)
        return nx.read_gpickle(graph_pickled_filename)
    else:
        finder = PackageFinder(options)
        detailer = EggDetailer(options)
        graph = DiGraph(name=graph_name)
        expander = DeepExpander(finder, detailer, options)
        graph = expander.expand_many(list(six.itervalues(requirements)))
        nx.write_gpickle(graph, graph_pickled_filename)
        return graph


def dfs_path_iter(root, graph, level=0, only_exact=True):
    if only_exact:
        if graph.node[root].get('exact'):
            yield root, level
    else:
        yield root, level
    children = list(graph.successors_iter(root))
    for c in children:
        for c, child_level in dfs_path_iter(c, graph,
                                            level=level+1,
                                            only_exact=only_exact):
            yield c, child_level


def resolve(requirements, graph, options):
    solution_paths = OrderedDict()
    for pkg_name, pkg_req in six.iteritems(requirements):
        paths = list(dfs_path_iter(pkg_req.req, graph, level=1))
        solution_paths[pkg_name] = (pkg_req, paths)
        if options.verbose:
            LOG.debug("Solutions for '%s'" % pkg_req)
            for p, p_level in paths:
                indent = " " * p_level
                LOG.debug("%s%s" % (indent, p))
    return {}


def setup_logging(options):
    if options.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(levelname)s: @%(name)s : %(message)s')
    else:
        logging.basicConfig(level=logging.INFO,
                            format='%(levelname)s: @%(name)s : %(message)s')
    req_logger = logging.getLogger('requests')
    req_logger.setLevel(logging.WARNING)


def main():
    def req_cmp(a, b):
        return cmp(req_key(a), req_key(b))
    parser = create_parser()
    options = parser.parse_args()
    if not options.requirements:
        parser.error("At least one requirement file must be provided")
    setup_logging(options)
    initial = parse_requirements(options)
    for d in ['.download', '.versions', '.graphs']:
        scratch_path = os.path.join(options.scratch, d)
        if not os.path.isdir(scratch_path):
            os.makedirs(scratch_path)
    print("Initial package set:")
    for r in sorted(list(six.itervalues(initial)), cmp=req_cmp):
        print(" - %s" % r)
    graph = expand(initial, options)
    if options.verbose:
        print(graph.pformat())
    resolved = resolve(initial, graph, options)
    print("Resolved package set:")
    for r in sorted(list(six.itervalues(resolved)), cmp=req_cmp):
        print(" - %s" % r)


if __name__ == "__main__":
    main()
