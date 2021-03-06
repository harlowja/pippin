# Pippin

#### Pippin ain't easy [1]

A *prototype* of a recursive backtracking pip dependency solver...

Get ready like:

```
$ virtualenv .venv
$ source .venv/bin/activate
$ pip install -r requirements.txt
```

Run like:                     

```
$ git clone git://git.openstack.org/openstack/requirements
$ python pippin.py -r requirements/global-requirements.txt
```

And wait ;-)

#### How it works:

1. Extract *desired* requirements from provided requirements files.
1. Set initially *gathered/matched* requirements to ``{}`` and begin probing.
1. Clone/copy *desired* requirements and *gathered/matched* requirements.
   * Required to avoid recursion affecting a prior probes
     requirements (needed since python is pass by reference for
     non-primitive types).
1. Select a requirement ``X`` from *desired* requirements (and remove it).
 1. Before this occurs; if no *desired* requirements (aka the *desired*
    requirement set is empty) left we have finished (**return**
    *gathered/matched* requirements from
    current probing level).
1. Find version(s) of ``X`` (currently only selecting ``sdist``
   distributions) on pypi that satisify specified requirement
   restrictions (using a cache stored at ``.versions``) via
   the ``pkg_tools.pypi`` API(s) [2].
1. Iterate over all versions ``Y`` (ordered from newest version
   to oldest version) from the version(s) of ``X`` that
   were found:
 1. Download version ``Y`` and extract its ``egg-info`` (using a cache
    stored at ``.downloads``).
 1. *Pick* that version ``Y`` (inserting it into the
    *gathered/matched* requirements).
 1. Check that the version ``Y`` of ``X`` selected is compatible along-side
    the *gathered/matched* requirements.
    * If this ``aborts`` remove ``Y`` from being *picked* and force a
      new version ``Y`` of ``X`` to be checked (if no versions ``Y`` are
      left ``abort``).
 1. Probe deeper by recursing (starting again at step #3) using
    current *gathered/matched* requirements (which has inserted
    version ``Y``).
    * If this ``aborts`` remove ``Y`` from being *picked* and force a new
      version ``Y`` of ``X`` to be checked (if no versions ``Y`` are
      left ``abort``).
 1. Check that the version ``Y`` of ``X`` selected is *still*
    compatible along-side the *gathered/matched* requirements using the
    resultant *gathered/matched* requirements from the prior step.
    * If this ``aborts`` remove ``Y`` from being *picked* and force a
      new version ``Y`` of ``X`` to be checked (if no versions ``Y`` are
      left ``abort``).
    * If this does **not** ``abort``:
       * Extract that version ``Y`` dependencies (from its previously
         determined ``egg-info``) and create a new requirement set (and recurse
         at step #3; starting a new probe with this **different** *desired*
         requirement set using the resultant *gathered/matched* requirements
         from the prior step).
         * If this ``aborts`` remove ``Y`` from being *picked* and force a
           new version ``Y`` of ``X`` to be checked (if no versions ``Y`` are
           left ``abort``).
         * If this does **not** ``abort`` merge *gathered/matched*
           requirements result from deeper probing into
           local *gathered/matched*
           requirements and **return** it.

##### Example output(s) from actual run(s):

See the ``examples`` folder in this source tree.

### Program argument help:

```
$ python pippin.py -h
usage: pippin.py [-h] [-r <file> [<file> ...]] [-s <path>] [--no-verbose]

optional arguments:
  -h, --help            show this help message and exit
  -r <file> [<file> ...], --requirement <file> [<file> ...]
                        Analyze all the packages listed in the given
                        requirements file
  -s <path>, --scratch <path>
                        Scratch path (used for caching downloaded data)
                        [default: $CWD]
  --no-verbose          Disable verbose output
```

### Notes

* Likely only works in python 2.6 or 2.7 (until further notice).

[1]: http://www.customink.com/designs/stackpip/qvh0-0015-grtw/
[2]: http://pkgtools.readthedocs.org
