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
$ python pippin.py  -r requirements/global-requirements.txt
```

And wait ;-)

#### How it works:

1. Extract *desired* requirements from provided requirements files.
1. Set initially gathered/matched requirements to ``{}`` and begin probing.
1. Select a requirement ``X`` from *desired* requirements (and remove it).
1. Find version(s) of ``X`` on pypi that satisify its requirement restrictions (using a cache stored at ``.versions``) via the ``http://pypi.python.org/pypi/$pkg_name/json`` API.
1. Iterate over all versions ``Y`` from the version(s) of ``X`` that were found:
 1. Download version ``Y`` and extract its ``egg-info`` (using a cache stored at ``.downloads``).
 1. *Pick* that version ``Y`` (inserting it into the gathered/matched requirements).
 1. Check that the version ``Y`` of ``X`` selected is compatible along-side the  gathered/matched requirements.
    * If this ``aborts`` remove ``Y`` from being *picked* and force a new version ``Y`` of ``X`` to be checked (if no versions ``Y`` are left ``abort``).
 1. Extract that version ``Y`` dependencies (from its previously deteremined ``egg-info``) and create a new requirement set (and recurse at step #3; starting a new probe using a copy of the gathered/matched requirements but with this different *desired* requirement set).
    * If this ``aborts`` remove ``Y`` from being *picked* and force a new version ``Y`` of ``X`` to be checked (if no versions ``Y`` are left ``abort``).
 1. Probe deeper by recursing (starting again at step #3)
    * If this ``aborts`` remove ``Y`` from being *picked* and force a new version ``Y`` of ``X`` to be checked (if no versions ``Y`` are left ``abort``).

##### Example output(s) from actual run(s):

See the ``examples`` folder in this source tree.

[1]: http://www.customink.com/designs/stackpip/qvh0-0015-grtw/
