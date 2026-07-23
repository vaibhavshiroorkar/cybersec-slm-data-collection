"""Session-wide test setup.

The suite asserts against a known taxonomy: sub-domain names, their enum codes
and order, the domain aliases, and the schema's sub-domain enum are all pinned by
tests. Every one of those resolves through the *active profile*, which is
ordinarily read from ``sources/active_profile`` - a checked-in file any developer
may legitimately change to build a different corpus. Switching it to ``cybersec``
turned twelve tests red without a line of code changing, which made the suite a
report on local state rather than on the code.

So pin the profile the tests are written against. ``CYBERSEC_SLM_PROFILE``
outranks ``sources/active_profile`` (see ``sourcing.profiles``) and is documented
for exactly this, and ``setdefault`` leaves it overridable::

    CYBERSEC_SLM_PROFILE=cybersec pytest

This must happen at import time, before anything imports
``cybersec_slm.normalize.schema``: that module snapshots the taxonomy into
module-level constants when it is first imported (deliberately - see its
``_load_taxonomy`` docstring), so a fixture setting the variable later would be
too late to change what it bound. The root conftest is imported before any test
module, which is early enough.
"""

import os
import tempfile

from cybersec_slm.sourcing.taxonomies import DEFAULT_PROFILE

os.environ.setdefault("CYBERSEC_SLM_PROFILE", DEFAULT_PROFILE)

# Pin the data root away from the developer's corpus, for the same reason and with
# the same urgency as the profile.
#
# `core.data_root()` falls back to `os.getcwd()`, so any test that reaches real
# code without setting a root operates on the checkout it is running in. Most
# tests do set one (monkeypatch.setenv per test, which still wins over this), but
# "most" is not a safety property. A run of this suite moved a real 5GB corpus
# under the wrong profile, because a test called `cli.main()` without a root and
# the CLI's layout migration duly migrated the developer's data using the profile
# pinned above.
#
# Nothing the suite touches should ever be outside a temp directory. Set here, at
# import, because `core` freezes DATA_ROOT/DATA_DIR/LOGS the moment it is imported
# and the root conftest is the last place that runs before that.
os.environ.setdefault("CYBERSEC_SLM_DATA_ROOT",
                      tempfile.mkdtemp(prefix="cybersec-slm-tests-"))
