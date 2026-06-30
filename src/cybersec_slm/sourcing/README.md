# Sourcing: search-engine source discovery

`cybersec-slm source` finds **new** candidate cybersecurity sources by querying
a search engine with per–Sub-Domain keyword sets, maps each hit into the catalog's
row schema, drops anything already present, and appends the survivors to the local
catalog (`sources/Sources.csv`).

It's the inverse of [`ingestion/sources.py`](../ingestion/sources.py): that
module *reads* the catalog to drive ingestion; this one *grows* it.

Usage mirrors the prior `discovery` README but uses the `source` verb.
