# Sourcing — search-engine source discovery

`cybersec-slm source` finds **new** candidate cybersecurity sources by querying
a search engine with per–Sub-Domain keyword sets, maps each hit into the
finalized tracking sheet's row schema, drops anything already in the sheet, and
appends the survivors back to the Google Sheet.

It's the inverse of [`extraction/sources.py`](../extraction/sources.py): that
module *reads* the sheet to drive ingestion; this one *grows* the sheet.

Usage mirrors the prior `discovery` README but uses the `source` verb.
