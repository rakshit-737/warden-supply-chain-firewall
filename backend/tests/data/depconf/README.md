# Dependency-confusion test fixtures

Everything in this directory is **synthetic test data** for `tests/test_dependency_confusion.py`.
Nothing here is real registry data: the presence (or absence) of a name in these files says nothing
about the real PyPI. `examplecorp-*` stands for a fictional organisation's internal package names;
index hosts use the reserved `example` domain and the credentials exist only to prove redaction.

| File | Models | Covers |
|---|---|---|
| `public_index_snapshot.txt` | Warden's snapshot format (`app.analysis.depconf.index_snapshot`) | header parsing, canonicalisation of non-canonical names, skipped malformed lines (spaces, invalid characters, leading separator, non-ASCII, an overlong line) |
| `public_index_snapshot.txt.gz` | the same bytes, gzip-compressed with `mtime=0` | gzip detection by magic bytes |
| `simple_index_pep691.json` | the shape of a PEP 691 JSON root index (`GET /simple/`, `application/vnd.pypi.simple.v1+json`) | snapshot builder: canonicalisation, de-duplication, skipped malformed entries |
| `requirements-private.txt.fixture` | a pip requirements file mixing a private `--index-url` with PyPI as `--extra-index-url` | project-level findings with real declaration lines |

The `.fixture` suffix keeps dependency scanners from treating the requirements file as a real manifest.
Large or hostile inputs (gzip bombs, huge lines, corrupt archives) are generated inside the tests.
