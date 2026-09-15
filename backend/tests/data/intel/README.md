# Vulnerability-intelligence test fixtures

**Everything in this directory is a synthetic test fixture.** None of it is real vulnerability
data, and none of it is used outside the test suite.

The files are shaped like responses from the public APIs Warden's `app.intel` package
talks to, so the parsers are tested against realistic structure:

| File | Modelled on |
|---|---|
| `osv_querybatch.json` | OSV `POST /v1/querybatch` response (https://google.github.io/osv.dev/post-v1-querybatch/) |
| `osv_vuln_*.json` | OSV `GET /v1/vulns/{id}` records (OSV schema, https://ossf.github.io/osv-schema/) |
| `kev_feed.json` | CISA KEV JSON feed (`known_exploited_vulnerabilities.json`) |
| `epss_response.json` | FIRST EPSS API `GET /data/v1/epss?cve=...` response |
| `nvd_cve.json` | NVD CVE API 2.0 `GET /rest/json/cves/2.0?cveId=...` response |

To make fixtures impossible to mistake for real records:

- advisory ids are fake (`GHSA-fx01-fx01-fx01`, `PYSEC-2099-1`, ...);
- CVE ids use the year **2099** (`CVE-2099-0001`, ...);
- packages are named `warden-fixture-pkg` / `unrelated-fixture-lib`;
- every URL uses the reserved `example.invalid` domain;
- summaries and descriptions start with "Synthetic fixture".

Some fixtures contain deliberately hostile or malformed content (a `javascript:` reference,
invalid KEV entries, a withdrawn advisory, an unrelated package in `affected`) to exercise the
parsers' validation.
