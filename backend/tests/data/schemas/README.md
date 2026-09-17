# Official JSON schemas (offline validation)

`tests/test_sbom_cyclonedx.py`, `tests/test_sbom_spdx.py` and `tests/test_sarif.py` validate generated documents against
these unmodified copies of the official schemas. A local `referencing` registry resolves the
cross-file `$ref`s, so validation never touches the network. They were downloaded with `curl`
on 2026-09-15.

| File | Source URL | sha256 |
|---|---|---|
| `bom-1.6.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json | `18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d` |
| `spdx.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/spdx.schema.json | `ea6e844ee6fba1e93473d94834d0ee0996970533497935f932f73d488ffdf4a3` |
| `jsf-0.82.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/jsf-0.82.schema.json | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |
| `sarif-schema-2.1.0.json` | https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json | `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` |
| `spdx-2.3.schema.json` | https://raw.githubusercontent.com/spdx/spdx-spec/support/2.3/schemas/spdx-schema.json | `ca7fd7cc2c8107c3b6b5976058bb72363e8c072f0e446609d4fe7234860c2894` |

`bom-1.6.schema.json` references `spdx.schema.json` (the SPDX license-id enumeration CycloneDX
publishes) and `jsf-0.82.schema.json` by relative `$ref`; both resolve against the
`http://cyclonedx.org/schema/` base of its `$id`.

About the SPDX 2.3 schema: the originally planned URL
`https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3/schemas/spdx-schema.json` now
returns HTTP 404, so the copy here comes from the maintained `support/2.3` branch. The `v2.3` tag
copy (sha256 `239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b`) differs from it
in one place: an extra `"name"` entry in one `required` list, which the `support/2.3` branch
removed.

The SARIF schema (`$id` is the OASIS errata01 URL) was downloaded on 2026-09-17 and is validated with
`jsonschema.Draft4Validator`; it has no external `$ref`s.
