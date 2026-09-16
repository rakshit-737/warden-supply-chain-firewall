# Warden packaged Semgrep rules

`warden-python.yml` (rule-set version 1.0.0) is loaded by the semgrep adapter
(`app/analysis/analyzers/semgrep_scan.py`). The rules are designed to detect code structures that
are common in malicious Python packages. They provide **signals for review**, not verdicts: every
match becomes a `SEMGREP_FINDING` that Warden combines with its other analyzers, the correlation
engine and policy. They are not a complete malware detector.

Semgrep parses the package source as text. Nothing in a scanned package is imported or executed.

## Rules

Confidence is the base `warden_confidence`; "by context" values override it for matches in that
execution context (see [Context and confidence](#context-and-confidence)).

| Rule id | Severity | Confidence (base / by context) | Designed to detect |
|---|---|---|---|
| `warden.obfuscation.exec-decoded-payload` | ERROR → high | 0.85 | Taint from base64 / binascii / `codecs.decode` / `bytes.fromhex` / zlib / gzip / bz2 / lzma decoding into `exec`, `eval` or `compile` (packed loaders). |
| `warden.malicious_behavior.exec-network-payload` | ERROR → high | 0.9 | Data from `urllib`, `requests`, `httpx`, `urllib3`, `http.client` or a socket `recv` flowing into `exec` / `eval` / `compile` (droppers). |
| `warden.capability.shell-dynamic-command` | WARNING → medium | 0.55 / install 0.65, import 0.6, runtime 0.55, test 0.35 | `subprocess.*(..., shell=True)`, `subprocess.getoutput`, `os.system`, `os.popen` with a non-literal command. |
| `warden.install_time_execution.setup-network-call` | ERROR → high | 0.75 | Network calls at module top level (outside any `def`) of a `setup.py`. |
| `warden.credential_access.environ-dump-to-network` | ERROR → high | 0.85 | The whole `os.environ` (for example `dict(os.environ)`, `json.dumps(os.environ)`, `os.environ.copy()`, a comprehension over it) flowing into an HTTP, socket or SMTP sink. |
| `warden.malicious_behavior.marshal-loads-network-data` | ERROR → high | 0.85 | Network data flowing into `marshal.load(s)` (code-object loaders). |
| `warden.malicious_behavior.pickle-loads-network-data` | ERROR → high | 0.65 | Network data flowing into `pickle` / `_pickle` / `cPickle` / `dill` / `cloudpickle` `load(s)`. |
| `warden.malicious_behavior.persistence-write` | ERROR → high | 0.6 / install 0.9, import 0.85, runtime 0.6, test 0.4 | A string literal naming a shell start-up file, cron table, systemd unit, XDG autostart entry, macOS LaunchAgent/LaunchDaemon or Windows Startup folder flowing into a write (`open` with a `w`/`a`/`x`/`+` mode, `Path.write_text/write_bytes/open`, `shutil.copy*/move`, `os.symlink`). |
| `warden.malicious_behavior.ctypes-load-downloaded-library` | ERROR → high | 0.65 / install 0.9, import 0.85, runtime 0.65, test 0.4 | A file downloaded (`urlretrieve`, or a `requests` / `httpx` / `urlopen` response written with `open` or `write_bytes`) and then loaded with `ctypes.CDLL` / `PyDLL` / `WinDLL` / `OleDLL` / `*.LoadLibrary` in the same scope. |
| `warden.malicious_behavior.reverse-shell` | ERROR → high | 0.95 | A socket `connect` / `socket.create_connection`, `os.dup2(sock.fileno(), ...)` and a shell or interpreter start (`pty.spawn`, `os.exec*`, `os.spawnl`, `os.system`, `subprocess.*`) in one scope. |
| `warden.capability.raw-ip-url-request` | WARNING → medium | 0.6 / install 0.65, import 0.62, runtime 0.6, test 0.3 | A literal `http(s)://` or `ftp://` URL whose host is a public IPv4 address passed to `requests`, `httpx` or `urllib`. |

Severity mapping in the adapter: ERROR → high (weight 5), WARNING → medium (2), INFO → low (0.5).

## Calibration against policy

The policy engine gates capability hard-blocks and deny rules on finding confidence (default
`min_confidence: 0.7`). The rules are calibrated for that gate:

- **Capability-grade rules** (`warden.capability.*`) stay below 0.7 in every context, so a shell
  call or an IP-addressed request never blocks a package on its own.
- **Strong malicious structures** (decode→exec, download→exec, download→marshal, environment
  dump→network, reverse shell) are at or above 0.85.
- **Rules that legitimate software can trip** are below the gate when the match sits in a
  function body (runtime) and above it when the code runs on import or install:
  - `pickle-loads-network-data` (0.65): ML and caching libraries do download pickles. That is
    unsafe but usually not malicious.
  - `persistence-write` (runtime 0.6): shell-completion installers write `~/.bashrc` when a user
    asks them to; doing it on import (0.85) or install (0.9) is not legitimate.
  - `ctypes-load-downloaded-library` (runtime 0.65): some packages fetch a prebuilt library
    lazily, often with a digest check the rule cannot see.

`tests/test_semgrep_analyzer.py::test_rule_confidence_is_calibrated_against_the_policy_gate` pins
these properties.

## Metadata contract

Every rule has `id` (`warden.<category>.<name>`, where `<category>` is the Warden finding
category), `message`, `severity`, `languages: [python]` and `metadata` with:

| Key | Meaning |
|---|---|
| `category` | A Warden `Category` value. `pipeline` and `attack_chain` are refused (Warden produces those itself). Unknown values are kept only as `evidence.rule_category`. |
| `warden_code` | Hint naming the Warden code this rule corresponds to (for example `ENCODED_EXEC`). It sets the finding's capability tag. Pipeline codes and unknown codes are ignored. |
| `confidence` | Semgrep's label (`HIGH` / `MEDIUM` / `LOW`). Must agree with `warden_confidence` (≥0.8 HIGH, ≥0.6 MEDIUM, else LOW). |
| `warden_confidence` | Calibrated confidence as a **quoted decimal string** (`"0.85"`). |
| `warden_confidence_by_context` | Optional map over `install-time`, `import-time`, `runtime`, `test-file`. `runtime` must equal the base and `test-file` must be the lowest. |
| `likelihood`, `impact` | `HIGH` / `MEDIUM` / `LOW`, copied into evidence. |
| `cwe` | List of `"CWE-<n>: <name>"` strings. |
| `references` | List of `https://` URLs. |

Metadata values must be strings, integers, lists or maps. semgrep 1.177.0's rule loader rejects
YAML floats such as `0.85`: it exits with status 2 and prints no JSON. That is why confidences
are quoted.

Organisational rules may use the same keys. Without them a match gets confidence 0.5 (0.35 in a
test file), no category (the taxonomy default for `SEMGREP_FINDING` applies) and no capability tag.

## Context and confidence

The adapter records where a match executes in `evidence.context`:

- `test-file`: a `test`/`tests`/`testing` directory, `test_*.py`, `*_test.py`, `conftest.py`.
- `install-time`: any `setup.py`.
- `import-time`: module or class body, decorators, default argument values.
- `runtime`: function or lambda body.
- `unknown`: non-Python file, unparseable source, or no line number.

The context comes from the file path and Python's `ast` of the scanned text. The source is parsed,
never executed. Confidence precedence is: `warden_confidence_by_context[context]`, then
`warden_confidence`, then `confidence` (label), then 0.5. Matches in test files are multiplied by
0.7 unless the rule gives an explicit `test-file` value.

## Known false-positive and false-negative trade-offs

- Semgrep OSS taint tracking is **intraprocedural**. Flows split across functions or modules are
  not followed, for example a download in one helper and an `exec` in another.
- Reflective and runtime-built calls are not resolved: `getattr(builtins, "exec")`,
  `__import__("os").system`, or strings assembled from pieces. Import aliases (`import base64 as
  b64`, `from urllib.request import urlopen`) *are* resolved by semgrep.
- `setup-network-call` only matches calls lexically outside a `def`. A helper function that does
  the network call and is invoked at top level is not matched. Build backends configured in
  `pyproject.toml` / `setup.cfg` are not covered.
- `shell-dynamic-command` treats module-level string constants as literals (semgrep constant
  propagation). A shell command in a variable that semgrep cannot resolve is reported even when
  its value is trusted.
- `environ-dump-to-network` ignores single named variables (`os.environ["X"]`,
  `os.environ.get("X")`) and allowlist comprehensions over names. Forwarding the complete
  environment to a documented service is still reported. Exfiltration through DNS or a
  subprocess (`curl`) is not covered here.
- `persistence-write` needs a string literal containing the target path fragment. Paths built
  from separate pieces (`"." + "bashrc"`) and crontab edits through `subprocess` are missed.
- `raw-ip-url-request` covers public IPv4 literals only. Loopback, private, link-local (including
  cloud metadata), `0.x`, `255.x` and the public DNS-over-HTTPS resolvers `1.1.1.1`, `1.0.0.1`,
  `8.8.8.8`, `8.8.4.4`, `9.9.9.9`, `149.112.112.112` are excluded. IPv6 literals, decimal/hex IP
  encodings and URLs built at runtime are not matched.
- `reverse-shell` requires connect, `dup2` of the socket's `fileno()` and the shell start in one
  scope. Implementations that use `subprocess.Popen(..., stdin=sock)` without `dup2` are missed.

## Validation

- Structure: `tests/test_semgrep_analyzer.py` loads this file with `yaml.safe_load` and checks
  required keys, id format and uniqueness, the metadata contract, calibration, the absence of YAML
  floats, and that every regex compiles. It also unit-tests the raw-IP and persistence-path
  regexes against positive and negative inputs.
- Real engine: semgrep is not a Warden dependency and is not installed on CI. During development
  the rules were validated with semgrep 1.177.0, installed with pip into an isolated virtual
  environment outside the repository, on Windows 11:
  - `semgrep --validate --config warden-python.yml` reports no configuration errors.
  - The opt-in tests `test_real_semgrep_packaged_rules_fire_on_malicious_samples` and
    `test_real_semgrep_packaged_rules_stay_silent_on_benign_code` check that every rule fires at
    the expected file and line on inert synthetic samples, including evasion attempts
    (`# nosemgrep`, a `tests/` directory, hostile `.semgrepignore` / `.gitignore` files, lone-CR
    line endings). They also check that no rule fires on a benign corpus with one realistic module
    per rule.
  - To re-run them: `WARDEN_TEST_SEMGREP=/path/to/semgrep pytest tests/test_semgrep_analyzer.py -k real_semgrep`.

## Organisational rule sets

Operators add rule sets with `SEMGREP_EXTRA_CONFIGS`. Each entry must be a local YAML/JSON file or
directory that resolves, symlinks included, inside an allowlisted base directory. Registry names
(`p/...`, `r/...`, `auto`), URLs and UNC paths are refused because semgrep would download and run
remote rule content. See the adapter's module docstring for the full validation rules.
