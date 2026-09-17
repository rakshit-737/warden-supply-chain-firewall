# Dynamic analysis sandbox — design (not implemented)

Warden analyses packages statically and never executes them. This document describes an **optional**
dynamic layer that could observe what an install actually does. **None of it is built.** The only
code that exists is configuration (`SANDBOX_*` settings) and the `dynamic-sandbox` provenance value
reserved for findings. Settings validation refuses `SANDBOX_ENABLED=true`, so `GET /system/info`
always reports `sandbox: false` and no deployment can claim a layer that does not run.

## Why it is not the default

Running a suspected malicious package is exactly what its author wants. Static analysis covers the
classic payloads (install hooks, start-up hooks, encoded execution, credential access) without that
risk. A sandbox adds coverage for behaviour that only appears at run time — environment-dependent
payloads, second-stage downloads, time bombs — at the cost of a much larger attack surface. It must
therefore be opt-in, isolated from everything else, and its findings must never be required for a
verdict.

## Threat model

Assume the package is actively hostile and knows it may be sandboxed:

* it tries to escape the container or the kernel boundary;
* it tries to reach the network (exfiltration, C2, lateral movement to the database or Redis);
* it tries to exhaust resources (fork bombs, disk fill, memory);
* it detects the sandbox and behaves benignly (evasion);
* it produces output designed to exploit Warden's parsers (log injection, huge output).

## Proposed architecture

1. **Separate executor.** A worker process on a dedicated host or node pool — never inside the API
   container — pulls sandbox jobs from `scan_jobs` (kind `sandbox`). It has no database credentials
   beyond writing its own job result, and no access to Warden's secrets.
2. **Strong isolation.** Each job runs in a fresh gVisor (`runsc`) container (`SANDBOX_RUNTIME`;
   validation should accept no other runtime once the sandbox exists). Read-only root filesystem, a
   size-capped tmpfs work directory, `--network none`, all capabilities dropped, `no-new-privileges`,
   the default seccomp profile, a non-root user, and the memory / CPU / PID limits from `SANDBOX_MEMORY_MB`, `SANDBOX_CPUS`,
   `SANDBOX_PIDS_LIMIT`. A wall-clock limit (`SANDBOX_TIMEOUT_SECONDS`) kills the whole container.
3. **Pinned image.** `SANDBOX_IMAGE` must be an image pinned by digest containing only the Python
   interpreter and an in-container tracer; it is rebuilt through the same Trivy-gated pipeline as
   Warden's own images.
4. **What runs.** `pip install --no-deps --no-build-isolation` of the already-downloaded,
   hash-verified artifact (never a fresh download inside the sandbox), then `python -c "import <pkg>"`.
5. **Observation.** gVisor's syscall trace (`runsc --strace` or its monitoring interface) records
   process execution, file writes outside the work directory, attempted socket connections (which
   fail, but are recorded), and reads of credential paths. A fake-credential environment
   (honeytoken values in `~/.aws/credentials`, `GITHUB_TOKEN`, …) makes credential access observable
   without real secrets.
6. **Bounded, sanitised output.** The executor parses the trace into a fixed schema, caps every list
   and string, and emits standard `Finding` objects with provenance `dynamic-sandbox` (for example
   `NETWORK_EGRESS`, `SUBPROCESS_EXEC`, `PERSISTENCE`, `ENV_HARVEST`). Raw traces are never shown to
   users or stored unbounded.
7. **Fail safe.** A sandbox timeout, crash or unavailable runtime records the layer as
   unavailable; it never lowers risk and never blocks the static verdict.

## Open questions before building it

* Detection of sandbox-aware payloads (time checks, CPU count, container markers) and how far to
  imitate a developer machine.
* Whether observed network attempts should be answered by a fake DNS / HTTP sink to capture
  second-stage URLs, and how to keep that sink from becoming an exfiltration path.
* Cost: a gVisor container per scan is far slower than static analysis; it probably belongs behind a
  policy trigger (for example only for packages that static analysis rated medium or above).
* Operating requirements: gVisor needs Linux hosts that allow it; many managed platforms do not.

Until those are answered and the design has an independent security review, Warden stays
static-only.
