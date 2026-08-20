# Binary scanning: runtime evaluation

> Investigated 2026-08-20 on macOS 15 (arm64), Docker 29.4.0 via OrbStack,
> cve-bin-tool 3.4 (latest on PyPI), installed into a clean venv at
> `~/.oxaudit-tools/cve-bin-tool`.

Two questions: does the integration work against a real cve-bin-tool, and should
the tool environment be containerised the way [oxfuzz](https://github.com/HenryCooper86/oxfuzz)
containerises its fuzzing sandbox?

---

## 1. The headline finding

**cve-bin-tool 3.4 cannot bootstrap its CVE database today.** Every documented
data path fails, on the host and inside a clean container alike, and the tool
refuses to do *anything* — including SBOM generation — while the database is
empty (`cli.py:909` raises `CVEDataMissing` before any other work).

Seven attempts:

| # | Runtime | Invocation | Result |
|---|---|---|---|
| 1 | host | default | `FileNotFoundError: 'gsutil'` — undeclared external dependency |
| 2 | host | `-n json` | 0 entries; NIST retired the legacy JSON feeds |
| 3 | host | default, after `pip install gsutil` | instant `CVEDataMissing` — see the stale-cache trap below |
| 4 | host | `-n json-mirror -u now` | "Rolling back the cache", 0 entries |
| 5 | host | `-n api2 -u now` | **`ClientResponseError: 403`** on `nvd.nist.gov/rest/public/dashboard/statistics` |
| 6 | container | volume at `~/.cache/cve-bin-tool` | `OSError: [Errno 16] Device or resource busy` (our bug — see §3) |
| 7 | container | clean volume, gsutil present | identical `CVEDataMissing` |

Corroborating checks:

- The 403 in #5 reproduces for any client and any user agent — it is not a
  rate limit and not our environment. The endpoint is one NIST has locked down.
- `gs://cve-bin-tool`, the mirror bucket, returns **404 — bucket does not exist**.
- Network egress is fine: the NVD API (`services.nvd.nist.gov`) returns 200 and
  `cveb.in` returns 200 from this machine.
- `3.4.1rc0`, the only newer artifact on PyPI, still calls the same 403 endpoint
  (`nvd_api.py:26`).

So this is upstream breakage, not an integration fault and not a network fault.

### The stale-cache trap

Worth calling out because it is the one failure oxAudit can meaningfully soften.
A partly-completed bootstrap leaves ~1 GB in `~/.cache/cve-bin-tool` (mostly
`purl2cpe`) with `cve_severity` empty. cve-bin-tool's default `daily` refresh
policy then treats that cache as current, so every later run fails in under a
second with `No data in CVE Database` and **never retries on its own**. Without
being told, a user reads that as "oxAudit is broken".

`binscan::run::explain_failure` now names this case and points at a database
refresh, rather than surfacing a Python traceback. Same for the missing-`gsutil`
case.

---

## 2. Should we containerise, like oxfuzz?

**Yes — but as an optional runtime, and for a different reason than oxfuzz.**

oxfuzz *must* use Docker: fuzzing executes attacker-influenced code, so the
sandbox is a correctness requirement, which is why `hf-runtime` has no host
fallback and its `docker.rs` sets `--cap-drop=ALL`, `--network=none`,
`--pids-limit`, memory/CPU ceilings, pinned image digests and canonicalised
workspace confinement.

cve-bin-tool does not execute what it scans — it pattern-matches strings — so
the security case is weaker. The case that *does* hold up is *reproducibility*,
and this investigation is the evidence:

- **It has undeclared external dependencies.** `gsutil` for the mirror, and
  `cabextract` / `rpm2cpio` / `p7zip` / `zstd` / `binutils` for the archive
  formats firmware actually ships in. A native install silently lacks these and
  either crashes (failure #1) or quietly skips formats.
- **Python and pip resolution drift per machine.** The venv here resolved
  Python 3.13; the image pins 3.12.
- **Containment is a real secondary benefit.** cve-bin-tool *extracts*
  ZIP/RPM/DEB/CAB/APK archives to inspect them. Doing that to untrusted firmware
  under `--cap-drop=ALL --network=none` is meaningfully better than on the host.

What Docker does **not** fix: failures #2–#5. Those are upstream. A container
with a pre-warmed database baked in would work, but baking cve-bin-tool plus a
CVE snapshot into a published image means distributing GPL-3 software *and*
shipping data that goes stale.

### Licence note

`docker/cve-bin-tool/Dockerfile` is a **recipe, not a distribution**. The image
is built on the user's machine and pulls cve-bin-tool from PyPI there, so oxAudit
never distributes GPL software and no GPL obligation attaches to it. This mirrors
oxfuzz's `scripts/build-sandbox.sh` pattern. Do not push the built image to a
public registry without meeting those obligations.

---

## 3. What the container prototype taught us

A working `docker/cve-bin-tool/Dockerfile` is in the repo, built and exercised.
Two things that are not obvious:

- **Mount the CVE volume at `/home/scanner/.cache`, not at
  `/home/scanner/.cache/cve-bin-tool`.** cve-bin-tool `rmdir`s its own cache
  directory on the update-rollback path, which fails with `EBUSY` when a volume
  is mounted exactly there. This is failure #6 above; it cost a full run to find.
- **The database wants network; the scan does not.** Once the volume is warm,
  the scan itself can run `--network=none`. That two-phase split is the right
  shape and is what makes the containment argument real.

The invocation that the runtime would build:

```
docker run --rm \
  --cap-drop=ALL --security-opt no-new-privileges --pids-limit 512 \
  -v <target>:/scan:ro \
  -v oxaudit-cvedb:/home/scanner/.cache \
  -v <report-dir>:/out \
  --network=none \                      # bridge only for the refresh phase
  oxaudit/cve-bin-tool:3.4 \
  /scan --format json2 --output-file /out/report.json
```

This slots into the existing seam almost untouched: `detect::Invocation` is
already `{ program, leading_args }`, and `docker run … <image>` is just a
different program plus leading arguments. Path translation (host target →
`/scan`, and mapping container paths back for display) is the only new work.

---

## 4. Recommendation

1. **Keep the integration, keep the honest failure messages.** The parser,
   argument construction and safety properties are all tested and correct; the
   blocker is entirely upstream.
2. **Add Docker as an opt-in runtime**, not a requirement. Unlike oxfuzz there is
   no safety argument forcing it, and requiring Docker Desktop would put binary
   scanning out of reach for users who will not install it.
3. **Reconsider the dependency.** Given cve-bin-tool cannot currently function
   from a clean install, [syft + grype](https://github.com/anchore/grype)
   deserve a real evaluation: Apache-2.0 (no GPL friction), single static Go
   binaries (no Python, no undeclared helpers — so most of the Docker
   justification evaporates), and a database pipeline Anchore operates itself.
   They are weaker at "which OpenSSL is statically linked into this stripped
   ELF", which is cve-bin-tool's specialty — so the honest framing is that they
   solve *most* of the goal reliably, versus one that solves *all* of it and is
   currently broken.
