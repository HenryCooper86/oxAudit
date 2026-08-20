# Binary scanning: runtime evaluation

> Investigated 2026-08-20 on macOS 15 (arm64), Docker 29.4.0 via OrbStack,
> cve-bin-tool 3.4 (latest on PyPI), installed into a clean venv at
> `~/.oxaudit-tools/cve-bin-tool`.

Two questions: does the integration work against a real cve-bin-tool, and should
the tool environment be containerised the way [oxfuzz](https://github.com/HenryCooper86/oxfuzz)
containerises its fuzzing sandbox?

---

## 0. Update — cve-bin-tool is fixable

Everything in §1 stands, but the cause turned out to be **two small upstream
bugs**, not a dead tool. With both patched at runtime, cve-bin-tool fetches
normally: `Adding 380851 CVE entries`.

**Bug 1 — a cosmetic preflight aborts everything.** `NVD_API.nvd_count_metadata`
(`nvd_api.py:82`) requests NIST's dashboard-statistics endpoint with
`raise_for_status=True`. NIST now returns 403 to every client. That count is only
used to size the fetch, and the NVD API reports `totalResults` itself
(380,851 at time of writing), so the request should not be fatal.

**Bug 2 — a failed run poisons the next one.** cve-bin-tool records a
`time_of_last_update` even when the fetch produced nothing. Every later run then
takes the *incremental* branch and asks for CVEs modified since that timestamp —
seconds ago — so it adds nothing and reports an empty database. `--update now`
does not help; only clearing the cache does.

The two interact, which is why this took seven runs to isolate: fixing the 403
alone still yields zero, because the stale timestamp routes you into the
incremental path. Both must be addressed together.

Worth filing upstream. Bug 1 is a `try`/`except` plus a `totalResults` fallback;
bug 2 is not recording an update time when nothing was ingested.


### The bootstrap is rate-limited to hours without an API key

With both patches in place the fetch starts correctly — `Adding 380851 CVE
entries` — but NVD's unauthenticated limit (5 requests / 30s) means the initial
download reaches only ~3% in ten minutes. That extrapolates to roughly **5½
hours**. An NVD API key raises the limit to 50 requests / 30s.

Two consequences:

- **Set an NVD API key before the first binary scan.** oxAudit already has the
  field in Settings and already forwards it to cve-bin-tool
  (`binscan::run::build_args`), so this costs nothing but is easy to miss.
- **An interrupted bootstrap recreates the §0 bug 2 trap**, because the partial
  run still records an update time. Any "refresh" path we ship should clear the
  cache first rather than only passing `--update now`.

---

## 1. How it presents before you know the cause

**cve-bin-tool 3.4 cannot bootstrap its CVE database.** Every documented
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
3. **Keep cve-bin-tool, and carry the fix in our image.** See §5 for the
   measured comparison against grype. Since the patch cannot be applied to a
   user's own installation without fighting their package manager, the container
   is the natural place to carry it — which is a far stronger argument for
   Docker than reproducibility alone.


---

## 5. Measured against grype

Same target, same machine: 15 MB of real macOS dylibs and binaries — OpenSSL
(`libssl`, `libcrypto` 3.x), `libzstd`, `/usr/bin/curl`.

| | cve-bin-tool 3.4 | grype 0.117.0 |
|---|---|---|
| Licence | GPL-3.0-or-later | Apache-2.0 |
| Install | Python + venv + undeclared `gsutil`, `cabextract`, `rpm2cpio`, `p7zip`, `zstd` | single static Go binary (`brew install grype`) |
| First run | seven failures before a patch made it work | **worked first try**, 86s including database download |
| Database | ~1 GB, NVD bootstrap broken without the §0 patch | ~200 MB from Anchore's own infrastructure |
| Components found | ~450 purpose-built checkers (should catch all four families) | **1 of 4** — only `curl 8.7.1` |
| Findings | — (bootstrap still running at time of writing) | 34 CVEs: 4 critical, 9 high, 18 medium, 3 low |
| Output quality | vendor/product/version, CVSS, EPSS, paths | CVE, severity, CVSS, **fix state**, EPSS, KEV |

grype detected **only `curl`**. It missed OpenSSL and zstd entirely, because its
strength is package metadata (containers, distro packages, language manifests)
and its binary classifiers cover a limited set. cve-bin-tool's ~450 checkers
exist precisely for "which OpenSSL is linked into this stripped object".

So the trade is real and neither tool dominates:

- **grype** is dramatically easier to operate and gives richer per-CVE data
  (notably fix state), but sees far less inside raw binaries.
- **cve-bin-tool** sees much more, and is now known to be fixable, but needs the
  §0 patch and a heavier environment.

They are complementary rather than competing: grype for package- and
container-shaped targets, cve-bin-tool for firmware and stripped binaries.
Running both and merging by (component, version) would cover more than either.

---

## 6. Measured — and the conclusion that follows

> Added 2026-08-20. §5 left the cve-bin-tool findings column empty because its
> bootstrap was still running. It has since completed, and the comparison can be
> finished with numbers instead of expectations.

### cve-bin-tool does run — the NVD source is the part that is broken

Passing `-d NVD,PURL2CPE` skips the rate-limited source entirely and populates
from Red Hat, GitLab and OSV instead. It **completed in about eight minutes**
with no API key, ingesting 24,336 Red Hat and 39,454 GitLab entries, and wrote a
genuine `json2` report. So the 5½-hour figure in §0 is a property of the NVD
path, not of the tool.

The catch: without NVD the database has far less CPE coverage. On the §5 corpus
it found CVEs for `curl` only — ten of them — where the full database would also
cover OpenSSL. It is a usable fallback, not a replacement.

That report is now checked in as `src-tauri/tests/fixtures/cve_bin_tool_3.4_json2.json`
and two tests parse it. Until now every parser test used a fixture we wrote
ourselves, which could only confirm our own assumptions about the schema.

### The detection comparison, on a firmware-shaped target

A Debian rootfs (21,279 files) with `var/lib/dpkg`, `usr/share/doc` and the
Python `dist-info` directories removed — the shape real firmware has.

| | components | time | notes |
|---|---|---|---|
| grype, metadata intact | 184 | 2.7 s | 2,003 CVE matches — its natural target |
| **grype, stripped** | **11** | 2.7 s | collapses; finds only what ELF notes and a few classifiers give it |
| **cve-bin-tool, stripped** | **54** | **300 s** | 365 checkers, detection only (its database cannot map most of them) |
| **oxAudit native, stripped** | **30** | **0.5 s** | 22 signatures + the ELF package note |

Read carefully, because the headline numbers mislead:

- grype losing 184 → 11 is the whole argument for having a binary scanner at
  all. Package metadata is not present in firmware.
- cve-bin-tool's 54 is genuinely more than our 30, and that gap is *coverage* —
  365 curated signatures against 22. It is the one thing it still does better.
- Our 0.5 s against its 300 s is **600×**, and is not a micro-optimisation: it
  is one `RegexSet` pass per file instead of 365 sequential checker evaluations.
- We find things both miss. `libzstd 1.5.7` comes from the ELF package note,
  which neither tool reads; zstd has no version string, so no signature can
  find it.

### Recommendation, revised

**Ship the native scanner as the default and keep cve-bin-tool as optional.**

The native scanner has no database to bootstrap, so every failure mode in §0–§1
simply does not apply to it. It runs in half a second, is cross-platform without
Docker, and carries no GPL relationship. cve-bin-tool remains worth offering to
a user who has it, because 365 signatures beat 22 — but it can no longer be the
thing standing between the user and a working scan.

Docker (§2) drops from "frequently the runtime that works" to "one option for
running cve-bin-tool", because the capability it was carrying now exists
natively.

### CVE enrichment — done, and it needed two sources

The native scanner now attaches CVEs, using each source where it is
authoritative. This is not redundancy; a given detection can only be answered by
one of them:

| Detection | Carries | Asked of | Why the other cannot answer |
|---|---|---|---|
| Signature | CPE vendor + upstream version | **NVD** | OSV has no ecosystem for a bare upstream library |
| ELF package note | distro package + packaged version | **OSV** | NVD needs a CPE vendor, which the note does not carry |

Both directions were measured against the live APIs rather than assumed:

- `virtualMatchString=cpe:2.3:a:openssl:openssl:3.0.2` → **56 CVEs**. The same
  query with `*` in the vendor position → **0**. NVD does not treat it as a
  wildcard, so there is genuinely no CPE query for a component whose vendor we
  do not know, and a package note never supplies one.
- `{"ecosystem":"Debian","name":"curl","version":"7.88.1-10+deb12u5"}` → **68**
  entries. The release is deliberately left off the ecosystem: OSV answers
  across all of them, and the note says which distribution built the binary,
  never which release it runs on.

This is why `Detection` carries both version forms. Normalizing to one would
make the other silently return nothing: OSV compares against `1.5.7+dfsg-1`, and
NVD is keyed on `1.5.7`.

End to end on three Debian binaries: `libzstd 1.5.7` → CVE-2022-4899, rated
high, **fixed in 1.5.4+dfsg2-1**. Neither cve-bin-tool nor grype found that
component at all, and cve-bin-tool never reports a fix version.

Two defects found by running it rather than by reading it:

- **OSV's `/v1/querybatch` returns ids and modification times only.** One
  request for everything looked like the obvious win, and it produced four real
  Debian findings each rated "unknown" with no remediation — a summary reading
  "0 critical, 0 high" that invites the reader to relax. `/v1/query` per
  component returns full records; OSV is not rate-limited the way NVD is.
- **Debian's OSV records carry no `aliases` array.** The CVE number appears only
  inside the id, so `DEBIAN-CVE-2022-4899` was being reported verbatim — an
  identifier that cannot be looked up anywhere.

The remaining sharp edge is NVD's rate limit: five requests per thirty seconds
without an API key, one request per component. A scan is capped at 100 NVD
lookups and *says so* when it caps, rather than returning a short list.

### Still open

- **Signature coverage.** 22 against cve-bin-tool's 365. `tools/derive-signatures.py`
  makes extending this mechanical.
- **Merge keys ignore version normalization.** `grype.rs` stores
  `artifact.version` verbatim, so grype's `mariadb 1:11.8.6-0+deb13u1` will never
  merge with a native or cve-bin-tool `11.8.6`. `package_note::upstream_version`
  is the function that fixes it; it is not yet applied on the grype path.
- **No LICENCE file.** oxAudit has none, so it is all-rights-reserved by
  default and its relationship to GPL tooling is undefined.
