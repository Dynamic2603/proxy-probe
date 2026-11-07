# proxy-probe (`pxp`)

**English** | [Русский](README.ru.md)

---

Universal tool for proxy testing, selection, and routing:
Refreshes subscriptions via URL or client database (e.g. Throne), launches isolated sandbox engines (`sing-box` / `Xray`), validates node capability for target CLI utilities and services (such as Antigravity `agy` and Gemini API) bypassing geo-restrictions (`User location is not supported`), classifies servers (`AGY-OK` / `AGY-BLOCK` / `DEAD`), and generates clean subscription files (`proxy-ok.txt`) and Markdown reports (`report.md`).

---

## Requirements

- **Python**: 3.11+ (fully tested on Python 3.11–3.14).
- **Package manager**: [uv](https://docs.astral.sh/uv/) (recommended).


## Usage

- **Via batch launcher**: `run.cmd`. Automatically sets UTF-8 encoding (`chcp 65001`), launches via `uv run pxp`, and pauses for user review before closing.
- **Via CLI (`uv`)**:
  ```bash
  uv run pxp [options]
  # or using the full command alias:
  uv run proxy-probe [options]
  ```

### CLI Examples
```bash
# Test the first 5 servers
uv run pxp --subset 5

# Run with 8 concurrent workers without confirmation prompt on exit
uv run pxp --jobs 8 --no-pause

# Force recheck all servers bypassing cache
uv run pxp --refresh-cache

# Automatically publish verified proxies to a GitHub Secret Gist
uv run pxp --gist <GIST_ID>
```

---

## Configuration via `.env`

Copy `.env.example` to `.env` to configure persistent environment variables:
```bash
copy .env.example .env
```
Supported variables:
- `PROXY_PROBE_GIST_ID`: GitHub Secret Gist ID for automatic remote subscription delivery.
- `GITHUB_TOKEN`: GitHub Personal Access Token (optional; defaults to `gh auth token` from GitHub CLI).
- `AGY_BIN`: Path to `agy.exe`.
- `AGY_MODEL`: Specific Gemini model preference (e.g. `gemini-2.5-flash-lite`).
- `THRONE_DIR`: Custom path to Throne data directory.
- `PROXY_PROBE_BIN_DIR`: Custom binary directory for engine caches.

---

## Caveats and Constraints

1. **Terms of Service**: No direct API calls using extracted OAuth tokens — probing uses the authentic `agy.exe` executable with your real signed-in account.
2. **Throne GUI Interference**: Active system proxy or active tunnel in Throne may route sandbox traffic through that parent tunnel rather than the tested proxy node. For pure results, disable system proxy / tunnels before running a batch.
3. **Transient AGY-OK**: Egress IP reputation on Gemini API can fluctuate over time.
4. **`agy models` is not a probe**: Banned egress IPs still allow listing models; the geo-gate only triggers on actual inference / print operations.
5. **`agyp` wrapper**: Optional helper script to run `agy` through a local proxy port (e.g., Throne on port 2080).
   Place on your PATH:
   ```bat
   @echo off
   set HTTP_PROXY=http://127.0.0.1:2080
   set HTTPS_PROXY=http://127.0.0.1:2080
   set ALL_PROXY=http://127.0.0.1:2080
   set NO_PROXY=
   agy.exe %*
   ```
6. **Results Cache**: Test statuses (`AGY-OK` / `AGY-BLOCK` / `DEAD`) are cached locally in `results.json` (keyed by `host:port`) to avoid redundant engine and CLI launches in subsequent runs.
   TTL per status: OK — 3 days, BLOCK — 7 days, DEAD — 1 day (`--ttl-ok`, `--ttl-blocked`, `--ttl-dead`; 0 = never expires; `UNKNOWN` is never cached).
   On collision of the same `host:port` across multiple configurations, resolution priority is: `BLOCK` > `AGY-OK` > `DEAD` (a broken duplicate profile does not downgrade an active BLOCK to DEAD).
   Cached `AGY-OK` servers are included in `proxy-ok.txt` alongside freshly tested ones.
7. **Quota Exhaustion Protection (`Individual quota reached`)**:
   - Automatically detects and uses the lightest available Flash model via `detect_best_agy_model` (configurable via `--agy-model` or `AGY_MODEL` env).
   - Rate limit smoothing via a concurrency semaphore for `agy` execution (`--agy-concurrency 2`), preventing burst HTTP 429 errors.
   - Fail-fast `QuotaCircuitBreaker`: when an account quota exhaustion error is encountered, subsequent `agy` invocations are immediately skipped; servers are verified via fast preflight/geo and marked `UNKNOWN` without cache pollution.
   - Pre-flight quota sanity check (`--skip-precheck` to bypass) detects quota status before initiating full batch scans.

---

## Connecting `proxy-ok.txt` as a Subscription in Throne

### Option A: Local File Subscription (Same PC)
Instead of manual one-time imports, `proxy-ok.txt` can be linked as an auto-updating local subscription (without setting up a local web server):

1. In Throne: **Groups** -> **Add Group**.
2. Configure settings:
   - **Name**: `PROXY-OK`
   - **Type**: `Subscription`
   - **Subscription URL**: `file:///C:/path/to/proxy-probe/proxy-ok.txt` *(replace with your system's absolute path; note the three slashes `file:///` before drive letter on Windows)*.
3. Clicking **Update** prompts Throne to read the local file via Qt's file engine (`QNetworkReplyFileImpl`) and automatically synchronize profiles (pruning invalid nodes and adding working ones).

### Option B: Remote Delivery via GitHub Secret Gist (Zero-Server Remote Sync)
To deliver verified proxies to mobile devices, laptops, or remote PCs without running web servers:

1. **Create a Secret Gist (once)**:
   ```bash
   gh gist create proxy-ok.txt --desc "Throne Proxy Pool"
   ```
   *(GitHub CLI creates an unlisted Secret Gist with a 128-bit hash ID, e.g. `5b0e0062eb8e9654adad7bb1d81cc75f`).*
2. **Configure auto-sync**:
   Set `PROXY_PROBE_GIST_ID=<GIST_ID>` in `.env` (or pass `--gist <GIST_ID>`).
   Every `pxp` run will automatically push the latest `proxy-ok.txt` to the Gist.
3. **In Throne on any device**:
   - **Subscription URL**: `https://gist.githubusercontent.com/<username>/<gist_id>/raw/proxy-ok.txt`
   - **Update Interval**: e.g., 30 or 60 minutes.
   - GitHub Fastly CDN caches this dynamic permalink for 5 minutes (`max-age=300`), ensuring all devices receive the latest verified proxies automatically.

---

## Roadmap (TODO)

- [ ] **Multi-target validation**: Pluggable probe modules for diverse tools and services.
- [ ] **Server badging on export**: Prefixing profile names with working target badges (e.g. `[AGY|GH] 🇩🇪 Germany`).
- [ ] **Autonomous local database**: Managing and rotating proxy pools independently of any specific client UI.
- [ ] **Extended client adapters**: Direct import/export for v2rayN, Clash Verge Rev / Mihomo, Nekoray, and raw sing-box configs.
- [ ] **Graphical User Interface (GUI)**: Desktop/web UI for visual pool management, target selection, and one-click testing.

---

## License

This project is licensed under the [MIT License](LICENSE).
