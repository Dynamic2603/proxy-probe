# proxy-probe (`pxp`)

**English** | [Русский](README.ru.md)

---

Multi-stage proxy testing, selection, and Anti-DPI routing pipeline for Antigravity (`agy`) and Google Gemini API:
Refreshes subscriptions via URL and local Throne database, filters unreachable sockets via a fast L4 TCP prefilter (Stage 0), launches in-memory sandbox engines (`sing-box` / `Xray`) to select nodes free of Google regional restrictions (`AGY-OK` vs `AGY-BLOCK`, Stage 1), rescues DPI-blocked proxies through an isolated local Zapret2 relay with strict IP-whitelist WinDivert filtering (Stage 2), and generates ranked subscriptions (`proxy-ok.txt`) and analytical reports (`report.md`).

---

## Requirements

- **Python**: 3.11+ (fully tested on Python 3.11–3.14).
- **Package manager**: [uv](https://docs.astral.sh/uv/) (recommended).


## Usage

- **Unified interactive launcher (`run.cmd` / `uv run pxp`)**: Sets UTF-8 encoding (`chcp 65001`) and opens the interactive TUI menu in a persistent session loop:
  1. Probe and update proxy pool (`Stage 0 TCP -> Stage 1 Direct -> Stage 2 Anti-DPI` with Just-in-Time UAC).
  2. Start and stop the persistent background Zapret2 SOCKS5 relay (`127.0.0.1:10850`) for rescued `[zapret]` nodes in Throne (adaptive toggle in the TUI menu or CLI flags `uv run pxp --serve [--detach]`, `uv run pxp --stop-relay`, `uv run pxp --status-relay`).
  3. Calibrate Anti-DPI strategies for current ISP (Levels 2, 3, and 4 submenu or `uv run pxp --calibrate {2|3|4}`).
  4. Update catalogue of 484 Anti-DPI strategies from upstream (`uv run pxp --update-catalogue`).
  5. Prune dead (`DEAD`) entries from `results.json` (`uv run pxp --clear-dead`).
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

# Force recheck only dead servers, keeping cached AGY-OK and AGY-BLOCK
uv run pxp --refresh-dead

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
2. **Throne TUN (VPN) Mode Interference**: System proxy environment variables (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`) are automatically stripped before spawning child `sing-box` and `Xray` processes, but an active virtual network adapter (**TUN mode**) in Throne or another VPN client intercepts traffic at the OS routing layer — causing probes to exit through the parent tunnel rather than the tested proxy node. Disable TUN mode before running a batch.
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
6. **Results Cache, Reliability Scoring, Grace Period, and Network Outage Guard**:
   - Entries in `results.json` are keyed by `Server.cache_key` (`{host}:{port}:{engine}:{sha256(config_identity)[:8]}`), so distinct configurations and uTLS fingerprints sharing the same `host:port` (e.g. behind a CDN) are cached without collisions. On export to `proxy-ok.txt`, profiles are deduplicated by `endpoint_identity`, retaining the highest-ranked profile per `Server.export_rank`.
   - **Reliability Scoring ($0..100$)**: nodes receive a base score of 70 on first success, up to +20 bonus for consecutive successes, and latency penalties. Canonical tags include badges: `[95⭐]` for stable (`score >= 90`), `[70]` for active, and `[40⚠️]` for nodes on probation.
   - **Grace Period**: on a transient network failure (`DEAD`), a previously working node transitions to `DEGRADED` (probation 1/3 and 2/3) and remains in `proxy-ok.txt`. Terminal failures (`AGY-BLOCK` geo-restrictions) transition to `DEAD` immediately without probation.
   - **Local Network Outage Guard**: if at least 5 servers are probed in a run and 100% return `DEAD`, `consecutive_fails` penalties are suppressed for previously working (`ACTIVE`/`DEGRADED`) cache entries.
   - **Fast Pruning (`--clear-dead`)**: removes all `DEAD` entries from `results.json` while preserving `AGY-OK` and `AGY-BLOCK`.
   - TTL per status: OK — 3 days, BLOCK — 7 days, DEAD — 1 day (`--ttl-ok`, `--ttl-blocked`, `--ttl-dead`; 0 = never expires; `UNKNOWN` is never cached).

7. **Quota Exhaustion Protection (`Individual quota reached`) and High-Throughput Probing**:
   - Automatically detects and caches (for 24h in `results.json`) the lightest available Flash model via `detect_best_agy_model` (configurable via `--agy-model` or `AGY_MODEL` env).
   - Rate limit smoothing via a concurrency semaphore for `agy` execution (`--agy-concurrency 2`), preventing burst HTTP 429 errors.
   - Stage 0 L4 TCP prefilter runs across 200 threads (`--tcp-concurrency 200`), filtering dead TCP sockets before spawning engines (UDP protocols `hysteria2`/`tuic`/`wireguard` pass directly to Stage 1).
   - Online subscriptions are fetched in parallel (`fetch_subscriptions_batch`), and `results.json` is serialized compactly (`separators=(',', ':')`).
   - Fail-fast `QuotaCircuitBreaker`: when an account quota exhaustion error is encountered, subsequent `agy` invocations are immediately skipped; servers are verified via fast preflight/geo and marked `UNKNOWN` without cache pollution.
   - Pre-flight quota sanity check (`--skip-precheck` to bypass) detects quota status before initiating full batch scans.

8. **Zero-Quota Geo Precheck and Web Capability (`--check-web`)**:
   - Before spawning `agy`, a lightweight unauthenticated HTTP precheck is sent through the tunnel to `aistudio.google.com` (150–250ms).
   - If Google Edge already returns `403 Forbidden` or `User location is not supported`, the node is immediately classified as `AGY-BLOCK` without consuming account quota or the `agy` semaphore; nodes passing precheck proceed to full `agy` verification.
   - Control flags: `--no-geo-precheck`, `--geo-precheck-timeout` (default 2.5s).
   - `--check-web`: probes `gemini.google.com` to detect interactive Google CAPTCHA challenges (`google.com/sorry`), adding an informational `[captcha]` badge without disqualifying `AGY-OK` API capability.

9. **Isolated Anti-DPI Relay (Stage 2 Zapret2 and Per-ISP/ASN Ratings)**:
   - For servers whose TCP port is open (Stage 0) but whose TLS/protocol handshake fails in Stage 1, Stage 2 Anti-DPI runs automatically (`--antidpi`, disable via `--no-antidpi`).
   - `WinDivert` packet interception (`winws2.exe`) is strictly restricted to an explicit IP whitelist of the current batch (up to 150 IPs per batch) with zero global system traffic capture.
   - Rescued servers receive the `[zapret]` badge and are exported to `proxy-ok.txt` with `dialerProxy: "zapret-relay"` routed through the local SOCKS5 relay (`127.0.0.1:10850`, launched persistently via option 2 in `run.cmd` or `uv run pxp --serve`). If a previously rescued server later passes Stage 1 directly, its Zapret binding is automatically cleared in cache.
   - Strategy ratings (`data/antidpi_ratings.json`) are isolated per ingress ISP/ASN (`IspIdentity`, override via `--isp`); if the ISP cannot be determined, the tool fails fast without falling back to another network's profile.

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
