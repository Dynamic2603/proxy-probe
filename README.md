# proxy-probe (`pxp`)

**English** | [Русский](README.ru.md)

---

Universal tool for proxy testing, selection, and routing:
Refreshes subscriptions via URL or client database (e.g. Throne), launches isolated sandbox engines (`sing-box` / `Xray`), validates node capability for target CLI utilities and services (such as Antigravity `agy` and Gemini API) bypassing geo-restrictions (`User location is not supported`), classifies servers (`AGY-OK` / `AGY-BLOCK` / `DEAD`), and generates clean subscription files (`proxy-ok.txt`) and Markdown reports (`report.md`).

---


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
```

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

---

## Connecting `proxy-ok.txt` as a Subscription in Throne

Instead of manual one-time imports, `proxy-ok.txt` can be linked as an auto-updating local subscription (without setting up a local web server):

1. In Throne: **Groups** -> **Add Group**.
2. Configure settings:
   - **Name**: `PROXY-OK`
   - **Type**: `Subscription`
   - **Subscription URL**: `file:///C:/path/to/proxy-probe/proxy-ok.txt` *(replace with your system's absolute path; note the three slashes `file:///` before drive letter on Windows)*.
3. Clicking **Update** prompts Throne to read the local file via Qt's file engine (`QNetworkReplyFileImpl`) and automatically synchronize profiles (pruning invalid nodes and adding working ones).

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