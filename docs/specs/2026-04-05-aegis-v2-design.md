# Aegis v2.6.0 — "Safety Pin & Proper Detection" design

**Spec date:** 2026-04-05
**Author:** (overnight autonomous session)
**Status:** DRAFT — awaiting Chris's morning review and approval
**Scope:** Five coordinated changes (buckets A–E) to fix two confirmed bugs, add two new features, and replace the broken C2 beacon detector with a real one.

---

## 0. Motivation

The audit that preceded this spec uncovered:

1. **Two real bugs** in the C2 beacon detector (`src/modules/network/mod.rs`) and the response engine (`src/response/mod.rs`). Together they can cause Aegis to firewall-block legitimate infrastructure IPs (Anthropic API, GitHub, CloudFront). Evidence: the user's current `AEGIS_BLOCK` chain already contains `13.224.185.{97,100,102,127}` (CloudFront) and `140.82.112.{25,26}` (GitHub) with 19,000–23,000 dropped packets each. See `docs/TRIAGE_PHASE_A0.md`.
2. **One dead config field** (`c2_beacon_window`) that suggests the detector was originally designed to be time-windowed but was never implemented that way.
3. **A missing feature** the user asked for explicitly: first-offense permanent ban for high-severity threat types like `path_traversal` and `web_ddos`. The strike-based escalation primitive exists (`state.rs:428-465`) but is wired up as "N strikes in 30 days," not "zero tolerance on type X."
4. **A drift risk** between `block_list.json` and the live `AEGIS_BLOCK` chain. The audit found ~700 iptables rules but only ~143 entries in `block_list.json`. Some drift is from stale rules surviving across restarts; some is from manual iptables edits that never made it back to the persistence layer.
5. **No destination reputation enrichment.** When Aegis sees an outbound connection to a suspicious IP, the only context it has is whether the IP is in a static threat-intel feed. It has no concept of "is this IP owned by Cloudflare / Anthropic / Amazon CloudFront / etc." This is exactly the signal that would have prevented the current false positives.

---

## 1. Design decisions & trade-offs

These are the choices made in this spec. Chris should review and override anything he disagrees with.

### 1.1 On the C2 beacon bug fix: **change semantics of `source_ip` or add a new field?**

**Decision:** **Keep `source_ip` semantics consistent with the rest of the codebase** (= the *adversary* IP, which for port scans is the remote IP, for brute force is the remote IP, for c2_beacon is also the remote C2 server IP). **Add two new optional fields to the `details` HashMap on the threat event: `local_ip` and `local_port`.** This means the "source" field continues to mean "who we should consider blocking" (which is what the response engine wants), while the local endpoint is captured for forensic triage.

**Why not a new top-level `local_endpoint: Option<SocketAddr>` field on `ThreatEvent`?** Because changing the `ThreatEvent` struct is a serialization-incompatible change. Persisted `threats.jsonl` files on existing users' disks would still deserialize with `serde(default)`, but any downstream consumer (dashboard JS, slack alerts) that expects the new field would break. Using `details` keeps the schema stable.

**Alternative considered:** Rename `source_ip` → `adversary_ip`. Rejected because it's a breaking change to the web dashboard API and threat log schema, with no offsetting benefit over the `details`-field approach.

### 1.2 On the safety pin: **static CIDR list, runtime ASN lookup, or both?**

**Decision:** **Both, but layered.** The static CIDR list ships in the embedded default config (Bucket A) and handles ~95% of real-world cases with zero runtime cost. Bucket C's ASN lookup layer handles the tail — IPs in ranges Aegis hasn't seen before, or ranges that change frequently. The ASN layer caches results in `data_dir/asn_cache.json` so that subsequent checks on the same IP are O(1).

**Order of checks in `block_ip()`:**
1. Is the IP in `response.whitelist` (existing CIDR allow-list)? → skip (existing behavior, unchanged)
2. Is the IP in `response.well_known_destinations` (new static CIDR infra list)? → skip, log at Low severity
3. Does ASN lookup classify the IP as `is_known_infra == true` (new dynamic lookup)? → skip, log at Low severity
4. Rate-limited? → skip with rate-limit warning (existing behavior)
5. Otherwise: call firewall backend + persist

**Why not merge `well_known_destinations` into the existing `whitelist`?** Because they're semantically different:
- `whitelist` = "never block this, period" (user-curated, can include private ranges)
- `well_known_destinations` = "don't auto-block this, but do still log the detection" (infra-provided, shipped with Aegis, updated by the project)

Keeping them separate means a user who wants to force-block a specific Cloudflare IP (maybe they're getting scanner probes from it) can still do so manually without fighting the safety pin. The safety pin only blocks *automatic* response actions.

### 1.3 On the zero-tolerance policy: **list by threat type string or by severity?**

**Decision:** **List by threat type string.** Config:
```toml
[response]
zero_tolerance_threats = ["path_traversal", "sql_injection", "reverse_shell"]
```

Not by severity (e.g., "all Critical → permaban") because:
- `C2Beacon` is Critical by default but, given bug #1 and bug #2 history, we'd be mass-permabanning infrastructure
- `RootkitDetected` is Critical but represents a local threat (rootkit on *our* box), not an IP to ban — banning an IP for it makes no sense
- Users should get to pick exactly which types get zero-tolerance based on their threat model

The `web_ddos` type is deliberately **not** in the default list. If a user has aggressive `ddos_threshold` tuning, a single traffic spike could trigger a perma-ban on someone's legitimate IP (e.g., a proxied VPN exit). Users who want it can add it manually.

### 1.4 On the time-series beacon detector: **how big a rewrite?**

**Decision:** **Full rewrite of `detect_c2_beacon`, minimal touches elsewhere.** Keep the existing module structure (`NetworkModule`), keep the `scan()` entry point, replace only the beacon function. Add one new in-memory state struct (`BeaconHistory`) held by `NetworkModule` that persists across scans. Serialized to `data_dir/beacon_history.json` on daemon shutdown and every housekeeping tick (5 min). Loaded on startup.

**Why not also restructure `NetworkModule` for better testability?** Scope. That's a separate refactor that can happen later.

**Why coefficient of variation (σ/μ) and not FFT / Fourier analysis?** Because:
- CoV works with as few as 4 samples (a proper FFT needs many more)
- CoV handles jitter gracefully (jittered beacons have CoV ≈ 0.2-0.4, pure-random traffic has CoV > 1.0, strict beacons have CoV < 0.1)
- CoV is O(n) in sample count, not O(n log n)
- It's a standard blue-team technique documented in the Mandiant "How to detect beaconing" whitepaper

### 1.5 On drift detection: **warn-only or auto-repair?**

**Decision:** **Warn-only by default, auto-repair behind a config flag `response.auto_reconcile_firewall = false`.** Chris can flip it to `true` once he's comfortable the logic is correct. Auto-repair is a high-blast-radius operation (it modifies kernel firewall state based on on-disk state), so it should not be default-on.

### 1.6 On commits: **don't.**

Per Chris's explicit instruction: do not `git commit` anywhere in this worktree. All changes stay as uncommitted working-tree edits. Chris reviews via `git diff` / `git status` and commits in whatever granularity he chooses. See `WAKEUP.md` for a suggested commit plan.

---

## 2. Bucket A — Bugs #1, #3, the safety pin, the beacon downgrade

### 2.1 Architecture

- `src/core/threat.rs` — no struct changes. Documentation comment added to `ThreatEvent.source_ip` clarifying its semantic.
- `src/modules/network/mod.rs` — `detect_c2_beacon` now records `local_ip` and `local_port` in the threat event's `details` map for forensic visibility. (This is the Bug #1 fix. Bucket E will replace the algorithm entirely, but Bug #1 is orthogonal to the algorithm and is worth fixing independently for the partial transition period.)
- `src/config/schema.rs` — `ResponseConfig` gains `well_known_destinations: Vec<String>` with a sensible default list.
- `src/response/mod.rs` — `ResponseEngine::new()` parses `well_known_destinations` into `Vec<IpNet>` at construction. `block_ip()` checks this list *after* whitelist and *before* rate limit, and skips with a Low-severity log on match.
- `src/modules/network/mod.rs` — no change to the severity of the C2Beacon threat type itself (it stays `Critical` in `threat.rs` — it's a real serious threat if the detector is actually right). But see 2.5.
- `aegis.toml` (embedded default) — `[response.overrides] c2_beacon = "alert"` changed from `"block"`, with a comment: `# TEMPORARY until v2.6.0's time-series detector (Bucket E) graduates — downgraded from "block" because the count-based detector has too many false positives.`

### 2.2 Components

Files touched:
- `src/modules/network/mod.rs` — `detect_c2_beacon` function body + new test cases
- `src/config/schema.rs` — `ResponseConfig` struct + `Default` impl
- `src/response/mod.rs` — `ResponseEngine` struct fields + `new()` + `block_ip()` + new helper `is_well_known_destination()`
- `src/core/threat.rs` — doc comment on `source_ip`
- `aegis.toml` — embedded default config
- `CHANGELOG.md` — new entry (if one exists — I haven't checked; will create if missing)

### 2.3 Data flow (post-change)

```
ThreatEvent { threat_type: C2Beacon, source_ip: Some(remote), details: {local_ip, local_port, ...} }
       │
       ▼
ResponseEngine.determine_action()
       │  (lookup override map: c2_beacon → "alert")
       ▼
ResponseAction::Alert   ← not Block!
       │
       ▼
Log + alerting subsystem only — no firewall call
```

And for threat types that *do* result in a block:
```
ResponseAction::Block (e.g. from brute_force or manual web-dashboard ban)
       │
       ▼
block_ip(ip, reason, state)
       │
       ├── is_ip_blocked(ip)? → skip
       ├── is_whitelisted(ip, whitelist)? → skip           [existing]
       ├── is_well_known_destination(ip, wkd_list)? → skip [NEW, logs Low-severity event]
       ├── rate limit check → skip if exceeded
       └── call firewall.block_ip() + record strike + persist
```

### 2.4 Error handling

- Parse errors in `well_known_destinations` CIDR list on startup: log a warning per invalid entry, continue with the valid ones. Never fail to start the daemon because of a malformed config list.
- Safety pin hit: still produce a `ThreatEvent` (so the admin sees it in the dashboard and alerting channels), but with `severity = Low` and a `safety_pin_reason` detail explaining why the block was suppressed.

### 2.5 Test plan

Unit tests added to `src/response/mod.rs::tests`:
- `test_well_known_destination_blocks_firewall_action` — given an IP in the WKD list, `block_ip()` returns Ok without calling the backend, and the reason is recorded in state
- `test_well_known_destination_does_not_suppress_whitelist` — whitelist still wins (no behavior change for pre-existing whitelisted IPs)
- `test_empty_wkd_list_behaves_like_before` — migration safety: users with no `well_known_destinations` set get the old behavior

Unit tests added to `src/modules/network/mod.rs::tests`:
- `test_c2_beacon_event_records_local_endpoint` — constructs fake /proc/net/tcp data, asserts resulting event has `local_ip` and `local_port` in `details`

### 2.6 Migration

- New config field `well_known_destinations` has a hardcoded default via `#[serde(default = "default_well_known_destinations")]`, so existing `aegis.toml` files without the field continue to load fine and get the new default automatically.
- Users running `apt upgrade aegis` will get their `aegis.toml` merged via `config-upgrade` (existing postinst logic) — the merge preserves their existing values but adds the new key.
- Users who have explicitly set `[response.overrides] c2_beacon = "block"` in their own config will **keep** that override (the downgrade only changes the embedded default, not the merge behavior). That's the correct behavior: respect user overrides.

### 2.7 Rollback

Each file change is independent and can be reverted in isolation:
- Revert `src/response/mod.rs` + `src/config/schema.rs` changes → safety pin is gone, fall back to original behavior
- Revert `src/modules/network/mod.rs` → local-endpoint recording is gone
- Revert `aegis.toml` → c2_beacon goes back to "block"

No database migrations, no persistent state changes, no restart required beyond the normal daemon restart.

---

## 3. Bucket B — Zero-tolerance first-offense permaban

### 3.1 Architecture

- `src/config/schema.rs` — `ResponseConfig` gains `zero_tolerance_threats: Vec<String>` (list of threat-type config keys, e.g. `"path_traversal"`).
- `src/response/mod.rs::block_ip()` — before the strike-count branch, check if the current threat's type config key is in `zero_tolerance_threats`. If so, immediately: record a strike, call `state.mark_escalated(ip)`, set `expires_at = None`, skip the normal duration math.

**Interaction with repeat-offender escalation:** zero-tolerance short-circuits the strike counter. A single zero-tolerance hit produces a permanent ban regardless of history. This is independent of `repeat_offender_threshold` (which handles the "N strikes across time" case for non-zero-tolerance types).

### 3.2 Threading the threat type through to `block_ip()`

Currently `block_ip()` only takes the IP and a reason string. It doesn't know the threat type. We need to pass the threat type in so the check can work. Minimal change: add an optional `threat_type_key: Option<&str>` parameter, passed from `respond()` which has full access to the event.

Alternative: store the `last_threat_type` on the `ResponseEngine` state. Rejected — this is stateful and error-prone in concurrent scenarios.

### 3.3 Test plan

- `test_zero_tolerance_single_hit_produces_permaban` — mock an event with type in the list, assert `blocked_ips[ip].expires_at == None` and `strike_history[ip].escalated == true`
- `test_zero_tolerance_does_not_affect_other_types` — mock a non-listed type, assert normal duration is applied
- `test_zero_tolerance_with_whitelist_wins` — whitelist still wins (zero-tolerance doesn't override whitelist)
- `test_zero_tolerance_with_safety_pin_wins` — Bucket A's safety pin still wins (zero-tolerance doesn't override well_known_destinations)

### 3.4 Default configuration

```toml
[response]
zero_tolerance_threats = ["path_traversal", "sql_injection", "reverse_shell"]
```

Deliberately conservative. `web_ddos`, `scanner_probe`, `brute_force` are NOT in the default list — they're too noisy for permaban on first offense. Users who want more aggressive policy can add them.

---

## 4. Bucket C — ASN/destination reputation enrichment

### 4.1 Scope clarification

Bucket C originally covered three sub-features:
1. ✅ **ASN/whois destination reputation** — implemented in v2.6.0
2. ❌ **Process-exe signature verification** — DEFERRED. Requires per-distro dpkg/rpm integration, file hash database of trusted binaries, and careful handling of edge cases (setuid binaries, symlinks, LD_LIBRARY_PATH hijacks). Out of scope for one overnight session. Will be a separate bucket in v2.7.0.
3. ✅ **First-pass ISP/ASN lookup cache** — implemented, shares the same cache as (1)

### 4.2 Architecture

New file: `src/util/asn_lookup.rs`. Exposes:

```rust
pub struct AsnInfo {
    pub asn: Option<u32>,
    pub org: String,
    pub country: String,
    pub classification: AsnClassification,
    pub last_updated: DateTime<Utc>,
}

pub enum AsnClassification {
    KnownInfrastructure,      // Cloudflare, CloudFront, GitHub, Google, Anthropic, Fastly
    MajorCloudCustomer,       // Azure VMs (20.x, 4.x), GCP, EC2 customer ranges
    HostingProvider,          // OVH, Hetzner, Linode, DigitalOcean — dual-use
    ResidentialIsp,           // Cox, Comcast, Deutsche Telekom, etc.
    Unknown,
}

pub struct AsnLookup {
    cache_path: PathBuf,
    cache: RwLock<HashMap<IpAddr, AsnInfo>>,
    ttl: Duration,
}

impl AsnLookup {
    pub fn new(data_dir: &Path) -> Self { ... }
    pub async fn lookup(&self, ip: IpAddr) -> AsnInfo { ... }
    pub fn is_known_infrastructure(&self, ip: IpAddr) -> bool { ... }  // sync, cache-only
    pub async fn refresh_cache(&self) -> Result<()> { ... }
}
```

**How the lookup works:**
1. Check in-memory cache → return if present and not expired
2. Check disk cache at `data_dir/asn_cache.json` → return if present and not expired
3. Fire a `whois` subprocess call with a timeout (5s)
4. Parse the output for `OrgName`, `NetName`, `Country`, `origin` (ASN number)
5. Classify into the 5 buckets above via pattern matching on `OrgName`
6. Cache with a 30-day TTL
7. Return

**Why whois and not a BGP-table lookup?** Because:
- Aegis already depends on `whois` being available (we just used it in the triage)
- BGP tables change dynamically; whois-reported ownership is stable enough for this purpose
- A BGP lookup would require either an external API call (adding a third-party dependency) or shipping a multi-megabyte BGP snapshot (bad)

**Whois is slow — how do we avoid blocking the scan?** The `is_known_infrastructure()` method is cache-only and synchronous (O(1)). Uncached IPs are logged for background lookup, not blocked on. The `refresh_cache()` method runs on a background task triggered by the housekeeping interval.

### 4.3 Integration with Bucket A's safety pin

`ResponseEngine::is_well_known_destination()` now checks:
1. Static `well_known_destinations` CIDR list (fast, in-memory)
2. ASN cache for `KnownInfrastructure` classification (fast, in-memory)
3. Fallback: return false, queue IP for async lookup so future checks can match

### 4.4 Default ASN classification patterns

```rust
fn classify_org(org: &str) -> AsnClassification {
    let org_lower = org.to_lowercase();
    // KnownInfrastructure
    if org_lower.contains("cloudflare") || org_lower.contains("amazon technologies")
        || org_lower.contains("github") || org_lower.contains("google llc")
        || org_lower.contains("anthropic") || org_lower.contains("fastly")
        || org_lower.contains("akamai") || org_lower.contains("microsoft")  // nuance: 13.x.x.x
    {
        return AsnClassification::KnownInfrastructure;
    }
    // ... etc
}
```

**The Microsoft nuance:** `OrgName: Microsoft Corporation` covers both MS's own infrastructure (O365, Bing) AND customer Azure VMs. A coarse string match would incorrectly mark 20.x.x.x Azure VMs as infrastructure. Mitigation: combine org match with CIDR check — if org is Microsoft AND the IP falls within a known "MS-owned, not customer" range (hardcoded from MS's public documentation), classify as infra. Otherwise, classify as `MajorCloudCustomer`. For v2.6.0, we ship a conservative hardcoded list; users can extend it.

### 4.5 Test plan

- `test_asn_classify_cloudflare` — parse a canned whois response, assert `KnownInfrastructure`
- `test_asn_classify_azure_customer` — parse 20.x.x.x whois, assert `MajorCloudCustomer`
- `test_asn_cache_hit_is_sync` — load cache, call `is_known_infrastructure()`, assert no subprocess call happened
- `test_asn_cache_miss_triggers_async_lookup` — mock whois subprocess, assert cache is populated after lookup completes
- `test_asn_cache_respects_ttl` — load an entry with `last_updated` > 30 days ago, assert it's refreshed

---

## 5. Bucket D — Drift detection & reinstall hardening

### 5.1 Architecture

New function in `ResponseEngine`: `reconcile_firewall_state(&self, state: &AppState) -> ReconcileReport`.

```rust
pub struct ReconcileReport {
    pub persisted_count: usize,         // entries in block_list.json
    pub firewall_count: usize,          // rules in AEGIS_BLOCK chain
    pub missing_from_firewall: Vec<IpAddr>,  // persisted but not in chain
    pub orphaned_in_firewall: Vec<IpAddr>,   // in chain but not persisted
    pub auto_reconciled: bool,
}
```

Called from the daemon housekeeping tick (every 5 min, existing loop at `engine.rs:525`). Logs the report at `info` level always; if `response.auto_reconcile_firewall = true`, also issues `firewall.block_ip()` for missing entries and `firewall.unblock_ip()` for orphans.

### 5.2 How to enumerate the AEGIS_BLOCK chain

Current response backends (`IptablesBackend`, `NftablesBackend`, `UfwBackend`) don't expose a "list all blocked IPs" method. We add one:

```rust
trait FirewallBackend: Send + Sync {
    fn init(&self) -> Result<()>;
    fn block_ip(&self, ip: &IpAddr) -> Result<()>;
    fn unblock_ip(&self, ip: &IpAddr) -> Result<()>;
    fn list_blocked_ips(&self) -> Result<Vec<IpAddr>>;  // NEW
}
```

- `IptablesBackend::list_blocked_ips`: `iptables -S AEGIS_BLOCK -n`, parse `-A AEGIS_BLOCK -s <ip>/<mask> -j DROP` lines
- `NftablesBackend::list_blocked_ips`: `nft --json list chain inet aegis input`, parse JSON
- `UfwBackend::list_blocked_ips`: `ufw status numbered`, parse `DENY IN from <ip>` lines

### 5.3 Handling of the existing drift

The current ~700 iptables rules vs ~143 persisted entries includes many legitimate historical blocks that were never cleaned up. Drift detection on first run will report a MASSIVE number of orphaned rules. That's real and expected.

**First-run UX:** the report warns but does NOT auto-reconcile even if `auto_reconcile_firewall = true`, because the initial drift is so large it probably needs human review. A one-time `aegis reconcile --first-run` CLI command lets the user explicitly acknowledge and act on the initial drift.

### 5.4 Test plan

- `test_reconcile_report_with_no_drift` — persistent == firewall, empty missing/orphaned
- `test_reconcile_report_with_missing_rules` — 5 persisted, 3 in firewall, assert 2 in `missing_from_firewall`
- `test_reconcile_report_with_orphans` — 3 persisted, 5 in firewall, assert 2 in `orphaned_in_firewall`
- `test_reconcile_auto_repair_disabled` — `auto_reconcile_firewall = false`, backend methods never called
- `test_reconcile_auto_repair_enabled` — `auto_reconcile_firewall = true`, backend methods called with exactly the right IPs
- Integration with a mock `FirewallBackend` (not a real iptables one) — unit test only, no live iptables testing

---

## 6. Bucket E — Time-series C2 beacon detection

### 6.1 Problem statement

The current `detect_c2_beacon` counts **currently-established parallel sockets** in a single `/proc/net/tcp` snapshot. A threshold of 10 parallel sockets is trivially exceeded by any HTTP/2 client (browsers, API clients, streaming apps). The `c2_beacon_window` config field (default 300s) is read but never used.

### 6.2 What real beacon detection looks like

C2 beacons exhibit **periodic, low-jitter connection attempts** to the same remote endpoint, typically every 30s–15min. Parallel sockets are irrelevant — what matters is the *timing* of new outbound *initiations*.

Mathematical signal: **coefficient of variation (CoV)** of inter-arrival times. Define:
- Mean inter-arrival time μ = `sum(Δt) / n`
- Std deviation σ = `sqrt(sum((Δt_i - μ)^2) / n)`
- CoV = `σ / μ`

Low CoV (< 0.3) = periodic. High CoV (> 1.0) = random/bursty. Jittered beacons (common in modern C2) sit around 0.2–0.4.

### 6.3 Architecture

New state struct inside `NetworkModule`:

```rust
pub struct BeaconHistory {
    // Per-(local_process_path_or_pid, remote_ip, remote_port) history of
    // first-seen timestamps for newly-observed TCP connections.
    entries: HashMap<BeaconKey, VecDeque<DateTime<Utc>>>,
    max_samples: usize,      // cap at 20 samples to bound memory
    max_keys: usize,          // cap at 10k keys
    window: Duration,         // from c2_beacon_window config (now used!)
}

pub struct BeaconKey {
    pub local_exe: String,      // or "unknown" if we couldn't read /proc/<pid>/exe
    pub remote_ip: IpAddr,
    pub remote_port: u16,
}
```

### 6.4 Algorithm

On each scan tick (every 60s in daemon mode):

1. Snapshot `/proc/net/tcp` for ESTABLISHED connections to non-private remote IPs.
2. For each connection, build the `BeaconKey { local_exe, remote_ip, remote_port }` (use exe path via `/proc/<pid>/exe` → fallback to pid string).
3. If this `BeaconKey` was not present in the *previous* snapshot, record this scan's timestamp as a "new connection seen" event in `BeaconHistory.entries[key]`.
4. Trim entries older than `window` from each key's deque.
5. For keys with `>= min_samples` (4) entries in window:
   - Compute μ, σ, CoV of inter-arrival times
   - If `CoV < cov_threshold` (0.3 by default) AND `mean_interval_secs` is in the beacon range (30s–15min): emit `C2Beacon` threat event with:
     - `source_ip` = remote IP
     - `target` = `"{remote_ip}:{remote_port}"`
     - Details: `local_exe`, `local_ip`, `local_port`, `sample_count`, `mean_interval_secs`, `stddev_interval_secs`, `coefficient_of_variation`, `window_secs`
6. Persist `BeaconHistory` to disk at end of scan (atomic write to `data_dir/beacon_history.json`).

### 6.5 Data persistence

`BeaconHistory` serializes to JSON via serde. On `NetworkModule::new()`, the module attempts to load from disk; on scan completion, it writes back. Size bound: 10k keys × 20 samples × ~40 bytes/sample = ~8 MB worst case. Reasonable.

### 6.6 Interaction with Bucket A

Because of Bucket A's safety pin, even if the new detector fires on a Cloudflare IP (e.g., a legitimate periodic health-check hitting a CF-hosted API every 60s — which *will* produce a low CoV), the response engine will refuse to block it. The detection still gets logged as an alert for admin visibility.

The c2_beacon override in `aegis.toml` can be flipped back from `"alert"` to `"block"` once the time-series detector has soaked for a while and precision is validated.

### 6.7 Test plan

- `test_beacon_history_cov_computation` — hand-construct a series with known μ and σ, assert computed CoV matches
- `test_beacon_detects_strict_periodic` — 10 samples at exactly 60s intervals, assert CoV < 0.01 and beacon detected
- `test_beacon_detects_jittered` — 10 samples with +/- 5% jitter around 120s mean, assert CoV < 0.1 and beacon detected
- `test_beacon_ignores_random_traffic` — 10 samples at 5s, 30s, 200s, 10s, 1s, ..., assert CoV > 1.0 and no beacon
- `test_beacon_requires_minimum_samples` — 3 samples (below min), assert no beacon emitted even with perfect periodicity
- `test_beacon_window_filters_old_samples` — 5 samples at T-1000s, 2 at T-100s, assert only last 2 counted (below min_samples)
- `test_beacon_history_persists_across_module_restarts` — serialize to tempdir, reload, assert entries preserved
- `test_beacon_history_caps_memory` — insert 15k keys, assert len <= max_keys (10k), oldest evicted first

### 6.8 Default config additions

```toml
[network]
# Minimum samples in window before beacon detection fires (4 = lowest statistically meaningful)
c2_beacon_min_samples = 4
# Coefficient of variation threshold below which inter-arrival timing is considered "periodic enough"
c2_beacon_cov_threshold = 0.3
# Mean inter-arrival range (seconds) for beacon classification. Outside this → ignore.
c2_beacon_min_interval_secs = 20
c2_beacon_max_interval_secs = 900
```

The old `c2_beacon_threshold` config field is repurposed: it now controls how many beacon events can fire per key per scan (protection against flapping). Default = 1.

---

## 7. Cross-cutting concerns

### 7.1 Backwards compatibility

All changes are **strictly additive** on the config schema side. Every new field uses `#[serde(default = "...")]` so existing `aegis.toml` files deserialize successfully and get sensible defaults. The only behavioral change that could surprise users is the `c2_beacon = "alert"` override downgrade, which is loudly documented in `CHANGELOG.md` and explained in the `WAKEUP.md`.

### 7.2 Test isolation

All new tests use `tempfile::tempdir()` for any data_dir they need. No test touches `~/.aegis`, `/root/.aegis`, or any path outside its own tempdir. The existing test suite already follows this pattern (see `engine.rs::tests::test_config` and the `store_*` tests).

### 7.3 Semgrep / clippy / fmt

The existing codebase has semgrep rules (I noticed `nosemgrep:` comments in `main.rs:444` and `main.rs:731`). All new code should pass semgrep without suppressions except where unavoidable. I'll run `semgrep scan` before declaring the work complete. Similarly `cargo clippy` and `cargo fmt` should be clean.

### 7.4 Observability

Every new code path emits tracing events at appropriate levels:
- `info!` for routine operations (cache hit, scan complete)
- `warn!` for unexpected but recoverable situations (whois timeout, cache parse error)
- `error!` for actual failures
- `debug!` for high-volume events (per-IP check results)

### 7.5 Deployment checklist (for Chris post-review)

Even after Chris approves and commits this work:
1. `cargo build --release` in the worktree → `/home/chris/aegis-v2-worktree/target/release/aegis`
2. Verify binary runs: `./target/release/aegis --version` should print `2.6.0`
3. Back up current daemon data: `sudo cp -a /root/.aegis /root/.aegis.v2.5-backup`
4. Stop current daemon: `sudo systemctl stop aegis`
5. Replace binary: `sudo install -m 755 ./target/release/aegis /usr/local/bin/aegis`
6. Run config upgrade: `sudo aegis config-upgrade` (this adds the new `well_known_destinations`, `zero_tolerance_threats`, beacon fields to `/etc/aegis/aegis.toml` without clobbering existing values)
7. Review the merged config: `diff /etc/aegis/aegis.toml /etc/aegis/aegis.toml.old` (if the upgrade leaves a `.old` file)
8. Restart daemon: `sudo systemctl start aegis`
9. Watch logs for 5 minutes: `sudo journalctl -u aegis -f`
10. Verify safety pin is working: connections to 13.224.185.x should now **not** generate new DROP rules
11. After 24h of clean operation, run `scripts/unblock_infrastructure_fps.sh` to clean the historical drift
12. Optional: flip `response.auto_reconcile_firewall = true` in `/etc/aegis/aegis.toml` to enable bucket D's auto-repair

**Rollback plan:** if anything goes wrong, `sudo cp /usr/local/bin/aegis.old /usr/local/bin/aegis && sudo systemctl restart aegis`. The `cargo install`-style replacement keeps the old binary available for rollback (actually the self-update mechanism in `src/update.rs:227` does this already with `.with_extension("old")`).

---

## 8. What's deferred to future releases

These were originally in scope but deferred due to time/complexity:

- **Process-exe signature verification against dpkg/rpm** (part of original Bucket C) — separate project, v2.7.0
- **Alerting integration for safety pin hits** — the new Low-severity events will flow through the existing alerting pipeline, but the `min_severity = "high"` filter in most alerting configs means Chris won't see them. A dedicated "safety_pin_events" notification channel would be nice. v2.7.0.
- **Web dashboard UI for the new fields** (`local_ip`, `local_port`, ASN info, beacon statistics) — the dashboard currently doesn't render detail maps richly. Partial implementation via the existing "details" expander will work, but a polished UI is a follow-up. v2.7.0.
- **`aegis triage-chain` CLI subcommand** that auto-classifies current iptables drift using the Bucket C ASN lookup — would make the triage workflow reproducible for future drift incidents. Small, could be done in v2.6.1.
- **Integration tests against a real daemon** — the existing test suite is all unit-level. A qemu-based integration test harness would catch issues like the silently-failing iptables calls. Separate project.
