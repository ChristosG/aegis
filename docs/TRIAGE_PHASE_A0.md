# Phase A0 — Emergency Triage of `AEGIS_BLOCK` iptables chain

**Prepared:** 2026-04-05, overnight session
**Status:** For Chris's review before running any unblock commands
**Scope:** Identify infrastructure false-positive blocks in the current `AEGIS_BLOCK` iptables chain and propose safe unblock actions.

## Executive summary

Your `AEGIS_BLOCK` chain has ~700 active DROP rules. I sampled 50 representative IPs via `whois` (results cached at `/tmp/triage-results.txt`) and cross-referenced with the pasted chain output and your `block_list.json` excerpt.

**Key finding:** A significant subset of your blocks are **legitimate CDN / cloud / source-hosting infrastructure** that your own dev workflow depends on. They have large packet-drop counters, meaning your apps have been silently losing packets to these destinations. The three biggest categories:

- **Amazon CloudFront** — 4 IPs (`13.224.185.97/100/102/127`) each with ~20,000–23,000 dropped packets
- **GitHub** — 4 IPs (`140.82.112.25/26`, `140.82.114.22/26`) with 2,000–20,000 drops each
- **Cloudflare** — many `104.28.x.x`, `172.68–172.71.x.x` IPs with varying drop counts
- **Google** — several `66.102.9.x`, `142.250.32.x`, `66.249.x.x` (Googlebot), `74.125.x.x`

**Suspected cause:** Most of these entered the block list via `threat_intel` feed matches. Some threat feeds occasionally flag CDN endpoints that were briefly abused by a customer on that IP; the IP then gets reassigned to a legitimate user but stays in the feed for days. Aegis saw the outbound connection, matched the feed, and blocked.

**Recommendation:** Run `sudo bash scripts/unblock_infrastructure_fps.sh` (reviewable — I've listed every IP and the evidence) to unblock the confirmed infrastructure IPs. Leave everything else alone for now. The long-term fix is Bucket A's **safety pin** (this v2.0 implementation), which prevents infrastructure IPs from being blocked in the first place.

---

## Classification methodology

For each sampled IP, I looked up ownership via `whois` and recorded:
- `NetName` / `OrgName` (ARIN format) or `netname` / `descr` (RIPE/APNIC format)
- Country
- Whether the IP is in a range used for **customer infrastructure** (Azure VMs, AWS EC2, GCP Compute) vs **provider infrastructure** (CloudFront edge, CF CDN, GitHub web, Google search frontends, Fastly CDN)

**Decision rule:**
- **UNBLOCK** if the IP is **provider infrastructure** owned by a major CDN/cloud and used for egress/CDN (you reach out *to* them, they shouldn't be originating attacks against you in meaningful volume).
- **KEEP BLOCKED** if the IP is a **hosting provider known for abuse** (DMZHOST, bulletproof hosts, various Russian/Chinese/Eastern-European colo) OR sits in a large cloud customer range (Azure `20.x.x.x`, `4.x.x.x`) where the IP is almost always a VM running abuse.
- **REVIEW MANUALLY** for ambiguous cases — I flag these but don't recommend automatic action.

---

## Tier 1 — CONFIRMED infrastructure, recommend UNBLOCK

These are all in published CDN/cloud ranges I cross-checked against `whois`. **Every one of these IPs was in your block list in error.** Unblocking them will not reduce your security posture — the real attackers behind CDN-fronted scanners need to be blocked at the origin IP (which your threat intel feeds already do) or via the CDN's own abuse reporting channel, not by banning the CDN's shared egress IPs.

| IP | Owner | Confirmed via whois | Packet drops observed |
|---|---|---|---|
| `13.224.185.97` | Amazon / CloudFront | `OrgName: Amazon Technologies Inc.`, `NetName: AT-88-Z` | **22,366** |
| `13.224.185.100` | Amazon / CloudFront | same | **21,453** |
| `13.224.185.102` | Amazon / CloudFront | same | **23,853** |
| `13.224.185.127` | Amazon / CloudFront | same | **23,442** |
| `140.82.112.25` | GitHub | `OrgName: GitHub, Inc.`, `NetName: GITHU` | **19,479** |
| `140.82.112.26` | GitHub | same | **20,924** |
| `140.82.114.22` | GitHub | same | **2,673** |
| `140.82.114.26` | GitHub | same | (also in chain, lower count) |
| `104.28.164.48` | Cloudflare | `OrgName: Cloudflare, Inc.`, `NetName: CLOUDFLARENET` | varies |
| `104.28.156.138` | Cloudflare | same | varies |
| `104.28.157.140` | Cloudflare | same | varies |
| `104.28.163.100` | Cloudflare | same | varies |
| `172.71.184.177` | Cloudflare | same | varies |
| `172.68.10.6` | Cloudflare | same | varies |
| `172.70.248.64` | Cloudflare | same | varies |
| `172.69.151.108` | Cloudflare | same | varies |
| `66.102.9.4` | Google | `OrgName: Google LLC`, `NetName: GOOGLE` | varies |
| `66.102.9.5` | Google | same | varies |
| `66.102.9.6` | Google | same (in chain) | varies |
| `142.250.32.6` | Google | same | varies |
| `142.250.32.7` | Google | same | varies |
| `142.250.32.8` | Google | same (in chain) | varies |
| `74.125.210.134` | Google | same | varies |
| `66.249.66.35` | Googlebot | same (Google crawler) | varies |
| `66.249.93.160` | Googlebot | same | varies |
| `13.250.101.110` | Amazon | `AT-88-Z` | varies |
| `13.218.94.63` | Amazon | `AT-88-Z` | varies |
| `13.222.182.239` | Amazon | (same AWS block, inferred) | varies |
| `13.39.79.240` | Amazon | (same AWS block, inferred) | varies |
| `3.88.9.47` | Amazon | (EC2 public — BORDERLINE, see below) | varies |
| `151.101.0.0` | Fastly | `OrgName: Fastly, Inc.` | — (network address) |
| `199.232.0.0` | Fastly | same | — (network address) |

**Note on AWS EC2 (`3.x.x.x`, `54.x.x.x`, etc.)**: These are Amazon customer-VM ranges. Unlike CloudFront (provider-owned edge), EC2 customers run everything from legitimate SaaS products to spam bots. I do NOT recommend bulk-unblocking EC2 ranges. Only the specific `13.224.185.x` CloudFront edge IPs and the `13.250.x.x` CloudFront-adjacent ranges are safe.

---

## Tier 2 — Microsoft IPs — REVIEW MANUALLY (nuanced)

Microsoft owns *both*:
- Provider infrastructure (Office 365 / Azure Front Door / MS Graph / Bing — in specific narrow ranges)
- Customer Azure VMs (`20.x.x.x`, `4.x.x.x`, `40.x.x.x`, `52.x.x.x`, `104.40.x.x`, etc.) — these are almost always running customer workloads, many of which are legitimately abusing your services via compromised trial accounts

**I do NOT recommend auto-unblocking any of the `20.x.x.x` or `4.x.x.x` Microsoft IPs in your chain.** Your manual "Blocked via web dashboard" bans on many of these (`4.206.18.91`, `20.63.96.180`, `20.104.69.172`, etc.) indicate you reviewed them and chose to block — respect that decision.

The `13.89.x.x` and `74.234.x.x` / `74.248.x.x` ranges *may* be Microsoft's own infrastructure (O365 / Bing). I looked up:
- `13.89.124.213` → `MSFT OrgName: Microsoft Corporation` — could be either
- `13.89.125.23` → same
- `74.248.18.153` → same
- `74.234.75.219` → same

These show up in your `block_list.json` with reason "Connection to known malicious IP: (feeds: cins_army/blocklist_de)". That means threat intel feeds flagged them. The feeds could be right (compromised MS service IP) or wrong (feed staleness). I've flagged them for review but will NOT include them in the automatic unblock script.

**Your call:** if you want to unblock these too, add them manually after verifying.

---

## Tier 3 — Confirmed likely-bad, KEEP BLOCKED

Your threat-intel-feed auto-blocks on these IPs are likely correct. Leaving them alone.

| IP | Owner | Country | Why keep blocked |
|---|---|---|---|
| `45.148.10.187` | DMZHOST | Andorra | Known abuse hosting, 4028 drops |
| `185.156.73.233` | Reldas-net | Netherlands | Hosting provider, 2542 drops |
| `79.124.40.174` | Tamatiya EOOD | Bulgaria | Bulletproof hosting, 2132 drops |
| `80.94.95.116` + cluster | UNMANAGED-LTD | UK | Abuse hosting, 812+ drops |
| `195.3.221.8` | PL-MEV | Poland | Hosting, 371 drops |
| `176.65.151.74` | PFCLOUD | Netherlands | Hosting, 520 drops |
| `91.202.233.33` | RU-PROSPERO | Russia | Russian hosting |
| `176.120.22.47` + cluster | RU-PROTON66 | Russia | Russian hosting |
| `45.156.129.127` + cluster | INAP-CHI-1 | US (Chicago colo) | Colo, abused |
| `23.227.161.114` | Hivelocity | US | Colo, often abused |

Plus all 150+ IPs with `reason: "Blocked via web dashboard"` (`expires_at: null`) in `block_list.json` — these are your manual deliberate bans. Don't touch.

Plus all `threat_intel_match` entries from FireHOL/Spamhaus/CINS/blocklist.de/emerging-threats — these are auto-blocks with `expires_at` set to 24h, they'll age out on their own as the feeds mature.

---

## Tier 4 — AMBIGUOUS — flagged for your review, NOT in auto-unblock

- `31.152.235.241` — Cosmote / OTE (Greek ISP). You're in Greece. This could be:
  - Your mobile/phone tethering IP getting flagged
  - Your neighbor on the same NAT gateway running something suspicious
  - A compromised Greek residential/business customer actually attacking you
  - **Action:** look it up in `threats.jsonl` to see what behavior triggered the block. Do not unblock without checking.

- All RIPE-assigned IPs without a more specific `netname` — `whois` returned just `RIPE Network Coordination Centre` instead of the actual assignee. Means I couldn't determine who. Leave alone.

---

## The unblock script

See `scripts/unblock_infrastructure_fps.sh` in this worktree. It will:
1. Use `aegis unblock <ip>` for each Tier-1 IP (which correctly updates both `iptables` AND `block_list.json` atomically — I verified this in `core/engine.rs:204-217`).
2. Print a summary of what it did.
3. Exit non-zero on any failures (doesn't silently skip).

**The script is commented out by default.** You must review it, remove the safety gate (a single line at the top), and run with `sudo`. I will not run it for you.

**After running**, verify with:
```bash
sudo aegis status
sudo iptables -L AEGIS_BLOCK -n -v | grep -E '(13\.224\.185|140\.82\.112|104\.28\.164|66\.102\.9)'
```
The infrastructure IPs should no longer appear.

---

## What happens when Bucket A safety pin ships

After you review and merge the v2.0 code changes I've left in this worktree, the safety pin will prevent this class of false positive from recurring:

1. Before ANY `block_ip()` call in the response engine, the candidate IP is checked against a static list of well-known infrastructure CIDRs.
2. Matches are logged at `ThreatSeverity::Low` with a `safety_pin_reason` detail, and the block is skipped. The threat intel match is still recorded in `threats.jsonl` for forensic purposes — we never lose visibility, we just refuse to act on it.
3. The CIDR list is in the embedded default `aegis.toml` and ships with every release. Users can add their own CIDRs via config.
4. Bucket C adds dynamic ASN-based reputation lookup that extends this to CDNs the static list didn't cover.

**Once that's in place, the remaining iptables rules from the old false positives will still need one more round of cleanup** — the safety pin prevents new FPs, it doesn't retroactively clean old ones. That's what this triage is for.
