# Airtel 5G Hotspot Bypass

> **"Unlimited" data but only on the device we choose? Nah.**

Scripts for **Windows (PowerShell)** and **Linux (Bash)** that make tethered laptop traffic appear as native mobile traffic to Airtel's hotspot detection system — so you can actually use the unlimited 5G data you're paying for.

**By [sayann70](https://github.com/sayann70) — MIT License**

---

## The Problem

Airtel officially confirmed that their "Unlimited 5G Data" benefit is **only for the registered smartphone**, and is intentionally throttled/blocked when shared via mobile hotspot. They detect tethering using multiple network-layer fingerprints and throttle or cut off hotspot traffic.

---

## How Airtel Detects Tethering

This is the core of why it works. Airtel (and most carriers) use a combination of these signals to know your traffic is coming from a laptop, not a phone:

```
Your Laptop
    │
    │  WiFi Hotspot
    ▼
Your Phone  ──────────────►  Airtel's Tower  ──►  Internet
    │                              │
    │                              │
    │                         Inspects packets:
    │                         - TTL value
    │                         - MTU size
    │                         - DNS queries (windows update?)
    │                         - TCP connection count
    │                         - User-Agent / app signatures
    │                         - Network discovery broadcasts
    │                         - OS telemetry endpoints
```

When a phone acts as a router (hotspot), it decrements the TTL of every packet passing through it by 1. So:

| Scenario | Original TTL | After phone | Carrier sees |
|---|---|---|---|
| Normal phone traffic | 64 | — | **64** ✅ Looks like phone |
| Windows laptop (default) | **128** | −1 | **127** ❌ BUSTED |
| This script applied | **65** | −1 | **64** ✅ Looks like phone |

---

## Detection Vectors & How We Beat Each One

### 1. TTL (Time-To-Live) — Most Critical

**How Airtel detects it:** Every IP packet has a TTL field. Mobile OSes (Android/iOS) default to TTL=64. Windows defaults to TTL=128. When your phone routes a packet through hotspot, it subtracts 1. So Airtel sees TTL=127 from a Windows laptop — an instant giveaway.

**Fix:** Set Windows TTL to **65**. Phone subtracts 1 → Airtel sees **64** → identical to native mobile traffic.

```
Registry: HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DefaultTTL = 65
Live:      netsh int ipv4 set global defaultcurhoplimit=65
IPv6:      netsh int ipv6 set global defaultcurhoplimit=65
```

---

### 2. MTU (Maximum Transmission Unit)

**How Airtel detects it:** Mobile devices use MTU of ~1400 bytes. Windows defaults to 1500 bytes. Different MTU sizes cause different IP fragmentation patterns. A carrier can detect 1500-byte MTU frames and know it's a desktop device.

**Fix:** Clamp MTU to **1400** on the Wi-Fi adapter.

```
netsh interface ipv4 set subinterface "Wi-Fi" mtu=1400 store=persistent
Set-NetIPInterface -InterfaceIndex X -NlMtuBytes 1400
```

---

### 3. Windows Update Traffic

**How Airtel detects it:** Windows Update constantly phones home to Microsoft servers (`windowsupdate.microsoft.com`, `update.microsoft.com`, etc.). No smartphone ever makes requests to these endpoints. Seeing these DNS queries or TCP connections immediately tells the carrier you're running a desktop OS.

**Fix:** Block **15 Windows Update domains** via Windows Firewall outbound rules + stop & disable the `wuauserv` service.

---

### 4. Windows Telemetry

**How Airtel detects it:** Windows Diagnostics Tracking (`DiagTrack`) and telemetry services constantly send data to Microsoft endpoints like `vortex.data.microsoft.com`, `settings-win.data.microsoft.com`, etc. Again — no phone does this.

**Fix:** Block **10 telemetry domains** via firewall rules + stop & disable the `DiagTrack` service.

---

### 5. DNS Override

**How Airtel detects it:** Airtel's APN (Access Point Name) configuration can split traffic based on DNS — sending hotspot DNS queries to a different resolver that flags them differently, or inspecting DNS queries to see desktop-specific lookups.

**Fix:** Override DNS to **Cloudflare (1.1.1.1 / 1.0.0.1)**, bypassing Airtel's APN-controlled resolver entirely. Also enables **DNS-over-HTTPS (DoH)** on Windows 11 for encrypted DNS.

---

### 6. Parallel TCP Connections

**How Airtel detects it:** A typical smartphone opens 10–20 parallel TCP connections when browsing. A Windows desktop with Chrome, background apps, and Windows services can open **100+ simultaneous connections**. This concurrency pattern is highly distinctive.

**Fix:**
- Limit max TCP connections to **24** via registry
- Reduce ephemeral port range to **49152–53247** (mobile-like)
- Disable **TCP Window Auto-Tuning** (mobile stacks don't use this)

---

### 7. Desktop App Signatures

**How Airtel detects it:** Apps like Steam, Xbox, Windows Store, OneDrive, and Microsoft Edge all make requests to distinctive endpoints that are 100% exclusive to desktop operating systems.

**Fix:** Block outbound connections from **6 desktop-specific executables**:
- `Steam.exe`
- `XboxApp.exe` / `GamingServices.exe`
- `WinStore.App.exe`
- `OneDrive.exe`
- `MicrosoftEdgeUpdate.exe`

---

### 8. Network Discovery Protocols

**How Airtel detects it:** Windows broadcasts several discovery protocols on the local network that leak out through the hotspot:
- **SSDP** (Simple Service Discovery Protocol) — port 1900
- **LLMNR** (Link-Local Multicast Name Resolution) — port 5355
- **NetBIOS** — ports 137/138
- **mDNS** (Multicast DNS) — port 5353

Phones don't broadcast any of these. Seeing them is a dead giveaway.

**Fix:** Block all 4 protocols via Windows Firewall inbound+outbound rules.

---

### 9. NCSI Active Probing (Additional Hardening)

**How Airtel detects it:** Windows Network Connectivity Status Indicator periodically pings `www.msftconnecttest.com` and `dns.msftncsi.com` to check internet connectivity. These are Windows-exclusive endpoints.

**Fix:** Disable NCSI active probing via registry and live service restart.

---

## Full Architecture Diagram

```
BEFORE (Airtel detects you):
─────────────────────────────────────────────────────────
 Laptop                Phone              Airtel
 ┌──────┐   WiFi    ┌────────┐   5G     ┌──────────┐
 │      │──hotspot─►│        │─────────►│          │
 │ TTL  │           │  −1    │          │ Sees 127 │ ← BUSTED
 │ =128 │           │  TTL   │          │ (desktop)│
 │ MTU  │           │        │          │          │
 │ =1500│           │        │          │ Sees 1500│ ← BUSTED
 │WinUpd│           │        │          │          │
 │ DNS  │           │        │          │ Sees MSFT│ ← BUSTED
 └──────┘           └────────┘          └──────────┘


AFTER (This script applied):
─────────────────────────────────────────────────────────
 Laptop                Phone              Airtel
 ┌──────┐   WiFi    ┌────────┐   5G     ┌──────────┐
 │      │──hotspot─►│        │─────────►│          │
 │ TTL  │           │  −1    │          │ Sees 64  │ ✅ Phone
 │ =65  │           │  TTL   │          │          │
 │ MTU  │           │        │          │          │
 │ =1400│           │        │          │ Sees 1400│ ✅ Phone
 │ FW   │           │        │          │          │
 │Block │           │        │          │ No MSFT  │ ✅ Clean
 │ DNS  │           │        │          │          │
 │ 1.1  │           │        │          │ CF DNS   │ ✅ Neutral
 └──────┘           └────────┘          └──────────┘
```

---

## Usage

### 🪟 Windows

**Requirements:**
- Windows 10/11
- Administrator privileges
- Connected to your Airtel hotspot

| Action | How |
|---|---|
| Apply bypass | Double-click `RUN_AS_ADMIN.bat` |
| Verify it's working | Double-click `scripts\VERIFY.bat` |
| Undo everything | Double-click `UNDO_BYPASS.bat` |

All changes are applied live. **No reboot needed.**

---

### 🐧 Linux

**Requirements:**
- Any modern Linux distro (Ubuntu, Debian, Fedora, Arch, etc.)
- `sudo` / root access
- `iptables` + `ip6tables` installed (standard on almost all distros)
- Connected to your Airtel hotspot via Wi-Fi

```bash
# 1. Make scripts executable (first time only)
chmod +x run_bypass.sh undo_bypass.sh scripts/bypass.sh scripts/verify.sh scripts/check_state.sh

# 2. Check current state before applying
sudo bash scripts/check_state.sh

# 3. Apply the bypass
sudo ./run_bypass.sh

# 4. Verify everything is active
sudo bash scripts/verify.sh

# 5. Undo when you're done (e.g. back on regular Wi-Fi)
sudo ./undo_bypass.sh
```

> **Note on persistence:** TTL and port range changes are written to `/etc/sysctl.d/99-airtel-bypass.conf`
> so they survive reboots. The undo script removes this file automatically.
> iptables rules are NOT persistent across reboots by default — re-run `run_bypass.sh` after a reboot
> if you need them again, or install `iptables-persistent` and let the undo script handle it.

---

## File Structure

```
fuck_airtel/
├── RUN_AS_ADMIN.bat        ← [Windows] Apply bypass (double-click)
├── UNDO_BYPASS.bat         ← [Windows] Revert everything (double-click)
├── run_bypass.sh           ← [Linux]   Apply bypass (auto-elevates via sudo)
├── undo_bypass.sh          ← [Linux]   Revert everything
├── README.md
└── scripts/
    ├── bypass.ps1          ← [Windows] Core logic (all 8 detection vectors)
    ├── verify.ps1          ← [Windows] Verification — checks all 18 settings
    ├── VERIFY.bat          ← [Windows] Run verification (double-click)
    ├── check_state.ps1     ← [Windows] Dump current network state for debugging
    ├── fix_encoding.ps1    ← [Windows] UTF-8 BOM fixer (dev utility)
    ├── bypass.sh           ← [Linux]   Core logic (all 8 detection vectors)
    ├── verify.sh           ← [Linux]   Verification — checks all settings
    └── check_state.sh      ← [Linux]   Dump current network state for debugging
```

---

## What Gets Backed Up & Restored

Before making any changes, the script saves your original settings to:
```
C:\Users\<you>\.airtel_bypass_backup.json
```

This backup includes your original TTL, DNS servers, MTU, and TCP settings. The Undo command reads this file and restores everything exactly as it was.

---

## Verification — What Each Check Tests

| # | Check | Expected |
|---|---|---|
| 1 | Registry TTL | 65 |
| 2 | Live Stack TTL (netsh) | 65 |
| 3 | IPv6 Hop Limit | 65 |
| 4 | MTU on Wi-Fi adapter | 1400 |
| 5 | DNS servers | 1.1.1.1, 1.0.0.1 |
| 6 | Windows Update service | Stopped |
| 7 | Windows Update startup | Disabled |
| 8 | DiagTrack service | Stopped |
| 9 | Total firewall rules | 35+ |
| 10 | Update domains blocked | 13+ |
| 11 | Telemetry domains blocked | 10+ |
| 12 | Desktop apps blocked | 6 |
| 13 | Discovery protocols blocked | 4/4 |
| 14 | TCP connection limit | 24 |
| 15 | TCP auto-tuning | Disabled |
| 16 | NCSI probing | Disabled |
| 17 | Internet access | ✅ |
| 18 | DNS resolution | ✅ |

---

## Disclaimer

These scripts modify your **local** network stack settings only (TTL, MTU, firewall rules, DNS). They do not modify any Airtel infrastructure, do not involve packet injection, and do not intercept any traffic. They make your device *look like* a mobile device to your carrier's passive observation systems, which is comparable to changing your browser's User-Agent.

Use at your own risk. The author is not responsible for any throttling, account suspension, or consequences that may arise from use of these scripts.

---

## Contributing

Got a better sarcastic tagline? Open a PR. Found another detection vector? Open an issue.

**github.com/sayann70**
