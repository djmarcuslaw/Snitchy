# Snitchy

**A real-time log of every network connection your Mac makes: which app, where to, and whether that app is signed by someone accountable.** It comes with a local dashboard styled after Pi-hole's.

Snitchy only *watches*. It doesn't block anything, so keep using [LuLu](https://objective-see.org/products/lulu.html) (or another firewall) for that. Snitchy fills the gap LuLu leaves: a searchable history.

- **Live log.** New connections show up within about a second.
- **Per-app.** Uses Apple's own per-packet process tags, so it knows that `Slack Helper` is part of Slack and that `nsurlsessiond` was downloading something for Spotify.
- **Hostnames, not just IPs.** It reads the name each app put in its HTTPS hello, falls back to the DNS lookup, and finally to who owns the IP.
- **Sketchiness check.** Every program that connects is checked with Apple's `codesign` tool, including whether Apple really issued its certificate. Unsigned, ad-hoc, self-signed and tampered apps get flagged.
- **Private.** Everything stays on your Mac. The log is readable only by the service, and the dashboard needs a sign-in. See [Privacy](#privacy).

---

## Install

You need [Homebrew](https://brew.sh). Paste these into Terminal one at a time:

```bash
# 1. Tell Homebrew where Snitchy lives
brew tap djmarcuslaw/snitchy https://github.com/djmarcuslaw/Snitchy

# 2. Trust it (Homebrew asks this once for any tap outside its own catalog)
brew trust djmarcuslaw/snitchy

# 3. Install it
brew install --HEAD snitchy

# 4. Install the background service: runs now and at every boot (asks for your Mac password)
sudo snitchy install-service

# 5. Open the dashboard (this also signs you in)
snitchy open
```

Step 4 needs Apple's Command Line Tools, which Homebrew already installed.

Why the password? Watching network traffic needs administrator rights on every operating system. Snitchy uses them only to start Apple's built-in `tcpdump` and two tiny helpers: one looks up which program a process ID belongs to, the other checks a program's signature. Everything else (parsing, database, web dashboard) then runs as the powerless `nobody` user.

Why not `brew services`? Homebrew's files belong to your user account, so a root service running from there could be hijacked by anything running as you. `install-service` copies Snitchy into `/Library/Snitchy`, owned by root, and runs it with Apple's own Python instead.

> **Upgrading from an earlier Snitchy** that used `sudo brew services start snitchy`? Just run step 4. It stops and removes the old service for you.

### Check it works (optional)

```bash
sudo snitchy selftest
```

This captures for 15 seconds and lists each connection as it happens. Open a website while it runs and you should see your browser appear.

### Update / stop / uninstall

```bash
brew upgrade --fetch-HEAD snitchy && sudo snitchy install-service    # update
sudo snitchy uninstall-service                                        # stop and remove the service
sudo snitchy uninstall-service --delete-data && brew uninstall snitchy   # remove everything, including the log
```

---

## Using the dashboard

| Part | What it tells you |
|---|---|
| **Tiles** | Connections, how many apps, how many destinations, and how many connections came from unverified apps |
| **Connections over time** | Hover a bar for exact counts. Spikes while you're idle are worth a look |
| **Apps worth a look** | Appears only when an unsigned, ad-hoc, self-signed or tampered program connected |
| **Top apps / destinations** | Click any name to jump to its connections in the log |
| **Connection log** | Live feed. Search anything (app, domain, IP, file path), filter by direction, pause, and click a row for full details |

### Signature badges

| Badge | Meaning |
|---|---|
| ✓ **Apple** | Part of macOS or an Apple app |
| ✓ **App Store** | Distributed through the Mac App Store |
| ✓ **Developer ID** | Signed with a certificate Apple issued to an identified developer (name shown on hover) |
| ! **Ad-hoc** | "Signed" with no identity, so nobody vouches for it. Normal for things you built yourself and some open-source tools; unusual for commercial apps |
| ! **Unsigned** | No signature at all |
| ✕ **Untrusted cert** | Signed with a certificate Apple didn't issue. Malware does this to look legitimate, e.g. a homemade certificate named "Developer ID Application: Something" |
| ✕ **Broken signature** | The files changed after signing. Legit apps occasionally do this after a bad update, but it's also what tampering looks like |

A flag isn't proof of anything bad; it means "nobody accountable signed this, so look closer". Click the row to see the program's full path on disk.

### Where hostnames come from

Each destination shows a small tag:

- **sni**: the name the app itself sent when opening an HTTPS connection. Most reliable.
- **dns**: the name the app looked up to get that IP.
- **rdns**: a reverse lookup of the IP. Often a hosting company (e.g. `...amazonaws.com`) rather than the actual service.
- *(bare IP)*: none of the above worked. Common with encrypted DNS, iCloud Private Relay, VPNs, or apps that connect to hard-coded IPs (which can itself be a red flag).

**Hostnames are claims, not proof.** An app chooses what name to send in its HTTPS hello, so malware can say it's talking to `apple.com` while connecting somewhere else. Snitchy only accepts DNS answers that match a lookup it saw your Mac make, which stops other devices on your network from relabelling your connections with forged answers. When a name looks wrong for an app, check the IP in the row details.

---

## Settings

Pass options to `install-service` (run it again to change them):

```bash
sudo snitchy install-service --keep-days 90       # history length (default 30, 0 = forever)
sudo snitchy install-service --port 9000          # dashboard port (default 8899; use `snitchy open --port 9000`)
sudo snitchy install-service --include-loopback   # also log app-to-app traffic inside your Mac
sudo snitchy install-service --no-rdns            # don't do reverse lookups of unnamed IPs
sudo snitchy install-service --keep-in-backups    # let Time Machine back up the log
snitchy demo                                      # preview the dashboard with fake data (no sudo)
```

---

## Privacy

The log is effectively a browsing history, **including sites visited in private browsing**, since Snitchy sees the traffic, not the browser's settings. So:

- **Nothing leaves your Mac.** No analytics, no update checks, and the dashboard loads nothing from the internet. Packet contents are never stored, only which app, where, when and how much.
- **Only the service can read the log.** It lives in `/Library/Application Support/Snitchy`, readable only by Snitchy's own account (and root).
- **The dashboard needs a sign-in.** `snitchy open` signs you in using a password file only administrator accounts can read. Other accounts on your Mac can't view your history, and websites can't read it from your browser.
- **Kept out of Time Machine** by default. Use `--keep-in-backups` if you want it backed up.
- **Reverse lookups** (for IPs with no name) ask your DNS provider who owns an IP. It usually saw the original lookup anyway, but `--no-rdns` turns this off.
- **History is deleted after 30 days** unless you change `--keep-days`.

---

## Known limits

- **Watching only.** It can't tell whether LuLu blocked a connection; it sees the attempt.
- **Encrypted names.** HTTP/3 (QUIC) and encrypted DNS hide hostnames from passive capture, so some rows only get an IP or a reverse-lookup name.
- **Very fast downloads.** At sustained hundreds of MB/s, macOS may drop some captured packets. Connections are rarely missed, but byte counts can run low.
- **A compromised account at install time.** `install-service` copies whatever Snitchy is installed at that moment into the root-owned folder. If you suspect something on your account has tampered with your Homebrew files, don't run it.
- **Short-lived programs.** If a program exits within milliseconds, Snitchy may not catch its path on disk in time, so its signature shows as "Unknown".
- **Protected folders.** macOS privacy protection stops even administrator processes from reading Desktop, Documents and Downloads unless they've been granted Full Disk Access. Programs run straight from those folders may show "Unknown" instead of a real verdict. (Granting Full Disk Access should fix this, but I haven't yet tested which exact program needs it.)
- **This Mac only.** Your Pi-hole covers the rest of the network.

---

## How it works

```
Apple tcpdump (root)  ──pcapng──▶  Snitchy (runs as "nobody")  ──▶  SQLite log  ──▶  dashboard
   -i pktap,all -P                   decode packets, group into                        localhost:8899
   (tags each packet                 connections, name hosts,                          live via
    with its process)                check code signatures                             Server-Sent Events
```

macOS's `tcpdump` has a hidden capture mode, `pktap`, that attaches the sending process to every packet. With `-P` it writes those tags into the capture as "Process Information Blocks", a format documented only in [Apple's open-source libpcap](https://github.com/apple-oss-distributions/libpcap/blob/main/libpcap/pcap/pcap-ng.h). Snitchy reads that stream live.

| File | Job |
|---|---|
| `snitchy/pcapng.py` | Reads tcpdump's output, including Apple's process tags |
| `snitchy/packets.py` | Decodes IP/TCP/UDP, DNS answers and HTTPS hostnames |
| `snitchy/tracker.py` | Groups packets into connections and credits each to an app |
| `snitchy/appinfo.py` | Finds the program on disk and checks its signature |
| `snitchy/pidpath.py` | The small root helpers: process ID → program path, and program → signature |
| `snitchy/service.py` | Installs the root-owned background service |
| `snitchy/store.py` | The SQLite log |
| `snitchy/capture.py` | Runs tcpdump and ties everything together |
| `snitchy/server.py` | The local web server |
| `snitchy/web/` | The dashboard (HTML/CSS/JS, no external libraries) |
| `Formula/snitchy.rb` | Homebrew install recipe |

No third-party Python packages are used: only Python's standard library and tools that ship with macOS.

### Development

```bash
python3 -m unittest discover -s tests -v   # tests (work on any OS)
python3 -m snitchy demo                    # dashboard with fake data
```

Every push runs [CI](.github/workflows/ci.yml) on a real Mac in GitHub's cloud. It does a live capture, checks that a `curl` to example.com is attributed to `/usr/bin/curl` with an Apple signature, then installs through Homebrew and `install-service`, checks the service runs from root-owned files with Apple's Python, that the dashboard is locked until signed in, and that it logs traffic.

## License

MIT. See [LICENSE](LICENSE).
