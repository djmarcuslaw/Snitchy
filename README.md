# Snitchy

**A real-time log of every network connection your Mac makes: which app, where to, and whether that app is signed by someone accountable.** It comes with a local dashboard styled after Pi-hole's.

Snitchy only *watches*. It doesn't block anything, so keep using [LuLu](https://objective-see.org/products/lulu.html) (or another firewall) for that. Snitchy fills the gap LuLu leaves: a searchable history.

- **Live log.** New connections show up within about a second.
- **Per-app.** Uses Apple's own per-packet process tags, so it knows that `Slack Helper` is part of Slack and that `nsurlsessiond` was downloading something for Spotify.
- **Hostnames, not just IPs.** It reads the name each app put in its HTTPS hello, falls back to the DNS lookup, and finally to who owns the IP.
- **Sketchiness check.** Every program that connects is checked with Apple's `codesign` tool. Unsigned, ad-hoc-signed and tampered apps get flagged.
- **Private.** Everything stays on your Mac. The dashboard only answers to `localhost`, and nothing is sent anywhere.

---

## Install

You need [Homebrew](https://brew.sh). Paste these into Terminal one at a time:

```bash
# 1. Tell Homebrew where Snitchy lives
brew tap djmarcuslaw/snitchy https://github.com/djmarcuslaw/Snitchy

# 2. Install it
brew install --HEAD snitchy

# 3. Start it now and at every boot (asks for your Mac password)
sudo brew services start snitchy

# 4. Open the dashboard
open http://localhost:8899
```

Why the password? Watching network traffic needs administrator rights on every operating system. Snitchy uses them only to start Apple's built-in `tcpdump` and a tiny helper that looks up which program a process ID belongs to. Everything else (parsing, database, web dashboard) then runs as the powerless `nobody` user.

### Check it works (optional)

```bash
sudo snitchy selftest
```

This captures for 15 seconds and lists each connection as it happens. Open a website while it runs and you should see your browser appear.

### Update / stop / uninstall

```bash
brew upgrade --fetch-HEAD snitchy && sudo brew services restart snitchy   # update
sudo brew services stop snitchy                                           # stop
sudo brew services stop snitchy && brew uninstall snitchy                 # uninstall
sudo rm -rf "/Library/Application Support/Snitchy"                        # delete the log
```

---

## Using the dashboard

| Part | What it tells you |
|---|---|
| **Tiles** | Connections, how many apps, how many destinations, and how many connections came from unsigned/ad-hoc apps |
| **Connections over time** | Hover a bar for exact counts. Spikes while you're idle are worth a look |
| **Apps worth a look** | Appears only when an unsigned, ad-hoc or tampered program connected |
| **Top apps / destinations** | Click any name to jump to its connections in the log |
| **Connection log** | Live feed. Search anything (app, domain, IP, file path), filter by direction, pause, and click a row for full details |

### Signature badges

| Badge | Meaning |
|---|---|
| ✓ **Apple** | Part of macOS or an Apple app |
| ✓ **App Store** | Distributed through the Mac App Store |
| ✓ **Developer ID** | Signed by a developer Apple has identified (name shown on hover) |
| ! **Ad-hoc** | "Signed" with no identity, so nobody vouches for it. Normal for things you built yourself and some open-source tools; unusual for commercial apps |
| ! **Unsigned** | No signature at all |
| ✕ **Broken signature** | The files changed after signing. Legit apps occasionally do this after a bad update, but it's also what tampering looks like |

A flag isn't proof of anything bad; it means "nobody accountable signed this, so look closer". Click the row to see the program's full path on disk.

### Where hostnames come from

Each destination shows a small tag:

- **sni**: the name the app itself sent when opening an HTTPS connection. Most reliable.
- **dns**: the name the app looked up to get that IP.
- **rdns**: a reverse lookup of the IP. Often a hosting company (e.g. `...amazonaws.com`) rather than the actual service.
- *(bare IP)*: none of the above worked. Common with encrypted DNS, iCloud Private Relay, VPNs, or apps that connect to hard-coded IPs (which can itself be a red flag).

---

## Settings

Change how the background service runs by editing the formula's `run` line, or run Snitchy by hand with options:

```bash
sudo snitchy run --keep-days 90        # history length (default 30, 0 = forever)
sudo snitchy run --port 9000           # dashboard port (default 8899)
sudo snitchy run --include-loopback    # also log app-to-app traffic inside your Mac
sudo snitchy run --no-rdns             # don't do reverse lookups of unnamed IPs
snitchy demo                           # preview the dashboard with fake data (no sudo)
```

---

## Known limits

- **Watching only.** It can't tell whether LuLu blocked a connection; it sees the attempt.
- **Encrypted names.** HTTP/3 (QUIC) and encrypted DNS hide hostnames from passive capture, so some rows only get an IP or a reverse-lookup name.
- **Very fast downloads.** At sustained hundreds of MB/s, macOS may drop some captured packets. Connections are rarely missed, but byte counts can run low.
- **Short-lived programs.** If a program exits within milliseconds, Snitchy may not catch its path on disk in time, so its signature shows as "Unknown".
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
| `snitchy/pidpath.py` | The small root helper that maps a process ID to its program path |
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

Every push runs [CI](.github/workflows/ci.yml) on a real Mac in GitHub's cloud. It does a live capture, checks that a `curl` to example.com is attributed to `/usr/bin/curl` with an Apple signature, then installs through Homebrew and queries the running service.

## License

MIT. See [LICENSE](LICENSE).
