"""Made-up traffic for `snitchy demo`, so the dashboard can be previewed
without root or a real capture. Nothing here touches the network."""

import random
import time

from .tracker import Flow

# (app, path, signing, signer, typical destinations)
APPS = [
    ("Safari", "/Applications/Safari.app", "apple", "Apple",
     ["www.apple.com", "news.ycombinator.com", "en.wikipedia.org", "www.nytimes.com", "fonts.gstatic.com"]),
    ("Google Chrome", "/Applications/Google Chrome.app", "developer", "Google LLC (EQHXZ8M8AV)",
     ["www.google.com", "clients4.google.com", "update.googleapis.com", "www.youtube.com", "i.ytimg.com"]),
    ("Slack", "/Applications/Slack.app", "developer", "Slack Technologies, Inc. (BQR82RBBHL)",
     ["wss-primary.slack.com", "edgeapi.slack.com", "slack-edge.com", "sentry.io"]),
    ("Spotify", "/Applications/Spotify.app", "developer", "Spotify (2FNC3A47ZF)",
     ["apresolve.spotify.com", "spclient.wg.spotify.com", "audio-ak.spotifycdn.com"]),
    ("mDNSResponder", "/usr/sbin/mDNSResponder", "apple", "Apple", ["1.1.1.1", "192.168.1.1"]),
    ("apsd", "/System/Library/PrivateFrameworks/ApplePushService.framework/apsd", "apple", "Apple",
     ["courier.push.apple.com"]),
    ("Microsoft Word", "/Applications/Microsoft Word.app", "appstore", "UBF8T346G9",
     ["nexusrules.officeapps.live.com", "mobile.events.data.microsoft.com", "self.events.data.microsoft.com"]),
    ("Zoom", "/Applications/zoom.us.app", "developer", "Zoom Video Communications, Inc. (BJ4HAAB9B3)",
     ["zoom.us", "log-gateway.zoom.us"]),
    ("helperd", "/Users/you/Library/Application Support/.helper/helperd", "unsigned", "",
     [None, None, "ec2-3-91-112-7.compute-1.amazonaws.com"]),
    ("Free PDF Converter", "/Applications/Free PDF Converter.app", "adhoc", "",
     ["api.pdf-convert-free.xyz", "tracking.adnet-metrics.io"]),
]

WEIGHTS = [30, 25, 12, 8, 15, 5, 6, 4, 2, 2]


def _fake_ip(rng):
    return "%d.%d.%d.%d" % (rng.choice([17, 23, 34, 52, 104, 142, 151, 172, 185]), rng.randrange(256),
                            rng.randrange(256), rng.randrange(1, 255))


def _make_flow(rng, ts):
    app, path, _signing, _signer, dests = rng.choices(APPS, WEIGHTS)[0]
    domain = rng.choice(dests)
    ip = domain if domain and domain[0].isdigit() else _fake_ip(rng)
    if domain and domain[0].isdigit():
        domain = None
    udp = app == "mDNSResponder" or rng.random() < 0.15
    source = None if not domain else ("rdns" if "compute" in domain else rng.choice(["sni", "sni", "dns"]))
    out = rng.randrange(400, 40_000)
    flow = Flow(key=None, proto="udp" if udp else "tcp", direction="in" if rng.random() < 0.02 else "out",
                iface=rng.choice(["en0", "en0", "en0", "utun4"]), local_ip="192.168.1.23",
                local_port=rng.randrange(49152, 65535), remote_ip=ip,
                remote_port=53 if app == "mDNSResponder" else rng.choice([443, 443, 443, 80, 5223]),
                ts_start=ts, ts_last=ts + rng.random() * 30, app=app, pid=rng.randrange(300, 9000),
                path=path, via="nsurlsessiond" if rng.random() < 0.05 else "",
                domain=domain, domain_source=source,
                bytes_out=out, bytes_in=int(out * rng.uniform(0.5, 40)),
                packets_out=rng.randrange(3, 60), packets_in=rng.randrange(3, 200))
    return flow


def fill_demo_data(store, hours=24 * 3, seed=7):
    rng = random.Random(seed)
    now = time.time()
    flows = []
    t = now - hours * 3600
    while t < now:
        hour = time.localtime(t).tm_hour
        busy = 1.0 if 8 <= hour <= 23 else 0.15          # quieter overnight
        t += rng.expovariate(busy / 25.0)
        flows.append(_make_flow(rng, t))
    store.insert_connections(flows)
    for app, path, signing, signer, _ in APPS:
        store.save_signature(path, signing, signer)


def live_demo(store, hub):
    """Keep adding a fake connection every second or two, like a real capture."""
    rng = random.Random()
    while True:
        time.sleep(rng.uniform(0.3, 2.0))
        flow = _make_flow(rng, time.time())
        store.insert_connections([flow])
        for row in store.get_connections([flow.row_id]):
            hub.publish({"type": "new", "row": row})
