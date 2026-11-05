"""owctl.routing"""
import owctl  # shared namespace (patched names)

import base64, difflib, json, os, re, secrets, smtplib, socket, sqlite3, ssl
import threading, time, logging, sys, ipaddress, paramiko, bcrypt
import urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.message import EmailMessage
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

_IP4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _valid_ip4(ip):
    if not (isinstance(ip, str) and _IP4.match(ip)):
        return False
    return all(0 <= int(o) <= 255 for o in ip.split("."))


def _valid_cidr(dst):
    """Validate an IPv4 CIDR (a.b.c.d or a.b.c.d/p, p in 0..32). Pure."""
    if not isinstance(dst, str):
        return False
    dst = dst.strip()
    if "/" in dst:
        base, _, prefix = dst.partition("/")
        if not prefix.isdigit() or not (0 <= int(prefix) <= 32):
            return False
        if not _valid_ip4(base):
            return False
        # for a network route the host bits are conventionally zero, but we
        # accept any base and normalize; for /32 the host IS the network.
        return True
    return _valid_ip4(dst)


def _route_iface(dev, dst, via, policy):
    """Choose the network section to hang a static route off of.

    OpenWrt attaches a static route to an interface via `network.<if>.route`
    list (+ per-route gateway). We pin logical routes to the interface that
    owns the gateway's subnet when it can be determined from `via`; otherwise
    the device's primary routed interface (the one with a `static` proto),
    falling back to 'lan'. Pure — no I/O.
    """
    # via "vlan:<id>" -> the VLAN's routed interface is "vlan_<id>".
    if isinstance(via, str) and via.startswith("vlan:"):
        try:
            vid = int(via.split(":", 1)[1])
        except (ValueError, IndexError):
            vid = 0
        if vid:
            return f"vlan_{vid}"
    return None  # caller falls back to the device's primary routed interface


def _primary_routed_iface(dev):
    """Best-effort primary routed interface name for a device (no I/O): prefer
    a VLAN router role if recorded, else 'lan'. Used only as the attach point
    when the route's own `via` doesn't name an interface."""
    try:
        row = owctl.q("SELECT d.name FROM vlans_devices m JOIN devices d ON d.id=m.device_id "
                "WHERE m.device_id=? AND m.role='router' ORDER BY d.id LIMIT 1", (dev["id"],))
        if row:
            return f"vlan_{row[0]['name']}"
    except Exception:
        pass
    return "lan"


def resolve_via(dev, via):
    """Resolve a route's `via` to a concrete IPv4 gateway, or raise HTTPException(400).

    - a concrete IPv4 address is returned as-is
    - "vlan:<id>" resolves to the gateway of that VLAN's routed interface
      (network.vlan_<id>.gateway), falling back to the .1 of its subnet.
    Pure with respect to SSH (reads only the in-memory/DB VLAN record); the
    actual on-device gateway is read separately when the route is applied.
    """
    via = (via or "").strip()
    if _valid_ip4(via):
        return via
    if via.startswith("vlan:"):
        try:
            vid = int(via.split(":", 1)[1])
        except (ValueError, IndexError):
            raise HTTPException(400, f"invalid logical via {via!r} (expected vlan:<id> or an IPv4 address)")
        if not (1 <= vid <= 4094):
            raise HTTPException(400, f"invalid VLAN id {vid} in via")
        # The concrete gateway is determined at apply time from the device's
        # config; for validation/storage we just confirm the VLAN exists.
        vlan = owctl.q("SELECT * FROM vlans WHERE vlan_id=?", (str(vid),))
        if not vlan:
            raise HTTPException(400, f"via refers to unknown VLAN {vid} (create it first)")
        return f"vlan_{vid}"  # marker: the do_* op resolves to the live gateway
    raise HTTPException(400, f"invalid via {via!r} (expected an IPv4 address or vlan:<id>)")


def parse_routing(uci_network_show):
    """Pure parser: `uci show network` text -> {iface: {gateway, statics:[{dst,gateway,metric}]}}.

    OpenWrt static routes are parallel lists on an interface:
    ``network.<if>.route='CIDR1 CIDR2'`` plus ``.route.gateway='G1 G2'`` and
    ``.route.metric='M1 M2'``. `uci show` renders a list as a single quoted,
    space-separated value, so we split with _uci_values and zip the three
    parallel lists. Per-interface default gateway comes from ``.gateway``.
    Returns {} for empty/absent input so "no routes" and "no data" are the same.
    """
    raw = owctl._parse_uci_show(uci_network_show or "")
    out = {}
    for section, opts in raw.items():
        m = re.match(r"^network\.(\w+)$", section)
        if not m:
            continue
        iface = m.group(1)
        d = {"gateway": None, "statics": []}
        d["gateway"] = (opts.get("gateway") or [None])[0]
        dsts = owctl._uci_list_values(uci_network_show or "", section, "route")
        gws = owctl._uci_list_values(uci_network_show or "", section, "route.gateway")
        mets = owctl._uci_list_values(uci_network_show or "", section, "route.metric")
        for i, dst in enumerate(dsts):
            d["statics"].append({
                "dst": dst,
                "gateway": gws[i] if i < len(gws) else None,
                "metric": int(mets[i]) if i < len(mets) and mets[i].isdigit() else None,
            })
        out[iface] = d
    return out


def parse_ip_route(ip_route_output):
    """Pure parser: `ip route` (Linux) text -> list of
    {dst, gateway, dev, metric}. Handles the default route and CIDR entries.
    Returns [] for empty/absent input."""
    routes = []
    for line in (ip_route_output or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        dst = parts[0]
        entry = {"dst": dst, "gateway": None, "dev": None, "metric": None}
        for i, tok in enumerate(parts):
            if tok == "via" and i + 1 < len(parts):
                entry["gateway"] = parts[i + 1]
            elif tok == "dev" and i + 1 < len(parts):
                entry["dev"] = parts[i + 1]
            elif tok == "metric" and i + 1 < len(parts):
                try:
                    entry["metric"] = int(parts[i + 1])
                except ValueError:
                    pass
        routes.append(entry)
    return routes


def parse_bgp_config(bird_or_bgp_conf):
    """Pure parser: detect and summarize a BGP daemon config from raw text.

    Accepts bird `router` blocks or a quagga/bgpd `router bgp` stanza. Returns
    {present:bool, asn:int|None, peers:[{addr, as, name}]}. Empty/None input ->
    {present:False, asn:None, peers:[]} so callers can no-op cleanly."""
    res = {"present": False, "asn": None, "peers": []}
    if not (bird_or_bgp_conf or "").strip():
        return res
    text = bird_or_bgp_conf
    # BGP ASN — bird `local as N;`, quagga `router bgp N`, bgpd `as N` / `as = N`.
    m = (re.search(r"\blocal\s+as\s+(\d+)", text)
         or re.search(r"\bras\s*=\s*(\d+)", text)
         or re.search(r"\brouter\s+bgp\s+(\d+)", text)
         or re.search(r"\bas\s+(\d+)", text))
    if m:
        res["asn"] = int(m.group(1))
        res["present"] = True
    # Peers: bird `neighbor X { as N }` or quagga `neighbor X remote-as N`
    for pm in re.finditer(r"neighbor\s+([\d.]+|[\w:-]+)\s*\{?[^}]*?\b(as|remote-as)\s*=?\s*(\d+)", text):
        res["peers"].append({"addr": pm.group(1), "as": int(pm.group(3)), "name": None})
        res["present"] = True
    return res


def build_route_cmds(dev, dst, via, metric, iface, apply):
    """Pure: the uci script that adds a static route to `iface` on one device.

    Idempotent: removes any existing route with the same dst on that iface
    before adding, then commits network (and restarts when apply=True).
    `via` here is a CONCRETE gateway (resolved by the do_* op).
    """
    if not _valid_cidr(dst):
        raise HTTPException(400, f"invalid destination CIDR {dst!r}")
    if not _valid_ip4(via):
        raise HTTPException(400, f"invalid gateway {via!r}")
    cmd = (
        f"for r in $(uci -q list network.{iface}.route 2>/dev/null); do "
        f"n=${{r#network.{iface}.route}}; "
        f"d=$(uci -q get network.{iface}.route.$n 2>/dev/null); "
        f"if [ \"$d\" = '{dst}' ]; then uci -q del_list network.{iface}.route.$n 2>/dev/null; "
        f"uci -q del network.{iface}.route.gateway.$n 2>/dev/null; "
        f"uci -q del network.{iface}.route.metric.$n 2>/dev/null; fi; done\n"
        f"n=$(uci add network.{iface}.route '{dst}')\n"
        f"uci set network.{iface}.route.gateway.$n='{via}'\n"
    )
    if metric is not None:
        cmd += f"uci set network.{iface}.route.metric.$n='{int(metric)}'\n"
    cmd += "uci commit network\n"
    if apply:
        cmd += (owctl._PENDING_RESTARTS["routing"] + "\n")
    return cmd


def build_policy_route_cmds(dev, table, match_dst, route_dst, via, iface, apply):
    """Pure: uci script for a POLICY-routing table entry on one device.

    OpenWrt policy routing = a named `network` interface whose `proto=static`
    route lives in a `route` table, selected by an `ip rule` match. We model it
    as: ensure a routing table named `table`, add the route there, and an
    `ip rule` from `match_dst` -> that table. `via` must be concrete.
    """
    if not _valid_cidr(match_dst):
        raise HTTPException(400, f"invalid match CIDR {match_dst!r}")
    if not _valid_cidr(route_dst):
        raise HTTPException(400, f"invalid route destination {route_dst!r}")
    if not _valid_ip4(via):
        raise HTTPException(400, f"invalid gateway {via!r}")
    t = re.sub(r"[^A-Za-z0-9_]", "_", table)
    cmd = (
        f"t=$(ip route show table {t} 2>/dev/null)\n"
        f"if [ -z \"$t\" ]; then ip route add table {t} default via '{via}' dev {iface} 2>/dev/null || "
        f"ip route add table {t} {route_dst} via '{via}' dev {iface} 2>/dev/null; fi\n"
        f"ip rule add from {match_dst} lookup {t} 2>/dev/null || true\n"
    )
    if apply:
        cmd += owctl._PENDING_RESTARTS["routing"] + "\n"
    return cmd


def build_bgp_cmds(dev, asn, peers, apply):
    """Pure: install a minimal BGP (bird) config on one device and restart it.

    `peers` is a list of {addr, as, name}. Generates /etc/birdc/owctl.bgp with
    one router block, then `birdc configure`. Requires the `bird` package
    (installed by the do_* op via ensure_pkg). Raises HTTPException(400) on a
    bad ASN or peer.
    """
    if not (isinstance(asn, int) and 1 <= asn <= 4294967295):
        raise HTTPException(400, f"invalid BGP ASN {asn!r}")
    peer_lines = []
    for p in peers:
        if not _valid_ip4(p.get("addr")):
            raise HTTPException(400, f"invalid BGP peer address {p.get('addr')!r}")
        if not (isinstance(p.get("as"), int) and 1 <= p["as"] <= 4294967295):
            raise HTTPException(400, f"invalid BGP peer ASN {p.get('as')!r} for {p.get('addr')}")
        peer_lines.append(
            f"\tnet {p['addr']}/32;\n"
            f"\tgraceful restart;\n"
            f"\tprotocol bgp owctl_{re.sub(r'[^A-Za-z0-9]', '_', p['addr'])} {{\n"
            f"\t\tlocal as {asn};\n"
            f"\t\tdynamic paths yes;\n"
            f"\t\tmultihop true;\n"
            f"\t\tlearn;\n"
            f"\t\texport all;\n"
            f"\t\timport all;\n"
            f"\t}}\n"
        )
    body = (
        f"router id '127.0.0.1';\n"
        f"protocol device;\n"
        f"protocol bgp owctl_self {{\n"
        f"\tlocal as {asn};\n"
        f"\timport all;\n"
        f"\texport all;\n"
        f"}}\n"
        + "\n".join(peer_lines)
    )
    cmd = (
        "opkg list-installed bird >/dev/null 2>&1 || opkg install -y bird\n"
        "mkdir -p /etc/birdc\n"
        "cat > /etc/birdc/owctl.bgp <<'OWCTL_BGP'\n" + body + "\nOWCTL_BGP\n"
        "if [ -f /etc/birdc/bird.cfg ]; then "
        "grep -q 'owctl.bgp' /etc/birdc/bird.cfg || echo \"include \"/etc/birdc/owctl.bgp\";\" >> /etc/birdc/bird.cfg; fi\n"
        "birdc configure 2>/dev/null || /etc/init.d/bird restart 2>/dev/null || true\n"
    )
    if apply:
        cmd += owctl._PENDING_RESTARTS["routing"] + "\n"
    return cmd


def _bgp_pkg_present(dev):
    try:
        c = owctl._ssh_connect(dev)
        try:
            out, _e, _s = owctl._exec_capture(c, "opkg list-installed bird 2>/dev/null", timeout=20)
        finally:
            c.close()
        return bool(out.strip())
    except Exception:
        return False


def read_routing(dev):
    """Read a device's live routing table + network config. Returns a dict with
    {name,host,gateways,statics,ip_routes,policy,bgp,error} or {error:..} on
    failure. Pure-SSH; never raises past the error field."""
    if dev["access"] != "ssh":
        return {"name": dev.get("name"), "host": dev.get("host"), "error": "luci-only device skipped"}
    try:
        c = owctl._ssh_connect(dev)
        try:
            out, _e, _s = owctl._exec_capture(c, (
                "echo '##uci##'; uci show network 2>/dev/null; "
                "echo '##iproute##'; ip route show 2>/dev/null; "
                "echo '##iprule##'; ip rule list 2>/dev/null; "
                "echo '##bgp##'; cat /etc/birdc/owctl.bgp 2>/dev/null || cat /etc/birdc/bird.cfg 2>/dev/null; "
                "true"), timeout=30)
        finally:
            c.close()
        secs = _split_sections(out)
        uci = secs.get("uci", "")
        iproute = secs.get("iproute", "")
        iprule = secs.get("iprule", "")
        bgp = secs.get("bgp", "")
        routing = parse_routing(uci)
        return {
            "name": dev.get("name"), "host": dev.get("host"),
            "interfaces": routing,
            "ip_routes": parse_ip_route(iproute),
            "policy": parse_ip_rule(iprule),
            "bgp": parse_bgp_config(bgp),
            "error": None,
        }
    except Exception as e:
        return {"name": dev.get("name"), "host": dev.get("host"), "error": str(e)}


def _split_sections(out):
    """Split a gather-style '##name##' section dump into {name: body}."""
    sections = {}
    cur = None
    buf = []
    for line in (out or "").splitlines():
        m = re.match(r"^##(\w+)##$", line.strip())
        if m:
            if cur:
                sections[cur] = "\n".join(buf)
            cur = m.group(1)
            buf = []
        else:
            buf.append(line)
    if cur:
        sections[cur] = "\n".join(buf)
    return sections


def parse_ip_rule(ip_rule_output):
    """Pure parser: `ip rule` text -> list of {priority, from, lookup, table}.

    Real `ip rule` output: ``0:      from all lookup local`` / ``1000:   from
    192.168.50.0/24 lookup owctl`` — the priority is the leading ``NNN:``.
    Returns [] for empty/absent input."""
    rules = []
    for line in (ip_rule_output or "").splitlines():
        line = line.strip()
        if not line:
            continue
        rule = {"priority": None, "from": None, "lookup": None, "table": None}
        m = re.match(r"^(\d+):", line)
        if m:
            rule["priority"] = int(m.group(1))
            line = line[m.end():].strip()
        parts = line.split()
        for i, tok in enumerate(parts):
            if tok == "from" and i + 1 < len(parts):
                rule["from"] = parts[i + 1]
            elif tok in ("lookup", "table") and i + 1 < len(parts):
                rule["lookup"] = rule["lookup"] or parts[i + 1]
        if rule["priority"] is not None or rule["lookup"] or rule["from"]:
            rules.append(rule)
    return rules


def _record_route_realization(route_id, device_id, state):
    """Record per-device realization of a logical route. Never raises."""
    try:
        owctl.execute("INSERT INTO routes_devices(route_id, device_id, state) VALUES(?,?,?) "
                "ON CONFLICT(route_id, device_id) DO UPDATE SET state=excluded.state",
                (route_id, device_id, state))
    except Exception:
        pass


def do_route(dev, dst, via, metric, iface, apply=True):
    """Add/replace a static route on one device. `via` may be logical
    (vlan:<id>) — resolved to the device's live gateway first. Idempotent."""
    if dev["access"] != "ssh":
        raise HTTPException(400, "routing config requires SSH access")
    # Resolve logical via to a concrete gateway using the device's live config.
    concrete = _resolve_concrete_via(dev, via)
    if iface is None:
        iface = _route_iface(dev, dst, via, "default") or _primary_routed_iface(dev)
    cmd = build_route_cmds(dev, dst, concrete, metric, iface, apply)
    c = owctl._ssh_connect(dev)
    try:
        out, err, status = owctl._exec_capture(c, cmd, timeout=60)
        if status != 0:
            raise RuntimeError(f"route apply failed on {dev['name']}: exit {status} {(err or out).strip()[:200]}")
    finally:
        c.close()
    owctl.set_pending(dev, "routing", apply)
    owctl.log_action(dev, "route", f"dst={dst} via={via} iface={iface} metric={metric}", ok=True)
    return {"device": dev["name"], "ok": True, "iface": iface}


def do_route_delete(dev, dst, iface, apply=True):
    """Remove a static route (by dst) from one device. Idempotent no-op when absent."""
    if dev["access"] != "ssh":
        raise HTTPException(400, "routing config requires SSH access")
    if not _valid_cidr(dst):
        raise HTTPException(400, f"invalid destination CIDR {dst!r}")
    if iface is None:
        iface = _primary_routed_iface(dev)
    cmd = (
        f"for r in $(uci -q list network.{iface}.route 2>/dev/null); do "
        f"n=${{r#network.{iface}.route}}; "
        f"d=$(uci -q get network.{iface}.route.$n 2>/dev/null); "
        f"if [ \"$d\" = '{dst}' ]; then uci -q del_list network.{iface}.route.$n 2>/dev/null; "
        f"uci -q del network.{iface}.route.gateway.$n 2>/dev/null; "
        f"uci -q del network.{iface}.route.metric.$n 2>/dev/null; fi; done\n"
        "uci commit network\n"
    )
    if apply:
        cmd += owctl._PENDING_RESTARTS["routing"] + "\n"
    c = owctl._ssh_connect(dev)
    try:
        out, err, status = owctl._exec_capture(c, cmd, timeout=60)
        if status != 0:
            raise RuntimeError(f"route delete failed on {dev['name']}: exit {status} {(err or out).strip()[:200]}")
    finally:
        c.close()
    owctl.set_pending(dev, "routing", apply)
    owctl.log_action(dev, "route_delete", f"dst={dst} iface={iface}", ok=True)
    return {"device": dev["name"], "ok": True}


def _resolve_concrete_via(dev, via):
    """Resolve a route `via` to a concrete IPv4 gateway on THIS device.

    Concrete IPv4 -> as-is. "vlan:<id>" -> read that VLAN's routed interface
    gateway (network.vlan_<id>.gateway) from the device; fall back to the .1
    of its subnet from the vlans table; else 400.
    """
    via = (via or "").strip()
    if _valid_ip4(via):
        return via
    if via.startswith("vlan:"):
        vid = via.split(":", 1)[1]
        iface = f"vlan_{vid}"
        gw = None
        try:
            c = owctl._ssh_connect(dev)
            try:
                out, _e, _s = owctl._exec_capture(
                    c, f"uci -q get network.{iface}.gateway 2>/dev/null", timeout=20)
            finally:
                c.close()
            gw = out.strip()
        except Exception:
            gw = None
        if _valid_ip4(gw):
            return gw
        vlan = owctl.q("SELECT * FROM vlans WHERE vlan_id=?", (vid,))
        if vlan and vlan[0].get("subnet"):
            base = vlan[0]["subnet"].split("/")[0]
            return base.rsplit(".", 1)[0] + ".1"
        raise HTTPException(400, f"could not resolve via for VLAN {vid} on {dev['name']} (no gateway found)")
    raise HTTPException(400, f"invalid via {via!r}")


def do_policy_route(dev, table, match_dst, route_dst, via, iface, apply=True):
    """Add a policy-routing table entry on one device."""
    if dev["access"] != "ssh":
        raise HTTPException(400, "policy routing requires SSH access")
    concrete = _resolve_concrete_via(dev, via)
    if iface is None:
        iface = _primary_routed_iface(dev)
    cmd = build_policy_route_cmds(dev, table, match_dst, route_dst, concrete, iface, apply)
    c = owctl._ssh_connect(dev)
    try:
        out, err, status = owctl._exec_capture(c, cmd, timeout=60)
        if status != 0:
            raise RuntimeError(f"policy route failed on {dev['name']}: exit {status} {(err or out).strip()[:200]}")
    finally:
        c.close()
    owctl.set_pending(dev, "routing", apply)
    owctl.log_action(dev, "policy_route", f"table={table} from={match_dst} to={route_dst} via={via}", ok=True)
    return {"device": dev["name"], "ok": True}


def do_bgp(dev, asn, peers, apply=True):
    """Install a minimal bird-based BGP config on one device and restart it."""
    if dev["access"] != "ssh":
        raise HTTPException(400, "BGP requires SSH access")
    cmd = build_bgp_cmds(dev, asn, peers, apply)
    c = owctl._ssh_connect(dev)
    try:
        out, err, status = owctl._exec_capture(c, cmd, timeout=300)
        if status != 0:
            raise RuntimeError(f"BGP config failed on {dev['name']}: exit {status} {(err or out).strip()[:200]}")
    finally:
        c.close()
    owctl.set_pending(dev, "routing", apply)
    owctl.log_action(dev, "bgp", f"asn={asn} peers={len(peers)}", ok=True)
    return {"device": dev["name"], "ok": True}


def parse_mac(s):
    """Normalize/validate a MAC: 'AA:BB:CC:DD:EE:FF' (also accepts dashes).
    Returns lowercase colon form, or None when invalid. Pure."""
    s = (s or "").strip().lower().replace("-", ":")
    if not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", s):
        return None
    return s


def lease_key(lease):
    """Identity of a static lease = its MAC (lowercase)."""
    return parse_mac((lease or {}).get("mac"))


def merge_leases(leases, name, mac, ip):
    """Upsert one static lease into a list, keyed by MAC. Returns a NEW list.
    Same MAC -> the entry is replaced (name/ip updated); new MAC -> appended.
    Pure (no I/O)."""
    mac = parse_mac(mac)
    if not mac:
        raise HTTPException(400, f"invalid MAC address: {mac!r}")
    out = [dict(l) for l in (leases or [])]
    for i, l in enumerate(out):
        if lease_key(l) == mac:
            out[i] = {"name": str(name or l.get("name") or "").strip(),
                      "mac": mac, "ip": str(ip or l.get("ip") or "").strip()}
            return out
    out.append({"name": str(name or "").strip(), "mac": mac, "ip": str(ip or "").strip()})
    return out


def remove_leases(leases, mac):
    """Drop every lease whose MAC matches. Returns a NEW list. Pure."""
    mac = parse_mac(mac)
    if not mac:
        raise HTTPException(400, f"invalid MAC address: {mac!r}")
    return [l for l in (leases or []) if lease_key(l) != mac]


def validate_reservation(ip, mac, subnet=None, gateway_ip=None, leases=None):
    """Validate a single IP reservation BEFORE any SSH. Returns an error string
    or None when the reservation is acceptable.

    Checks: MAC format; IP format; IP in the VLAN subnet (when a subnet is
    known); IP is not the gateway address (when known); IP is not already
    reserved for a different MAC (same-MAC re-reservation is fine — that's an
    edit).
    """
    mac = parse_mac(mac)
    if not mac:
        return f"invalid MAC address: {mac!r}"
    ip = (ip or "").strip()
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return f"invalid IP address: {ip!r}"
    if a.version != 4:
        return f"IPv4 required: {ip!r}"
    if subnet:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            net = None  # bad subnet recorded upstream — skip containment check
        if net and a.version == 4 and a not in net:
            return f"IP {ip} is not in subnet {subnet}"
    if gateway_ip:
        try:
            if a == ipaddress.ip_address(gateway_ip.strip()):
                return f"IP {ip} is the VLAN gateway address"
        except ValueError:
            pass
    for l in (leases or []):
        if lease_key(l) == mac:
            continue  # same device re-reserved — allowed (edit)
        if str(l.get("ip") or "").strip() == ip:
            return f"IP {ip} is already reserved for {l.get('mac')}"
    return None


def merge_known_devices(leases, neighbors, reservations):
    """Merge known-device sources into one inventory, deduped by MAC.

    leases: [{mac, ip, hostname}] (active /tmp/dhcp.leases); neighbors:
    [{ip, iface, mac}] (ARP table); reservations: [{name, mac, ip}] (existing
    static leases). Output: [{name, mac, current_ip, source(s), reserved,
    reserved_ip}] — name prefers reservation > hostname; 'reserved' marks MACs
    with an existing pin (reserved_ip is where it's pinned). Sorted by name.
    Pure (no I/O)."""
    by_mac = {}
    def _entry(mac):
        mac = parse_mac(mac)
        if not mac:
            return None
        return by_mac.setdefault(mac, {"name": None, "mac": mac, "current_ip": None,
                                       "sources": set(), "reserved": False, "reserved_ip": None})
    for l in (reservations or []):
        e = _entry((l or {}).get("mac"))
        if not e:
            continue
        e["name"] = (l or {}).get("name") or e["name"]
        e["reserved"] = True
        e["reserved_ip"] = (l or {}).get("ip")
    for l in (leases or []):
        e = _entry((l or {}).get("mac"))
        if not e:
            continue
        e["name"] = e["name"] or (l or {}).get("hostname")
        e["current_ip"] = (l or {}).get("ip") or e["current_ip"]
        e["sources"].add("lease")
    for n in (neighbors or []):
        e = _entry((n or {}).get("mac"))
        if not e:
            continue
        e["current_ip"] = e["current_ip"] or (n or {}).get("ip")
        e["sources"].add("arp")
    out = []
    for e in by_mac.values():
        if not (e["name"] or e["current_ip"]):
            continue  # MAC with no identity and no IP — not actionable
        e["sources"] = sorted(e["sources"])
        out.append(e)
    out.sort(key=lambda x: (x["name"] or "~").lower(), reverse=False)
    return out


def vlan_members(vlan_id):
    """Which devices carry a VLAN and in what role: [{device_id,name,role}]."""
    rows = owctl.q("SELECT d.id, d.name, m.role FROM vlans_devices m JOIN devices d ON d.id=m.device_id "
             "WHERE m.vlan_id=? ORDER BY m.role DESC, d.id", (str(vlan_id),))
    return [{"device_id": r["id"], "name": r["name"], "role": r["role"]} for r in rows]


def do_mesh(dev, cfg, apply: bool = True):
    """Configure 802.11s mesh on a device.

    cfg: {enabled, mesh_vap, mesh_id, mesh_ctrl, mesh_gw_mode,
          mesh_gw_bcast, mesh_htmode, mesh_channel, mesh_encryption, mesh_key}.

    Applies idempotently via a named `mesh` uci section on the mesh radio, then
    `uci commit wireless && wifi reload`. Requires the meshd package; installs
    it when missing (SSH only).
    """
    if dev["access"] != "ssh":
        raise HTTPException(400, "mesh config requires SSH access on this device")
    sec = "mesh"
    lines = [f"uci set wireless.{sec}=wifi-iface"]
    if not cfg.get("enabled"):
        lines.append(f"uci set wireless.{sec}.enabled=0")
        lines.append("uci commit wireless")
        owctl._run_ssh(dev, "\n".join(lines) + "\n", "mesh", "disabled", "mesh disabled")
        owctl.set_pending(dev, "wireless", apply)
        return {"device": dev["name"], "ok": True, "enabled": False}
    radio = (cfg.get("mesh_vap") or "radio0").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", radio):
        raise HTTPException(400, f"invalid mesh radio {radio!r}")
    lines.append(f"uci set wireless.{sec}.device={owctl._uci_quote(radio)}")
    lines.append(f"uci set wireless.{sec}.network={owctl._uci_quote(cfg.get('mesh_network') or 'lan')}")
    lines.append("uci set wireless.{sec}.mode=mesh".replace("{sec}", sec))
    lines.append(f"uci set wireless.{sec}.mesh={owctl._uci_quote(cfg.get('mesh_id') or 'mesh')}")
    for opt, key in (("mesh_ctrl", "mesh_ctrl"), ("mesh_gw_mode", "mesh_gw_mode"),
                     ("mesh_gw_bcast", "mesh_gw_bcast")):
        if cfg.get(key):
            lines.append(f"uci set wireless.{sec}.{key}={owctl._uci_quote(str(cfg[key]))}")
    ht = cfg.get("mesh_htmode")
    if ht:
        lines.append(f"uci set wireless.{sec}.htmode={owctl._uci_quote(str(ht))}")
    chan = cfg.get("mesh_channel")
    if chan:
        lines.append(f"uci set wireless.{sec}.channel={owctl._uci_quote(str(chan))}")
    enc = cfg.get("mesh_encryption") or "none"
    lines.append(f"uci set wireless.{sec}.encryption={owctl._uci_quote(enc)}")
    if enc != "none" and cfg.get("mesh_key"):
        lines.append(f"uci set wireless.{sec}.key={owctl._uci_quote(str(cfg['mesh_key']))}")
    lines.append("uci commit wireless")
    if apply:
        lines.append("wifi reload")
    pre = "opkg install -y meshd || true\n" if cfg.get("install_if_missing") else ""
    owctl._run_ssh(dev, pre + "\n".join(lines) + "\n", "mesh",
             f"radio={radio} mesh={cfg.get('mesh_id')} enc={enc}", "mesh apply")
    owctl.set_pending(dev, "wireless", apply)
    return {"device": dev["name"], "ok": True, "enabled": True, "backend": "meshd"}


def do_guest_wifi(dev, ssid, password, vlan_id=None, apply: bool = True):
    """Create a guest WiFi interface on a device. Requires wireless-capable device.
    apply=False commits the wireless config without bringing up the radio (LuCI 'Save')."""
    if dev["access"] != "ssh":
        raise HTTPException(400, "guest WiFi requires SSH access")
    c = owctl._ssh_connect(dev)
    try:
        # Check if device has wireless
        stdin, stdout, stderr = c.exec_command("uci show wireless 2>/dev/null | head -10", timeout=10)
        out = stdout.read().decode()
        if "wifi-iface" not in out and "wifi-device" not in out:
            raise HTTPException(400, f"{dev['name']} has no wireless interface")
        # Generate UCI config for guest WiFi. Reuse the shared helpers so the
        # SSID/password/section name are shell-safe: a quote or backtick in the
        # SSID or password can no longer break out of the `uci set` line.
        iface_name = "guest_" + owctl._uci_slug(ssid) if ssid else "guest_guest"
        sq = owctl._uci_quote
        vlan_net = f"vlan_{re.sub(r'[^0-9]', '', str(vlan_id))}" if vlan_id else None
        cmd = f"""uci set wireless.{iface_name}=wifi-iface
uci set wireless.{iface_name}.device={sq('radio0')}
uci set wireless.{iface_name}.network={sq('lan')}"""
        if vlan_net:
            cmd += f"\nuci set wireless.{iface_name}.network={sq(vlan_net)}"
        cmd += f"""
uci set wireless.{iface_name}.mode={sq('ap')}
uci set wireless.{iface_name}.ssid={sq(ssid)}
uci set wireless.{iface_name}.encryption={sq('psk2')}
uci set wireless.{iface_name}.key={sq(password)}
uci commit wireless
uci commit firewall"""
        stdin, stdout, stderr = c.exec_command(cmd, timeout=30)
        out = stdout.read().decode()
        err = stderr.read().decode()
        status = stdout.channel.recv_exit_status()
        if status != 0:
            raise RuntimeError(f"guest WiFi config failed: {(err or out)[:200]}")
        if apply:
            # Try to bring up wireless (may fail if radio not available)
            c.exec_command("wifi up 2>/dev/null || true")
        owctl.set_pending(dev, "wireless", apply)
        owctl.log_action(dev, 'guest_wifi', f'ssid={ssid}', ok=True)
        return {"ssid": ssid, "ok": True, "output": out[:300]}
    finally:
        c.close()


def do_upgrade(dev, packages):
    if dev["access"] != "ssh":
        raise HTTPException(400, "package upgrades require SSH access on this device")
    c = owctl._ssh_connect(dev)
    try:
        if not packages:
            cmd = "opkg update && opkg upgrade -y"
        else:
            safe = [p for p in packages if re.fullmatch(r"[A-Za-z0-9_.+-]+", p)]
            if len(safe) != len(packages):
                raise HTTPException(400, "invalid package name in list")
            cmd = "opkg update && opkg upgrade -y " + " ".join(safe)
        out, err, status = owctl._exec_capture(c, cmd, timeout=3600)
        result = (out.strip() + "\n--- stderr ---\n" + err.strip()).strip()
        if status != 0:
            raise RuntimeError(f"upgrade exited with status {status}")
    finally:
        c.close()
    owctl.log_action(dev, 'upgrade', f'packages={", ".join(packages) if packages else "all"}', ok=True)
    return result[:30000]


def do_reboot(dev):
    if dev["access"] != "ssh":
        raise HTTPException(400, "reboot requires SSH access on this device")
    c = owctl._ssh_connect(dev)
    try:
        c.exec_command("reboot")
    finally:
        c.close()
    owctl.log_action(dev, 'reboot', 'reboot sent', ok=True)
    return "reboot sent"


def check_device(dev):
    st = owctl.gather(dev)
    owctl.record_heartbeat(dev, True)
    owctl.execute("UPDATE devices SET status='online', last_checked=? WHERE id=?", (owctl.now(), dev["id"]))
    findings = owctl.apply_findings(dev, st)
    # Check for config changes
    changed = owctl.check_config_changes(dev, st)
    if changed:
        findings.append({"rule_id": "config_changed", "severity": "INFO",
                         "message": f"{len(changed)} config file(s) changed",
                         "detail": ", ".join(changed[:5]), "rec": "Review config if unexpected"})
    # Store config hashes — ONE row per snapshot, all paths as a single blob
    # (newline-separated "path=hash" lines). The table's UNIQUE(device_id, ts)
    # forbids two rows at the same ts, so a one-row-per-path write (the old
    # approach) silently dropped every path after the first. A single blob row
    # keeps the constraint intact and the baseline unambiguous: the latest
    # snapshot is exactly `MAX(ts)`.
    if st.get("config_hashes"):
        snap_ts = owctl.now()
        owctl.execute("DELETE FROM config_hashes WHERE device_id=? AND ts<?",
                (dev["id"], snap_ts))  # keep only latest
        blob = "\n".join(f"{p}={h}" for p, h in st["config_hashes"].items())
        owctl.execute("INSERT OR REPLACE INTO config_hashes(device_id, ts, hash) VALUES(?,?,?)",
                (dev["id"], snap_ts, blob))
    # Store config history for diff view
    owctl.execute("INSERT INTO config_history(device_id, ts, hash) VALUES(?,?,?)",
            (dev["id"], owctl.now(), ";".join(f"{p}={h}" for p,h in st.get("config_hashes",{}).items())))
    # Calculate and store health score
    score = owctl.calc_health_score(findings)
    owctl.execute("UPDATE devices SET health_score=? WHERE id=?", (score, dev["id"]))
    # Store traffic samples (keep last 48 per interface for trend chart)
    if st.get("traffic"):
        for iface, counters in st["traffic"].items():
            owctl.execute("INSERT INTO traffic_samples(device_id, ts, iface, rx_bytes, tx_bytes) VALUES(?,?,?,?,?)",
                    (dev["id"], owctl.now(), iface, counters["rx"], counters["tx"]))
        # prune old samples: keep only last 48 PER INTERFACE (the comment above
        # always said so; the old query's bare `LIMIT 48` scoped only by device,
        # so one busy interface evicted every other's samples from the trend
        # chart). PARTITION BY (device_id, iface) keeps each interface's own 48.
        owctl.execute("""DELETE FROM traffic_samples WHERE id NOT IN (
            SELECT id FROM (
                SELECT id,
                       ROW_NUMBER() OVER (PARTITION BY device_id, iface ORDER BY ts DESC) AS rn
                FROM traffic_samples
                WHERE device_id=?
            ) WHERE rn <= 48
        ) AND device_id=?""", (dev["id"], dev["id"]))
    # Store recent syslog entries (keep last 100 per device)
    if st.get("syslog"):
        owctl.execute("DELETE FROM log_entries WHERE device_id=? AND ts<?",
                (dev["id"], owctl.now()))  # keep only latest
        for msg in st["syslog"][-100:]:
            owctl.execute("INSERT OR IGNORE INTO log_entries(device_id, ts, message) VALUES(?,?,?)",
                    (dev["id"], msg["ts"], msg["message"]))
    # Persist a device_status snapshot (clients/uptime/firmware/traffic) for
    # the network overview. Never raises — a failed snapshot must not break a check.
    owctl.record_status_snapshot(dev, st)
    return {"status": st, "findings": findings, "health_score": score}
