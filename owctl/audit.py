"""owctl.audit"""
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

def audit_status(st):
    f = []

    def add(rule, sev, msg, detail="", rec=""):
        f.append({"rule_id": rule, "severity": sev, "message": msg, "detail": detail, "rec": rec})

    if st.get("telnet_on"):
        add("telnet", "HIGH", "Telnet (port 23) is listening",
            "Cleartext service exposed", "Disable telnet; use SSH with key auth")
    if str(st.get("dropbear_pwauth", "")).lower() in ("yes", "true", "on", "1"):
        add("ssh_password_auth", "MEDIUM", "SSH allows password authentication",
            "dropbear PasswordAuth=" + str(st.get("dropbear_pwauth", "")),
            "Set PasswordAuth='no' and use SSH keys")
    if st.get("fw_in") == "ACCEPT":
        add("fw_input_accept", "HIGH", "Firewall default INPUT policy is ACCEPT",
            "All inbound traffic to the router is allowed by default",
            "Set firewall defaults input=DROP (standard OpenWrt default)")
    if st.get("fw_fwd") == "ACCEPT":
        add("fw_forward_accept", "HIGH", "Firewall default FORWARD policy is ACCEPT",
            "All inter-zone forwarding allowed by default",
            "Set forward=DROP and allow only intended traffic")
    # QoS not shaping on the WAN — latency-sensitive traffic (VoIP, video, gaming)
    # will suffer under bursts. INFO: many people intentionally leave this off.
    # st["qos"] is the parse_sqm() result (dict) or None; absent on LuCI-only boxes.
    qos = st.get("qos")
    if isinstance(qos, dict) and qos.get("enabled") is False and st.get("wan_up") is not False:
        add("qos_disabled", "INFO", "QoS (SQM) is not enabled",
            "No traffic shaping — bursty flows can starve latency-sensitive traffic",
            "Enable SQM in the QoS tab (fq_codel recommended) if you have latency-sensitive traffic")
    if str(st.get("ntp") or "").lower() in ("false", "0", "disabled"):
        add("ntp_disabled", "LOW", "NTP time sync is disabled",
            "", "Enable system.ntp so logs and certs stay correct")
    if st.get("upgradable"):
        pkgs = ", ".join(p.get("pkg", "?") for p in st["upgradable"][:8])
        add("outdated_packages", "MEDIUM", f"{len(st['upgradable'])} package(s) have updates",
            pkgs, "Review in the Updates tab and apply")
    # Obsolete packages: installed but no longer in any feed. They are dead
    # weight (security patches stop landing) and a sign to remove them.
    obsolete = st.get("obsolete") or []
    if obsolete:
        add("obsolete_packages", "MEDIUM",
            f"{len(obsolete)} installed package(s) are no longer in any feed",
            ", ".join(obsolete[:8]),
            "opkg remove <pkg> to drop them; re-add from a feed if still needed")

    # Mesh daemon: 802.11s / batman-adv. INFO only — mesh is a deliberate
    # topology choice, not a threat, but worth surfacing in the WiFi tab.
    if st.get("meshd"):
        add("mesh_enabled", "INFO", "Mesh (802.11s / batman-adv) is configured",
            st["meshd"], "Confirm the mesh topology is intentional")

    if st.get("sysupgrade_available"):
        add("fw_update", "MEDIUM", "Firmware (sysupgrade) update available",
            st.get("latest", ""), "Back up config, then upgrade")
    if st.get("wan_up") is False:
        add("wan_down", "INFO", "WAN interface reports down",
            st.get("wan_ip", ""), "Check upstream link if unexpected")
    if st.get("redirects"):
        rs = ", ".join(f"{r['name']}->{r['dest_port']}" for r in st["redirects"][:8])
        add("wan_forwards", "INFO", f"{len(st['redirects'])} WAN port forward(s)",
            rs, "Confirm each forward is intended")

    # disk_usage
    if st.get("disk_used_pct") is not None:
        if st["disk_used_pct"] >= 90:
            add("disk_full", "HIGH", f"Overlay disk {st['disk_used_pct']}% used",
                detail=st.get("disk", ""), rec="Free space or move logs; a full overlay bricks config writes")
        elif st["disk_used_pct"] >= 80:
            add("disk_full", "MEDIUM", f"Overlay disk {st['disk_used_pct']}% used",
                detail=st.get("disk", ""), rec="Free space or move logs; a full overlay bricks config writes")

    # thermal
    if st.get("cpu_temp_c") is not None:
        if st["cpu_temp_c"] >= 85:
            add("cpu_hot", "MEDIUM", f"CPU at {st['cpu_temp_c']}°C", detail=str(st['cpu_temp_c']))
        elif st["cpu_temp_c"] >= 75:
            add("cpu_hot", "LOW", f"CPU at {st['cpu_temp_c']}°C", detail=str(st['cpu_temp_c']))

    # wifi security
    wifi = st.get("wifi", [])
    if wifi:
        open_aps = [a for a in wifi if a.get("encryption") in ("open", "", "none")]
        if open_aps:
            sev = "CRITICAL"
            if any(a.get("encryption") == "none" for a in open_aps) and not any(a.get("encryption") in ("open", "") for a in open_aps):
                sev = "HIGH"
            add("wifi_open", sev, f"{len(open_aps)} open WiFi network(s) detected",
                detail=", ".join(a.get("essid", "?") for a in open_aps),
                rec="Open networks are trivially sniffed; disable or use a VLAN. Disable the AP or require WPA2")

        wpa2_psk_aps = [a for a in wifi if 'psk' in str(a.get("encryption", "")).lower()
                        and 'psk2' not in str(a.get("encryption", "")).lower()
                        and 'psk3' not in str(a.get("encryption", "")).lower()]
        if wpa2_psk_aps:
            add("wpa2_psk", "LOW", f"{len(wpa2_psk_aps)} AP(s) use WPA2-PSK (no 802.1X)",
                detail=", ".join(a.get("essid", "?") for a in wpa2_psk_aps),
                rec="Prefer WPA2/WPA3 (sae) or mixed sae+psk2")

    if st.get("device_date"):
        try:
            dev_t = datetime.strptime(st["device_date"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            drift = abs((datetime.now(timezone.utc) - dev_t).total_seconds())
            if drift > 600:
                add("clock_drift", "LOW", f"Device clock off by ~{int(drift // 60)} min",
                    st["device_date"], "Enable NTP")
        except Exception:
            pass
    # ---- Routing (no-ops when `routing`/`bgp_present` are absent, i.e. LuCI) ----
    # BGP daemon installed — deliberate topology, surface it like mesh.
    if (st.get("bgp_present") or "").strip():
        add("bgp_enabled", "INFO", "A BGP daemon (bird) is installed/configured",
            "BGP can override your static routes", "Confirm the BGP peers/AS are intentional")
    routing_text = (st.get("routing") or "").strip()
    if routing_text:
        try:
            routes = owctl.parse_ip_route(routing_text)
            defaults = [r for r in routes if (r.get("dst") or "").strip() in ("default", "0.0.0.0/0")]
            if not defaults:
                add("no_default_route", "MEDIUM", "No default route in the kernel routing table",
                    "Default-gateway traffic (e.g. internet) will not be forwarded",
                    "Set a default route or a route via the WAN gateway")
            elif len(defaults) > 1:
                gws = ", ".join(d.get("gateway") or "?" for d in defaults[:5])
                add("multiple_default_routes", "MEDIUM",
                    f"{len(defaults)} default routes present (conflicting gateways)",
                    gws, "Keep a single default route; use policy routing for per-source defaults")
        except Exception:
            pass
    return f


def check_config_changes(dev, st):
    """Detect config file changes since last check.

    The baseline is the FULL latest snapshot: one row per config path, all
    sharing the snapshot's ts. The old code used `ORDER BY ts DESC LIMIT 1`,
    which returned a SINGLE path's row (one of N), so only that one path was
    ever baselined and changes to every other config file went undetected.
    """
    changed = []
    current_hashes = st.get("config_hashes", {})
    if not current_hashes:
        return changed
    prev = owctl.q("SELECT hash FROM config_hashes WHERE device_id=? AND ts=(SELECT MAX(ts) FROM config_hashes WHERE device_id=?)",
             (dev["id"], dev["id"]))
    if not prev:
        return changed  # first check, no baseline
    prev_map = {}
    for row in prev:
        # each row is "path=hash"; be tolerant of a multi-line blob too
        for line in (row["hash"] or "").splitlines():
            if "=" in line:
                path, hash_val = line.split("=", 1)
                prev_map[path] = hash_val
    for path, curr_h in current_hashes.items():
        prev_h = prev_map.get(path)
        if prev_h and prev_h != curr_h:
            changed.append(path)
    return changed


def calc_health_score(findings):
    """Calculate 0-100 health score based on findings severity."""
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 1}
    score = 100
    for f in findings:
        score -= weights.get(f["severity"], 0)
    return max(0, score)


_UCI_LINE_RE = re.compile(r"^([A-Za-z0-9_\-]+)\.(@?[A-Za-z0-9_]+)(?:\.([A-Za-z0-9_]+))?=(.*)$")


def _uci_unquote(val: str) -> str:
    """Strip uci show quoting: single quotes (with escapes) or surrounding double quotes."""
    if len(val) >= 2:
        if val[0] == "'" and val[-1] == "'":
            return val[1:-1].replace("\\'", "'").replace("\\\\", "\\")
        if val[0] == '"' and val[-1] == '"':
            return val[1:-1]
    return val


def parse_openwrt_release(text: str) -> dict:
    """Parse /etc/openwrt_release content (DISTRIB_* lines OR single description line).

    Returns a dict with keys: description, version, arch, target, revision.
    Each value is a string or None when absent. The 'description' key holds
    DISTRIB_DESCRIPTION when present; otherwise the entire trimmed text (single-line
    fallback). When text is empty/blank, all values are None except description=''.
    """
    # Default all-None dict
    result = {
        "description": None,
        "version": None,
        "arch": None,
        "target": None,
        "revision": None,
    }
    if not text or not text.strip():
        result["description"] = ""
        return result

    # Try to parse DISTRIB_* lines. OpenWrt emits these either one per line
    # (classic) or space-separated across one/few lines (e.g. 192.168.30.1);
    # finditer + quote-alternation handles both, quoted or unquoted values.
    distrib = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        for m in re.finditer(r"DISTRIB_(\w+)=(?:'([^']*)'|\"([^\"]*)\"|(\S+))", line):
            key = m.group(1).lower()
            val = m.group(2) or m.group(3) or m.group(4) or ""
            distrib[key] = val

    if distrib:
        # DISTRIB_* format found
        result["description"] = distrib.get("description", "")
        result["version"] = distrib.get("version")
        result["arch"] = distrib.get("arch")
        result["target"] = distrib.get("target")
        result["revision"] = distrib.get("revision")
    else:
        # Single-line fallback: the whole text is the description
        result["description"] = text.strip()

    # Fallback extraction from description when DISTRIB fields missing
    desc = result["description"] or ""
    if not result["version"]:
        m = re.search(r"(\d+\.\d+(?:\.\d+)*)", desc)
        if m:
            result["version"] = m.group(1)
    if not result["revision"]:
        m = re.search(r"\br\d+-[0-9a-f]+", desc)
        if m:
            result["revision"] = m.group(0)

    return result


def parse_uci_show(raw: str) -> dict:
    """Parse `uci show <pkg>` output into {package: {section: {opt: value, 'type': ...}}}.

    Section-declaration lines (`pkg.section=<type>`) store the type under 'type'.
    Handles both quoted and bare value forms, and skips stderr noise lines
    (e.g. 'uci: Package sqm is not defined')."""
    result: dict = {}
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        m = _UCI_LINE_RE.match(line)
        if not m:
            continue  # stderr noise, blank, or unexpected shape
        pkg, section, opt, val = m.groups()
        section_dict = result.setdefault(pkg, {}).setdefault(section, {})
        if opt is None:
            section_dict["type"] = _uci_unquote(val)
        else:
            section_dict[opt] = _uci_unquote(val)
    return result


def parse_sqm(raw: str):
    """Parse `uci show sqm` or `uci show nft-qos` output.

    Returns {backend, enabled, interface, download_kbps, upload_kbps, qdisc, ecn}
    or None when no QoS config is present (empty output / package missing / stderr noise).
    With multiple SQM queue sections, the enabled one wins (first enabled, else first).
    """
    parsed = parse_uci_show(raw)
    # luci-app-sqm
    if "sqm" in parsed:
        sections = [s for s in parsed["sqm"].values()
                    if isinstance(s, dict) and any(k != "type" for k in s)]
        if not sections:
            return None
        enabled = [s for s in sections if s.get("enabled") == "1" or s.get("enabled") is True]
        sec = enabled[0] if enabled else sections[0]
        qdisc = None
        for name in ("fq_codel", "cake", "hfsc", "hfs", "layer_cake"):
            if str(sec.get(name, "0")) in ("1", "true"):
                qdisc = name
                break
        try:
            dl = int(sec.get("download", "0"))
        except (TypeError, ValueError):
            dl = 0
        try:
            ul = int(sec.get("upload", "0"))
        except (TypeError, ValueError):
            ul = 0
        return {
            "backend": "sqm",
            "enabled": str(sec.get("enabled", "0")) in ("1", "true"),
            "interface": sec.get("interface"),
            "download_kbps": dl,
            "upload_kbps": ul,
            "qdisc": qdisc,
            "ecn": str(sec.get("ecn", "0")) in ("1", "true"),
        }
    # nft-qos: speeds live in the 'defaults' section
    if "nft-qos" in parsed:
        d = parsed["nft-qos"].get("defaults")
        if not isinstance(d, dict):
            return None
        ifaces = d.get("interfaces", "")
        first_iface = ifaces.split()[0] if ifaces else None

        def _k(name):
            try:
                return int(d.get(name, "0"))
            except (TypeError, ValueError):
                return 0

        return {
            "backend": "nft-qos",
            "enabled": True,
            "interface": first_iface,
            "download_kbps": _k("download"),
            "upload_kbps": _k("upload"),
            "qdisc": None,
            "ecn": None,
        }
    return None


def parse_firewall(raw: str) -> dict:
    """Parse `uci show firewall` output (fw4 / firewall4 layout).

    Returns {"zones": [...], "redirects": [...], "rules": [...], "defaults": {...}}.
    Sections are grouped by their declared type: zone → zones, redirect → redirects,
    rule → rules; the 'defaults' section is kept as a flat dict. Unknown section
    types are dropped. Empty/noise input yields all-empty lists + empty defaults."""
    parsed = parse_uci_show(raw)
    cfg = parsed.get("firewall") or {}
    out = {"zones": [], "redirects": [], "rules": [], "defaults": {}}
    for section, body in cfg.items():
        if not isinstance(body, dict):
            continue
        kind = body.get("type")
        if section == "defaults" or kind == "defaults":
            out["defaults"] = {k: v for k, v in body.items() if k != "type"}
        elif kind == "zone":
            z = {"name": body.get("name"), "network": body.get("network"),
                 "input": body.get("input"), "output": body.get("output"),
                 "forward": body.get("forward")}
            out["zones"].append(z)
        elif kind == "redirect":
            r = {"name": body.get("name"), "src": body.get("src"),
                 "proto": body.get("proto"), "src_dport": body.get("src_dport"),
                 "dest_ip": body.get("dest_ip"), "dest_port": body.get("dest_port")}
            out["redirects"].append(r)
        elif kind == "rule":
            r = {"name": body.get("name"), "src": body.get("src"), "dest": body.get("dest"),
                 "target": body.get("target"), "proto": body.get("proto")}
            for extra in ("limit", "limit_refresh"):
                if extra in body:
                    r[extra] = body[extra]
            out["rules"].append(r)
    return out


def firewall_zone_names(fw: dict):
    """Names of all zones in a parsed firewall config (skips unnamed)."""
    return [z["name"] for z in fw.get("zones", []) if z.get("name")]


def firewall_find_redirect(fw: dict, name: str):
    """Return the redirect (port forward) section whose name matches, else None."""
    for r in fw.get("redirects", []):
        if r.get("name") == name:
            return r
    return None


def firewall_find_rule(fw: dict, name: str):
    """Return the inter-zone rule whose name matches, else None."""
    for r in fw.get("rules", []):
        if r.get("name") == name:
            return r
    return None


_UCI_SLUG_RE = re.compile(r"[^A-Za-z0-9_]+")


def _uci_slug(name: str) -> str:
    """Sanitize a friendly name into a valid uci section id (lowercase, alnum+underscore)."""
    s = _UCI_SLUG_RE.sub("_", (name or "").strip()).strip("_").lower()
    if not s:
        raise HTTPException(400, "empty rule name")
    return s


def _uci_quote(v) -> str:
    """Quote a uci value for a shell-safe `uci set` line."""
    return "'" + str(v).replace("'", "'\\''") + "'"


_ENC_PREFIX = "enc.v1."


def _load_cred_key() -> bytes:
    """32-byte key for device-credential encryption (AES-256)."""
    env = (os.environ.get("OWCTL_CRED_KEY") or "").strip()
    if env:
        return base64.b64decode(env)
    try:
        key = (owctl.get_setting("cred_key", "") or "").strip()
        if key:
            return base64.b64decode(key)
        k = secrets.token_bytes(32)
        owctl.set_setting("cred_key", base64.b64encode(k).decode())
        return k
    except Exception:
        if owctl._FALLBACK_CRED_KEY is None:
            owctl._FALLBACK_CRED_KEY = secrets.token_bytes(32)
        return owctl._FALLBACK_CRED_KEY


def _store_device_cred(value: str) -> str:
    """Encrypt a credential for storage; returns the plaintext unchanged when
    encryption is unavailable so the app keeps working without `cryptography`.
    Idempotent: an already-encrypted value passes through untouched."""
    if not value:
        return value
    if isinstance(value, str) and value.startswith(_ENC_PREFIX):
        return value
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = _load_cred_key()
        if not key:
            return value
        nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, str(value).encode(), None)
        return _ENC_PREFIX + base64.b64encode(nonce + ct).decode()
    except Exception:
        return value


def _stored_device_cred(value) -> str:
    """Decrypt a stored credential; legacy plaintext passes through untouched."""
    if not value or not isinstance(value, str) or not value.startswith(_ENC_PREFIX):
        return value or ""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        raw = base64.b64decode(value[len(_ENC_PREFIX):])
        nonce, ct = raw[:12], raw[12:]
        return AESGCM(_load_cred_key()).decrypt(nonce, ct, None).decode()
    except Exception:
        return ""  # undecryptable (e.g. key rotated) — treat as empty, never crash


def _uci_values(rest: str) -> list:
    """Split a `uci show` value string into a list of values.

    Handles single-quoted values (which may contain spaces/commas, e.g. list
    options like ``dhcp_option='a' 'b'``) and bare unquoted values — uci show
    prints values unquoted unless they need quoting (``enabled=1``,
    ``dhcpv4=server``, ``leasetime=12h``, ``server=8.8.8.8``)."""
    rest = (rest or "").strip()
    if not rest:
        return []
    vals, i, n = [], 0, len(rest)
    while i < n:
        while i < n and rest[i].isspace():
            i += 1
        if i >= n:
            break
        if rest[i] == "'":
            j = rest.find("'", i + 1)
            if j == -1:
                vals.append(rest[i + 1:])
                break
            vals.append(rest[i + 1:j])
            i = j + 1
        else:
            j = i
            while j < n and not rest[j].isspace():
                j += 1
            vals.append(rest[i:j])
            i = j
    return vals


def _uci_list_values(raw: str, section: str, key: str) -> list:
    """Collect every value of ``section.key`` from raw ``uci show`` text.

    The value may be a single value or a list rendered on one line."""
    vals = []
    prefix = f"{section}.{key}="
    for line in (raw or "").splitlines():
        line = line.strip()
        if line.startswith(prefix):
            vals.extend(_uci_values(line[len(prefix):]))
    return vals


def build_wifi_clone_cmds(iface: dict, radio: str) -> tuple:
    """Uci script (no commit) to create/update one wifi-iface on a target radio.
    Pure (no I/O). The caller adds ``uci commit wireless`` + ``wifi reload``
    once per target. All values go through :func:`_uci_quote`; the section name
    is derived from a sanitized SSID so it is always a valid uci id."""
    ssid = str(iface.get("ssid") or "")
    slug = "clone_" + re.sub(r"\W+", "_", ssid or "iface")[:24].strip("_") or "iface"
    key = str(iface.get("key") or "")
    enc = str(iface.get("encryption") or "")
    net = str(iface.get("network") or "")
    lines = [
        f"uci set wireless.{slug}=wifi-iface",
        f"uci set wireless.{slug}.device={_uci_quote(radio)}",
        f"uci set wireless.{slug}.mode={_uci_quote('ap')}",
        f"uci set wireless.{slug}.ssid={_uci_quote(ssid)}",
    ]
    if key:
        lines.append(f"uci set wireless.{slug}.key={_uci_quote(key)}")
    if enc:
        lines.append(f"uci set wireless.{slug}.encryption={_uci_quote(enc)}")
    if net:
        lines.append(f"uci set wireless.{slug}.network={_uci_quote(net)}")
    return slug, "\n".join(lines) + "\n"


def _parse_subnet(subnet: str):
    """Parse ``a.b.c.d/prefix`` (or a bare network) into ``(ipaddr, netmask)``
    for the ``network`` package: the interface's L3 address is the first usable
    host (``network + 1``, e.g. ``192.168.10.1`` for ``192.168.10.0/24``) and
    ``netmask`` is the dotted full mask. Returns ``(ipaddr, netmask)`` or
    ``None`` when the subnet is empty/invalid. Pure (no I/O)."""
    subnet = (subnet or "").strip()
    if not subnet:
        return None
    if "/" in subnet:
        base, _, pref = subnet.partition("/")
    else:
        base, pref = subnet, "24"
    try:
        net = ipaddress.ip_network(f"{base.strip()}/{pref.strip()}", strict=False)
    except ValueError:
        return None
    if net.prefixlen >= 31:  # no usable host on /31, /32
        return None
    return (str(net.network_address + 1), str(net.netmask))


def build_dhcp_cmds(iface: str, cfg: dict, apply: bool = True) -> str:
    """Uci script (pure, no I/O) to create/update the FULL DHCP pool section on
    ``dhcp.<iface>``, covering the whole per-VLAN surface:

    * pool: ``start`` / ``limit`` / ``leasetime`` and ``dhcpv4`` mode (server|relay|none)
    * network overrides: ``netmask``, ``broadcast``, ``local``
    * behavior flags: ``no_resolve``, ``notransfer``, ``no_default`` (set=1 or removed)
    * DHCP options: ``options`` — raw dnsmasq/odhcpd option strings, e.g.
      ``'dhcp-option=6,1.1.1.1'``, ``'domain=home.lan'``, ``'ignore=6'``
    * static leases: ``static_leases`` — list of ``{name, mac, ip}``
    * IPv6 (odhcpd): ``ipv6`` dict — ``dhcpv6``, ``ra``, ``ra_management``,
      ``ra_service``, ``ra_default_lifetime``, ``ra_lifetime``

    List options (``dhcp_option``, ``dhcp_host``/``host``) are REPLACED
    wholesale: the existing list is deleted, then the new values added — so
    removing an option or lease is simply omitting it. Scalar overrides are
    written only when provided; boolean flags are set=1 or deleted, so toggling
    off actually clears them. Static leases are mirrored under both the dnsmasq
    (``dhcp_host``) and odhcpd (``host``) option names so whichever daemon is
    present picks them up; the IPv6 keys are odhcpd-specific and harmless on a
    dnsmasq-only box.

    All values go through :func:`_uci_quote` (shell-safe single-quoting) and the
    section name is validated, so this is safe to run through the remote shell
    via ``exec_command``. Reloads whichever DHCP daemon is present.

    If ``subnet`` (``a.b.c.d/prefix``) is provided, the interface's L3 address is
    set in the ``network`` package (``network.<iface>.ipaddr``/``netmask``), plus
    ``ifname`` when given — this is how the VLAN subnet is managed here.
    """
    iface = str(iface).strip()
    if not re.match(r"^[A-Za-z0-9_]+$", iface):
        raise HTTPException(400, "invalid interface name")
    cfg = cfg or {}
    s = f"dhcp.{iface}"
    n = f"network.{iface}"

    def _flag(key, on):
        if on:
            return [f"uci set {s}.{key}=1"]
        return [f"uci del {s}.{key} 2>/dev/null || true"]

    def _replace_list(uci_keys, values):
        lines = [f"uci del {s}.{k} 2>/dev/null || true" for k in uci_keys]
        for v in values:
            for k in uci_keys:
                lines.append(f"uci add_list {s}.{k}={_uci_quote(v)}")
        return lines

    lines = []
    # subnet / L3 address (network package) — managed alongside the DHCP section
    subnet = (cfg.get("subnet") or "").strip()
    _sub = _parse_subnet(subnet) if subnet else None
    if _sub:
        ipaddr, mask_full = _sub
        lines.append(f"uci set {n}=interface")
        lines.append(f"uci set {n}.proto={_uci_quote('static')}")
        lines.append(f"uci set {n}.ipaddr={_uci_quote(ipaddr)}")
        lines.append(f"uci set {n}.netmask={_uci_quote(mask_full)}")
        ifname = (cfg.get("ifname") or "").strip()
        if ifname:
            lines.append(f"uci set {n}.ifname={_uci_quote(ifname)}")
        lines.append("uci commit network")
    lines += [
        f"uci set {s}=dhcp",
        f"uci set {s}.interface={_uci_quote(iface)}",
    ]
    # pool
    if cfg.get("start") not in (None, ""):
        lines.append(f"uci set {s}.start={_uci_quote(cfg['start'])}")
    if cfg.get("limit") not in (None, ""):
        lines.append(f"uci set {s}.limit={_uci_quote(cfg['limit'])}")
    lines.append(f"uci set {s}.leasetime={_uci_quote(cfg.get('lease_time') or '12h')}")
    lines.append(f"uci set {s}.dhcpv4={_uci_quote(cfg.get('dhcpv4') or 'server')}")
    # network overrides
    for key in ("netmask", "broadcast"):
        if cfg.get(key):
            lines.append(f"uci set {s}.{key}={_uci_quote(cfg[key])}")
    # behavior flags (set=1 or remove)
    for key in ("local", "no_resolve", "notransfer", "no_default"):
        lines.extend(_flag(key, bool(cfg.get(key))))
    # DHCP options (list, replaced wholesale)
    opts = [str(o).strip() for o in (cfg.get("options") or []) if str(o).strip()]
    lines.extend(_replace_list(["dhcp_option"], opts))
    # static leases (list; mirror dnsmasq `dhcp_host` + odhcpd `host`)
    leases = []
    for h in (cfg.get("static_leases") or []):
        name = str(h.get("name") or "").strip()
        mac = str(h.get("mac") or "").strip()
        ip = str(h.get("ip") or "").strip()
        if name and mac and ip:
            leases.append(f"{name}, {mac}, {ip}")
    lines.extend(_replace_list(["dhcp_host", "host"], leases))
    # IPv6 (odhcpd)
    ip6 = cfg.get("ipv6") or {}
    if ip6.get("dhcpv6"):
        lines.append(f"uci set {s}.dhcpv6={_uci_quote(ip6['dhcpv6'])}")
    if ip6.get("ra") is not None:
        lines.extend(_flag("ra", bool(ip6.get("ra"))))
    if ip6.get("ra_management"):
        lines.append(f"uci set {s}.ra_management={_uci_quote(ip6['ra_management'])}")
    if ip6.get("ra_service") is not None:
        lines.extend(_flag("ra_service", bool(ip6.get("ra_service"))))
    for key in ("ra_default_lifetime", "ra_lifetime"):
        if ip6.get(key) not in (None, ""):
            lines.append(f"uci set {s}.{key}={_uci_quote(ip6[key])}")
    lines.append("uci commit dhcp")
    if apply:
        lines.append("/etc/init.d/dnsmasq reload 2>/dev/null || /etc/init.d/odhcpd reload 2>/dev/null || true")
    return "\n".join(lines) + "\n"


def build_dhcp_apply_cmds(iface: str, start=100, limit=150, lease_time: str = "12h") -> str:
    """Backward-compatible wrapper: build a standard server-mode pool. New code
    should call :func:`build_dhcp_cmds` with the full per-VLAN config dict."""
    return build_dhcp_cmds(iface, {"start": start, "limit": limit,
                                   "lease_time": lease_time, "dhcpv4": "server"})


def build_dns_cmds(backend: str, detect: str, servers: list, search_domains: list = None,
                  scope: str = "dhcp", apply: bool = True) -> str:
    """Uci script to set DNS for the active DHCP/DNS backend. Pure (no I/O).

    ``scope`` selects where the servers land:

    * ``"dhcp"`` (default) — DNS is delivered to DHCP clients via option 6
      (odhcpd) or the dnsmasq ``server`` list. Same as before this change.
    * ``"router"`` — the box's own resolver: ``system.@dns[0].server`` /
      ``system.@dns[0].search``, which is what ``/etc/resolv.conf`` is built
      from. Does NOT touch the DHCP options, so clients keep their own DNS.
    * ``"both"`` — applies to both places in one script.

    odhcpd: DHCP DNS is delivered via option 6. Replaces the
    ``dhcp-option=6,`` entries and the bare ``dhcp-option=6`` marker, but
    PRESERVES every other ``dhcp_option`` entry (notably IPv6 RA-DNS
    ``6,<addr>``) so existing IPv6 DNS is not silently dropped on re-apply.

    dnsmasq: clears the ``@dnsmasq[0].server`` list by removing each existing
    value individually (``del_list`` requires a value), then adds the new ones.

    An empty ``servers`` list is valid: it clears all upstream servers ("local
    only" / router-resolved). Callers validate the empty case before calling."""
    servers = [str(s).strip() for s in (servers or []) if str(s).strip()]
    search_domains = [str(s).strip() for s in (search_domains or []) if str(s).strip()]
    lines = []

    # Router's own resolver: system.@dns[0] is the source for /etc/resolv.conf.
    # Independent of the DHCP backend — the box needs to resolve regardless.
    if scope in ("router", "both"):
        existing_servers = _uci_list_values(detect, "system.@dns[0]", "server")
        for v in existing_servers:
            lines.append(f"uci -q del_list system.@dns[0].server={_uci_quote(v)} || true")
        for s in servers:
            lines.append(f"uci add_list system.@dns[0].server={_uci_quote(s)}")
        existing_search = _uci_list_values(detect, "system.@dns[0]", "search")
        for v in existing_search:
            lines.append(f"uci -q del_list system.@dns[0].search={_uci_quote(v)} || true")
        for d in search_domains:
            lines.append(f"uci add_list system.@dns[0].search={_uci_quote(d)}")
        lines.append("uci commit system")
        # dnsmasq reads system.@dns, so restart it; odhcpd does not, but the
        # restart is harmless and keeps one code path for both backends.
        if apply:
            lines.append("/etc/init.d/dnsmasq restart 2>/dev/null || /etc/init.d/system restart 2>/dev/null || true")

    if scope == "router":
        return "\n".join(lines) + "\n"

    if backend == "odhcpd":
        # Preserve every dhcp_option entry that is not an IPv4 option-6 DNS
        # entry. Option-6 servers are `dhcp-option=6,<ip>` (or the bare marker
        # `dhcp-option=6`); IPv6 RA-DNS entries look like `6,<addr>` and MUST
        # be kept, or the router stops advertising IPv6 DNS on re-apply.
        keep = [v for v in _uci_list_values(detect, "dhcp.lan", "dhcp_option")
                if not (v == "dhcp-option=6" or v.startswith("dhcp-option=6,"))]
        for v in keep:
            lines.append(f"uci set dhcp.lan.dhcp_option={_uci_quote(v)}")
        for s in servers:
            lines.append(f"uci add_list dhcp.lan.dhcp_option={_uci_quote('dhcp-option=6,' + s)}")
        lines.append("uci commit dhcp")
        if apply:
            lines.append("/etc/init.d/odhcpd restart 2>/dev/null || /etc/init.d/dnsmasq restart 2>/dev/null || true")
        return "\n".join(lines) + "\n"
    # dnsmasq backend: keep the @dnsmasq[0] block in-place.
    existing = _uci_list_values(detect, "dhcp.@dnsmasq[0]", "server")
    for v in existing:
        lines.append(f"uci -q del_list dhcp.@dnsmasq[0].server={_uci_quote(v)} || true")
    for s in servers:
        lines.append(f"uci add_list dhcp.@dnsmasq[0].server={_uci_quote(s)}")
    lines.append("uci commit dhcp")
    if apply:
        lines.append("/etc/init.d/dnsmasq restart 2>/dev/null || true")
    return "\n".join(lines) + "\n"


def _fw_commit(cmd: str, apply: bool = True) -> str:
    """Finish a firewall mutation script. ``apply=True`` (default) also reloads
    fw4 so the change goes live; ``apply=False`` commits to /etc/config only."""
    tail = "uci commit firewall"
    if apply:
        tail += " && fw4 restart"
    return cmd + tail + "\n"


def record_pending_apply(dev, feature):
    """Record that ``feature`` was Saved (committed) but not applied on ``dev``.
    Never raises — a pending-tracking failure must not break the save itself."""
    if feature not in owctl._PENDING_RESTARTS:
        return
    try:
        owctl.execute("INSERT INTO pending_applies(device_id, feature, restart_cmd, saved_at) "
                "VALUES(?,?,?,?) ON CONFLICT(device_id, feature) DO UPDATE SET "
                "restart_cmd=excluded.restart_cmd, saved_at=excluded.saved_at",
                (dev["id"], feature, owctl._PENDING_RESTARTS[feature], owctl.now()))
    except Exception:
        pass


def clear_pending_apply(dev, feature):
    try:
        owctl.execute("DELETE FROM pending_applies WHERE device_id=? AND feature=?",
                (dev["id"], feature))
    except Exception:
        pass


def pending_apply_for(dev):
    rows = owctl.q("SELECT feature, restart_cmd, saved_at FROM pending_applies "
             "WHERE device_id=? ORDER BY feature", (dev["id"],))
    return [{"feature": r["feature"], "saved_at": r["saved_at"]} for r in rows]


def record_vlan_membership(vlan_id, device_id, role):
    """Record that ``device_id`` carries ``vlan_id`` (``role`` = router|switch).
    Never raises — membership bookkeeping must not break the apply it tracks."""
    try:
        owctl.execute("INSERT INTO vlans_devices(vlan_id, device_id, role) VALUES(?,?,?) "
                "ON CONFLICT(vlan_id, device_id) DO UPDATE SET role=excluded.role",
                (str(vlan_id), device_id, role))
    except Exception:
        pass


def set_pending(dev, feature, apply):
    """Reconcile the pending-apply ledger with a just-run save. ``apply=True``
    (Save & Apply) clears the feature; ``apply=False`` (Save) records it as
    awaiting a restart. Both calls swallow their own errors so bookkeeping
    cannot break the config change it is tracking."""
    if apply:
        clear_pending_apply(dev, feature)
    else:
        record_pending_apply(dev, feature)


def apply_pending_for(dev):
    """Restart the union of this device's saved-but-not-applied features, in a
    single SSH session, then clear the pending rows."""
    if dev["access"] != "ssh":
        raise HTTPException(400, "apply requires SSH access on this device")
    rows = owctl.q("SELECT feature, restart_cmd FROM pending_applies WHERE device_id=?",
             (dev["id"],))
    applied = []
    if rows:
        cmds = "\n".join(sorted({r["restart_cmd"] for r in rows}))
        _run_ssh(dev, cmds + "\n", "apply",
                 f"features={','.join(sorted({r['feature'] for r in rows}))}",
                 "apply pending changes")
        applied = sorted({r["feature"] for r in rows})
        for r in rows:
            clear_pending_apply(dev, r["feature"])
    return {"device": dev["name"], "ok": True, "applied": applied}


def _run_ssh(dev, cmd, action, detail, ok_msg):
    """SSH-gated helper: run one command block on the device, log the action."""
    if dev["access"] != "ssh":
        raise HTTPException(400, f"{action} requires SSH access on this device")
    c = owctl._ssh_connect(dev)
    try:
        out, err, status = owctl._exec_capture(c, cmd, timeout=300)
        if status != 0:
            raise RuntimeError(f"{ok_msg} failed on {dev['name']}: exit {status} {(err or out).strip()[:200]}")
    finally:
        c.close()
    owctl.log_action(dev, action, detail, ok=True)
    return {"device": dev["name"], "ok": True}


def ensure_pkg(dev, pkg):
    """Install an opkg package if missing (opkg update + install -y)."""
    if dev["access"] != "ssh":
        raise HTTPException(400, "package install requires SSH access on this device")
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", pkg):
        raise HTTPException(400, f"invalid package name {pkg!r}")
    _run_ssh(dev, f"opkg update && opkg install -y {pkg}", "package",
             f"pkg={pkg}", "package install")
    return "installed"


def do_qos(dev, cfg, install_if_missing=False, apply: bool = True):
    """Apply SQM (luci-app-sqm) settings for the first enabled interface.

    cfg: {enabled, interface, download_kbps, upload_kbps, qdisc, ecn}.
    Idempotent: uses the named 'wan' section; re-apply only overwrites options."""
    if dev["access"] != "ssh":
        raise HTTPException(400, "QoS config requires SSH access on this device")
    iface = (cfg.get("interface") or "wan").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", iface):
        raise HTTPException(400, f"invalid interface name {iface!r}")
    dl, ul = int(cfg.get("download_kbps") or 0), int(cfg.get("upload_kbps") or 0)
    if dl < 0 or ul < 0:
        raise HTTPException(400, "QoS speeds must be >= 0")
    qdisc = cfg.get("qdisc") or "fq_codel"
    if qdisc not in ("fq_codel", "cake", "hfsc", "hfs", "layer_cake"):
        raise HTTPException(400, f"unsupported qdisc {qdisc!r}")
    ecn = "1" if cfg.get("ecn") else "0"
    sec = "wan"
    lines = [
        f"uci set sqm.{sec}=queue",
        f"uci set sqm.{sec}.enabled={'1' if cfg.get('enabled') else '0'}",
        f"uci set sqm.{sec}.interface={_uci_quote(iface)}",
        f"uci set sqm.{sec}.download='{dl}'",
        f"uci set sqm.{sec}.upload='{ul}'",
    ]
    for name in ("fq_codel", "cake", "hfsc", "hfs", "layer_cake"):
        lines.append(f"uci set sqm.{sec}.{name}={'1' if name == qdisc else '0'}")
    lines.append(f"uci set sqm.{sec}.ecn={ecn}")
    lines.append("uci commit sqm")
    if apply:
        lines.append("sqm restart")
    pre = f"opkg install -y luci-app-sqm || true\n" if install_if_missing else ""
    _run_ssh(dev, pre + "\n".join(lines) + "\n", "qos",
             f"iface={iface} dl={dl} ul={ul} qdisc={qdisc} enabled={bool(cfg.get('enabled'))}",
             "QoS apply")
    set_pending(dev, "qos", apply)
    return {"device": dev["name"], "ok": True, "backend": "sqm"}


def do_fw_forward(dev, rule, apply: bool = True):
    """Create or update one port forward (named uci section => idempotent).

    rule: {name, proto: tcp|udp|tcpudp, src_dport, dest_ip, dest_port?}.
    dest_port defaults to src_dport when omitted. apply=False commits without
    reloading fw4 (LuCI 'Save'); apply=True (default) also restarts fw4."""
    name = (rule.get("name") or "").strip()
    slug = _uci_slug(name)
    proto = rule.get("proto") or "tcp"
    if proto == "tcpudp":
        proto = "tcp udp"
    elif proto not in ("tcp", "udp"):
        raise HTTPException(400, f"invalid proto {proto!r} (use tcp, udp or tcpudp)")
    sport = int(rule.get("src_dport") or 0)
    if not (1 <= sport <= 65535):
        raise HTTPException(400, f"invalid source port {sport} (1-65535)")
    dport = int(rule.get("dest_port") or sport)
    if not (1 <= dport <= 65535):
        raise HTTPException(400, f"invalid destination port {dport} (1-65535)")
    dip = (rule.get("dest_ip") or "").strip()
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", dip):
        raise HTTPException(400, f"invalid destination IP {dip!r}")
    lines = [
        f"uci set firewall.{slug}=redirect",
        f"uci set firewall.{slug}.name={_uci_quote(name)}",
        f"uci set firewall.{slug}.src='wan'",
        f"uci set firewall.{slug}.proto={_uci_quote(proto)}",
        f"uci set firewall.{slug}.target='DNAT'",
        f"uci set firewall.{slug}.src_dport='{sport}'",
        f"uci set firewall.{slug}.dest_ip='{dip}'",
        f"uci set firewall.{slug}.dest_port='{dport}'",
    ]
    _run_ssh(dev, _fw_commit("\n".join(lines) + "\n", apply=apply), "firewall",
             f"forward={name} {proto} {sport}->{dip}:{dport}", "port forward apply")
    set_pending(dev, "firewall", apply)
    return {"device": dev["name"], "ok": True, "section": slug}


def do_fw_rule(dev, rule, apply: bool = True):
    """Create or update one inter-zone rule (named uci section => idempotent).

    rule: {name, src (zone name), dest (zone name), target: ACCEPT|REJECT|DROP, proto?}."""
    name = (rule.get("name") or "").strip()
    slug = _uci_slug(name)
    src, dst = (rule.get("src") or "").strip(), (rule.get("dest") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", src) or not re.fullmatch(r"[A-Za-z0-9_\-]+", dst):
        raise HTTPException(400, "rule needs a valid src and dest zone name")
    target = (rule.get("target") or "ACCEPT").upper()
    if target not in ("ACCEPT", "REJECT", "DROP"):
        raise HTTPException(400, f"invalid rule target {target!r}")
    proto = rule.get("proto")
    lines = [
        f"uci set firewall.{slug}=rule",
        f"uci set firewall.{slug}.name={_uci_quote(name)}",
        f"uci set firewall.{slug}.src={_uci_quote(src)}",
        f"uci set firewall.{slug}.dest={_uci_quote(dst)}",
        f"uci set firewall.{slug}.target='{target}'",
    ]
    if proto:
        if proto == "tcpudp":
            proto = "tcp udp"
        elif proto not in ("tcp", "udp"):
            raise HTTPException(400, f"invalid proto {proto!r}")
        lines.append(f"uci set firewall.{slug}.proto={_uci_quote(proto)}")
    _run_ssh(dev, _fw_commit("\n".join(lines) + "\n", apply=apply), "firewall",
             f"rule={name} {src}->{dst} {target}", "firewall rule apply")
    set_pending(dev, "firewall", apply)
    return {"device": dev["name"], "ok": True, "section": slug}


def do_zone_policy(dev, zone, policies, apply: bool = True):
    """Set default input/output/forward policies on a firewall zone.

    zone: zone name (valid uci id, e.g. 'guest'). policies: dict of
    {input?, output?, forward?} each ACCEPT|REJECT|DROP."""
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", zone or ""):
        raise HTTPException(400, f"invalid zone name {zone!r}")
    lines = []
    for opt in ("input", "output", "forward"):
        val = (policies or {}).get(opt)
        if val is None:
            continue
        val = str(val).upper()
        if val not in ("ACCEPT", "REJECT", "DROP"):
            raise HTTPException(400, f"invalid {opt} policy {val!r}")
        lines.append(f"uci set firewall.{zone}.{opt}='{val}'")
    if not lines:
        raise HTTPException(400, "no zone policies given (use input/output/forward)")
    _run_ssh(dev, _fw_commit("\n".join(lines) + "\n", apply=apply), "firewall",
             f"zone={zone} policies={policies}", "zone policy apply")
    set_pending(dev, "firewall", apply)
    return {"device": dev["name"], "ok": True, "zone": zone}


def delete_fw_rule(dev, name, apply: bool = True):
    """Remove an inter-zone rule by name (section id = slug of the name)."""
    slug = _uci_slug(name)
    _run_ssh(dev, _fw_commit(f"uci delete firewall.{slug}\n", apply=apply), "firewall",
             f"delete_rule={name}", "rule delete")
    set_pending(dev, "firewall", apply)
    return {"device": dev["name"], "ok": True, "section": slug}


def delete_fw_forward(dev, name, apply: bool = True):
    """Remove a port forward by name (section id = slug of the name)."""
    slug = _uci_slug(name)
    _run_ssh(dev, _fw_commit(f"uci delete firewall.{slug}\n", apply=apply), "firewall",
             f"delete_forward={name}", "forward delete")
    set_pending(dev, "firewall", apply)
    return {"device": dev["name"], "ok": True, "section": slug}


def apply_findings(dev, st):
    findings = audit_status(st)
    current = {r["rule_id"] for r in owctl.q("SELECT * FROM active_findings WHERE device_id=?", (dev["id"],))}
    new_rules = {f["rule_id"]: f for f in findings}
    fired = []
    for rule, f in new_rules.items():
        if rule not in current:
            owctl.execute("INSERT OR REPLACE INTO active_findings(device_id, rule_id, severity, message, detail, rec, ts) "
                    "VALUES(?,?,?,?,?,?,?)", (dev["id"], rule, f["severity"], f["message"], f["detail"], f["rec"], owctl.now()))
            owctl.execute("INSERT INTO findings(ts, device_id, device_name, rule_id, severity, message, detail, rec) "
                    "VALUES(?,?,?,?,?,?,?,?)", (owctl.now(), dev["id"], dev["name"], rule, f["severity"],
                                                f["message"], f["detail"], f["rec"]))
            fired.append(f)
        else:
            owctl.execute("UPDATE active_findings SET severity=?, message=?, detail=?, rec=?, ts=? "
                    "WHERE device_id=? AND rule_id=?",
                    (f["severity"], f["message"], f["detail"], f["rec"], owctl.now(), dev["id"], rule))
    for rule in list(current - set(new_rules)):
        owctl.execute("DELETE FROM active_findings WHERE device_id=? AND rule_id=?", (dev["id"], rule))
    for f in fired:
        try:
            owctl.fire_alert(dev, f)
        except Exception:
            pass
    return findings
