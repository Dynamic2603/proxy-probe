from __future__ import annotations

import base64
import json
import re
import urllib.parse
from typing import Any

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


def _is_true(v: Any) -> bool:
    return isinstance(v, str) and v.lower() in ("1", "true", "yes", "on", "y")


def _clean_alpn(val: str) -> list[str]:
    return [a for a in val.split(",") if a] if val else []


def _parse_uri(link: str) -> tuple[str, str, str, int, dict[str, str], str]:
    u = urllib.parse.urlsplit(link.strip())
    netloc = u.netloc
    if "@" in netloc:
        userpart, _, hostport = netloc.partition("@")
        user = urllib.parse.unquote(userpart)
    else:
        user = urllib.parse.unquote(u.username or "")
        hostport = netloc
    if ":" in hostport:
        parts = hostport.rsplit(":", 1)
        host = parts[0]
        port = int(parts[1]) if parts[1].isdigit() else 0
    else:
        host, port = hostport, 0
    q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    tag = urllib.parse.unquote(u.fragment or "")
    return u.scheme.lower(), user, host.strip("[]"), port, q, tag


def _build_transport(net: str, q: dict[str, str]) -> dict[str, Any] | None:
    host_param = q.get("host") or q.get("authority")
    path = q.get("path") or "/"
    if net == "ws":
        t: dict[str, Any] = {"type": "ws", "path": path}
        if host_param:
            t["headers"] = {"Host": host_param}
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": q.get("serviceName") or q.get("path") or ""}
    if net in ("h2", "httpupgrade"):
        t_type = "httpupgrade" if net == "httpupgrade" else "http"
        t = {"type": t_type, "path": path}
        if host_param:
            t["host"] = host_param
        return t
    return None


def _singbox_tls(sec: str, host: str, q: dict[str, str]) -> dict[str, Any] | None:
    sni = q.get("sni") or host
    fp = q.get("fp") or q.get("utls")
    if sec == "reality":
        pbk = q.get("pbk") or q.get("password") or ""
        reality: dict[str, Any] = {"enabled": True, "public_key": pbk}
        if sid := q.get("sid"):
            reality["short_id"] = sid
        return {
            "enabled": True,
            "server_name": sni,
            "utls": {"enabled": True, "fingerprint": fp or "chrome"},
            "reality": reality,
        }
    if sec in ("tls", "xtls"):
        tls: dict[str, Any] = {
            "enabled": True,
            "insecure": _is_true(q.get("allowInsecure") or q.get("insecure")),
            "server_name": sni,
        }
        if alpn := _clean_alpn(q.get("alpn", "")):
            tls["alpn"] = alpn
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        return tls
    return None


def parse_vless(link: str) -> tuple[str, dict]:
    _, uuid, host, port, q, name = _parse_uri(link)
    if not uuid or not host or not port:
        return "sing-box", {}
    net = q.get("type", "tcp")
    if net in ("raw", "none"):
        net = "tcp"
    sec = q.get("security", "none")
    flow = q.get("flow", "")

    if net == "xhttp":
        sec = sec or "none"
        ss: dict[str, Any] = {
            "network": "xhttp",
            "security": sec,
            "xhttpSettings": {"path": q.get("path") or "/", "mode": q.get("mode") or "auto"},
        }
        if host_param := (q.get("host") or q.get("authority")):
            ss["xhttpSettings"]["host"] = host_param
        if sec == "reality":
            rs = {
                "serverName": q.get("sni") or host,
                "fingerprint": q.get("fp") or "chrome",
                "password": q.get("pbk") or "",
                "spiderX": q.get("spx") or "/",
            }
            if sid := q.get("sid"):
                rs["shortId"] = sid
            ss["realitySettings"] = rs
        elif sec == "tls":
            ts: dict[str, Any] = {"serverName": q.get("sni") or host}
            if fp := (q.get("fp") or q.get("utls")):
                ts["fingerprint"] = fp
            if alpn := _clean_alpn(q.get("alpn", "")):
                ts["alpn"] = alpn
            if _is_true(q.get("allowInsecure") or q.get("insecure")):
                ts["allowInsecure"] = True
            ss["tlsSettings"] = ts
        return "xray", {
            "protocol": "vless",
            "settings": {"address": host, "port": port, "id": uuid, "encryption": "none", "flow": ""},
            "streamSettings": ss,
            "tag": name or f"{host}:{port}",
        }

    out: dict[str, Any] = {
        "type": "vless",
        "tag": name or f"{host}:{port}",
        "server": host,
        "server_port": port,
        "uuid": uuid,
    }
    penc = q.get("packetEncoding") or q.get("packet_encoding")
    if penc and penc != "none":
        out["packet_encoding"] = penc
    if net == "tcp" and flow and flow != "none" and "vision" in flow:
        out["flow"] = flow
    if tls := _singbox_tls(sec, host, q):
        out["tls"] = tls
    if tr := _build_transport(net, q):
        out["transport"] = tr
    return "sing-box", out


def parse_hysteria2(link: str) -> tuple[str, dict]:
    _, passwd, host, port, q, name = _parse_uri(link)
    if not host or not port:
        return "sing-box", {}
    out: dict[str, Any] = {
        "type": "hysteria2",
        "tag": name or f"{host}:{port}",
        "server": host,
        "server_port": port,
        "password": passwd,
        "tls": {
            "enabled": True,
            "server_name": q.get("sni") or host,
            "insecure": _is_true(q.get("insecure") or q.get("allowInsecure")),
        },
    }
    return "sing-box", out


def parse_shadowsocks(link: str) -> tuple[str, dict]:
    _, cred, host, port, _, name = _parse_uri(link)
    if not host or not port or not cred:
        return "sing-box", {}
    try:
        dec = base64.b64decode(cred, validate=False).decode("utf-8", "replace")
        method, password = dec.split(":", 1) if ":" in dec else ("aes-128-gcm", cred)
    except Exception:
        return "sing-box", {}
    return "sing-box", {
        "type": "shadowsocks",
        "tag": name or f"{host}:{port}",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }


def parse_trojan(link: str) -> tuple[str, dict]:
    _, passwd, host, port, q, name = _parse_uri(link)
    if not host or not port:
        return "sing-box", {}
    return "sing-box", {
        "type": "trojan",
        "tag": name or f"{host}:{port}",
        "server": host,
        "server_port": port,
        "password": passwd,
        "tls": {
            "enabled": True,
            "server_name": q.get("sni") or host,
            "insecure": _is_true(q.get("allowInsecure") or q.get("insecure")),
        },
    }


def parse_vmess(link: str) -> tuple[str, dict]:
    try:
        b64 = link.strip()[len("vmess://"):]
        j = json.loads(base64.b64decode(b64, validate=False).decode("utf-8", "replace"))
        net = j.get("net", "tcp")
        host = j.get("add", "")
        port = int(j.get("port") or 0)
        out: dict[str, Any] = {
            "type": "vmess",
            "tag": j.get("ps", "") or f"{host}:{port}",
            "server": host,
            "server_port": port,
            "uuid": j.get("id", ""),
            "security": j.get("scy") or "auto",
        }
        if j.get("tls"):
            sni = j.get("sni") or j.get("host") or host
            tls: dict[str, Any] = {"enabled": True, "server_name": sni}
            if str(j.get("tls")).lower() in ("1", "true", "tls") and (fp := j.get("fp")):
                tls["utls"] = {"enabled": True, "fingerprint": fp}
            out["tls"] = tls
        ws_host = j.get("host") or j.get("sni") or ""
        if tr := _build_transport(net, {"path": j.get("path", "/"), "host": ws_host}):
            out["transport"] = tr
        return "sing-box", out
    except Exception:
        return "sing-box", {}


def link_to_outbound(link: str) -> tuple[str, dict]:
    phrase = link.strip()
    if phrase.startswith("vless://"):
        return parse_vless(phrase)
    if phrase.startswith(("hy2://", "hysteria2://")):
        return parse_hysteria2(phrase)
    if phrase.startswith("ss://"):
        return parse_shadowsocks(phrase)
    if phrase.startswith("trojan://"):
        return parse_trojan(phrase)
    if phrase.startswith("vmess://"):
        return parse_vmess(phrase)
    return "sing-box", {}


def split_blocks(text: str) -> list[str]:
    items: list[str] = []
    decoder = json.JSONDecoder()
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        if text[i] in "#;/!":
            next_nl = text.find("\n", i)
            i = n if next_nl == -1 else next_nl + 1
            continue
        if text[i] in "{[":
            try:
                _, end_idx = decoder.raw_decode(text, i)
                items.append(text[i:end_idx].strip())
                i = end_idx
                continue
            except json.JSONDecodeError:
                pass
        next_nl = text.find("\n", i)
        line = text[i:next_nl].strip() if next_nl != -1 else text[i:].strip()
        i = n if next_nl == -1 else next_nl + 1
        if line and not line.startswith(("#", ";", "/", "!")):
            items.append(line)
    return items


def decode_body(data: bytes) -> str:
    txt = data.decode("utf-8", "replace")
    if len(txt) > 80 and bool(re.fullmatch(r"[A-Za-z0-9+/=\r\n]*", txt)) and "://" not in txt:
        try:
            dec = base64.b64decode(re.sub(r"\s+", "", txt), validate=True).decode("utf-8", "replace")
            if re.search(r"[a-z0-9]+://", dec, re.IGNORECASE):
                return dec
        except Exception:
            pass
    return txt


def parse_outbound_doc(doc: str) -> list[tuple[str, dict]]:
    doc = doc.strip()
    if not doc:
        return []
    if doc.startswith(("[", "{")):
        try:
            j = json.loads(doc)
        except Exception:
            return []
        objs = j.get("outbounds", [j]) if isinstance(j, dict) else j
        res: list[tuple[str, dict]] = []
        for o in (objs if isinstance(objs, list) else [objs]):
            if isinstance(o, dict):
                if "protocol" in o:
                    res.append(("xray", o))
                elif "type" in o:
                    res.append(("sing-box", o))
        return res
    if "://" in doc:
        eng, obj = link_to_outbound(doc)
        return [(eng, obj)] if obj else []
    return []


def parse_subscription(data: bytes) -> list[tuple[str, dict]]:
    text = decode_body(data)
    res: list[tuple[str, dict]] = []
    for block in split_blocks(text):
        res.extend(parse_outbound_doc(block))
    return res


def extract_host_port(obj: dict) -> tuple[str, int]:
    srv = obj.get("server") or (obj.get("settings") or {}).get("address") or ""
    prt = obj.get("server_port") or (obj.get("settings") or {}).get("port") or 0
    return str(srv), int(prt or 0)


def extract_tag(obj: dict) -> str:
    return str(obj.get("tag") or "")
