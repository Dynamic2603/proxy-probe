from __future__ import annotations

import base64
import contextlib
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
    """Надёжный парсер proxy URI (vless, trojan, hysteria2, shadowsocks).

    В отличие от стандартного urllib.parse.urlsplit, устойчив к:
    - паролям и именам с квадратными скобками (p[ass]word),
    - нестандартным bracketed-хостам ([1.2.3.4], [domain.com]),
    - непарным скобкам в netloc,
    - IPv6 адресам без квадратных скобок,
    - повреждённым URL-строкам.
    """
    try:
        raw = link.strip()
        raw, _, fragment = raw.partition("#")
        raw, _, query_str = raw.partition("?")
        scheme, sep, rest = raw.partition("://")
        if not sep:
            return "", "", "", 0, {}, ""

        rest, _, path = rest.partition("/")
        user = ""
        hostport = rest
        if "@" in rest:
            userpart, _, hostport = rest.rpartition("@")
            user = urllib.parse.unquote(userpart)

        host = ""
        port = 0
        if hostport.startswith("["):
            h, _, p = hostport[1:].partition("]")
            host = h
            if p.startswith(":"):
                port = int(p[1:]) if p[1:].isdigit() else 0
        elif ":" in hostport:
            h, _, p = hostport.rpartition(":")
            if p.isdigit():
                host = h
                port = int(p)
            else:
                host = hostport
                port = 0
        else:
            host = hostport
            port = 0

        clean_host = host.strip("[]")
        q = dict(urllib.parse.parse_qsl(query_str, keep_blank_values=True))
        if path and not q.get("path"):
            q["path"] = "/" + path
        tag = urllib.parse.unquote(fragment)
        return scheme.lower(), user, clean_host, port, q, tag
    except Exception:
        return "", "", "", 0, {}, ""


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
    # flow (XTLS Vision) применим только к TCP-потокам sing-box; в xhttp ветке намеренно опускается
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
        out["flow"] = "xtls-rprx-vision"
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
    method, password = "aes-128-gcm", ""
    if not port and host and not cred:
        pad = "=" * ((-len(host)) % 4)
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = fn(host + pad).decode("utf-8", "replace")
                if "@" in decoded and ":" in decoded:
                    up, _, hp = decoded.partition("@")
                    if ":" in up and ":" in hp:
                        method, password = up.split(":", 1)
                        h, p = hp.rsplit(":", 1)
                        if p.isdigit():
                            host, port = h.strip("[]"), int(p)
                            break
            except Exception:
                pass

    if not host or not port:
        return "sing-box", {}

    if cred:
        pad = "=" * ((-len(cred)) % 4)
        dec = None
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = fn(cred + pad).decode("utf-8", "replace")
                if ":" in raw:
                    dec = raw
                    break
            except Exception:
                pass
        if dec is None:
            dec = cred
        method, password = dec.split(":", 1) if ":" in dec else ("aes-128-gcm", dec)

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
        b64 = link.strip()[len("vmess://") :]
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
    try:
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
    except Exception:
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


_MIN_BASE64_BODY_LEN = 80  # Минимальная длина строки для эвристики base64-подписки


def decode_body(data: bytes) -> str:
    txt = data.decode("utf-8", "replace")
    clean = re.sub(r"\s+", "", txt)
    if len(clean) > _MIN_BASE64_BODY_LEN and "://" not in txt and bool(re.fullmatch(r"[A-Za-z0-9+/=\-_]*", clean)):
        pad = "=" * ((-len(clean)) % 4)
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                dec = fn(clean + pad).decode("utf-8", "replace")
                if re.search(r"[a-z0-9]+://", dec, re.IGNORECASE):
                    return dec
            except Exception:
                pass
    return txt


NON_PROXY_PROTOCOLS: frozenset[str] = frozenset({"freedom", "blackhole", "dns", "direct", "block"})


def extract_proxy_outbounds_from_config(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Извлекает список прокси-аутбаундов из комплексной конфигурации Xray/sing-box (SSOT).

    Исключает служебные протоколы (freedom, blackhole, direct, dns, block).
    """
    raw_obs = cfg.get("outbounds")
    if not isinstance(raw_obs, list):
        return []
    res: list[dict[str, Any]] = []
    for o in raw_obs:
        if not isinstance(o, dict):
            continue
        proto = str(o.get("protocol") or o.get("type") or "").strip().lower()
        if proto and proto not in NON_PROXY_PROTOCOLS:
            res.append(o)
    return res


def parse_outbound_doc(doc: str) -> list[tuple[str, dict]]:
    doc = doc.strip()
    if not doc:
        return []
    if doc.startswith(("[", "{")):
        try:
            j = json.loads(doc)
        except Exception:
            return []
        items = j if isinstance(j, list) else [j]
        # Если в списке есть как одиночные профили, так и балансировщики,
        # отфильтруем балансировщики, чтобы не затирать канонические имена узлов
        has_standalone = any(
            isinstance(it, dict)
            and (
                len(extract_proxy_outbounds_from_config(it)) == 1
                or "protocol" in it
                or "type" in it
            )
            for it in items
        )
        res: list[tuple[str, dict]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("outbounds"), list):
                if has_standalone and (
                    bool(item.get("routing", {}).get("balancers"))
                    or bool(item.get("burstObservatory"))
                ):
                    continue
                proxy_obs = extract_proxy_outbounds_from_config(item)
                remarks = str(item.get("remarks") or item.get("tag") or "").strip()
                for po in proxy_obs:
                    engine = "xray" if "protocol" in po else ("sing-box" if "type" in po else "xray")
                    po_dict = dict(po)
                    if remarks and (not po_dict.get("tag") or po_dict.get("tag") in ("proxy", "outbound")):
                        po_dict["tag"] = remarks
                    res.append((engine, po_dict))
            elif "protocol" in item:
                if str(item.get("protocol")).lower() not in NON_PROXY_PROTOCOLS:
                    res.append(("xray", item))
            elif "type" in item:
                if str(item.get("type")).lower() not in NON_PROXY_PROTOCOLS:
                    res.append(("sing-box", item))
        return res
    if "://" in doc:
        try:
            eng, obj = link_to_outbound(doc)
            return [(eng, obj)] if obj else []
        except Exception:
            return []
    return []


def parse_subscription(data: bytes) -> list[tuple[str, dict]]:
    text = decode_body(data)
    res: list[tuple[str, dict]] = []
    for block in split_blocks(text):
        with contextlib.suppress(Exception):
            res.extend(parse_outbound_doc(block))
    return res


def extract_host_port(obj: dict) -> tuple[str, int]:
    sett = obj.get("settings")
    sett_dict: dict[str, Any] = sett if isinstance(sett, dict) else {}
    srv = obj.get("server") or sett_dict.get("address")
    prt = obj.get("server_port") or sett_dict.get("port")
    if (
        (not srv or not prt)
        and (vnext := sett_dict.get("vnext"))
        and isinstance(vnext, list)
        and vnext
        and isinstance(vnext[0], dict)
    ):
        srv = srv or vnext[0].get("address")
        prt = prt or vnext[0].get("port")
    if (
        (not srv or not prt)
        and (servers := sett_dict.get("servers"))
        and isinstance(servers, list)
        and servers
        and isinstance(servers[0], dict)
    ):
        srv = srv or servers[0].get("address")
        prt = prt or servers[0].get("port")
    peers = obj.get("peers")
    if not srv and isinstance(peers, list) and peers and isinstance(peers[0], dict):
        srv = peers[0].get("address") or peers[0].get("server")
        prt = prt or peers[0].get("port")
    return str(srv or ""), int(prt or 0)


def extract_tag(obj: dict) -> str:
    return str(obj.get("tag") or "")
