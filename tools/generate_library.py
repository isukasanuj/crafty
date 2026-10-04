#!/usr/bin/env python3
"""Generate the crafty starter template library.

Honesty policy (baked into each file's header as a Tier):
  T1 verified   - uses only engine mechanisms covered by the test suite
                  (recv-first banners, send/recv line probes, HTTP path checks,
                  length-prefixed binary, UDP text). Schema-valid + smoke-tested.
  T2 constructed - payload built from documented protocol constants; schema-valid
                  but NOT reproduced against a live service. Validate before use.
  T3 draft      - poisoners needing a live target; default to safe 'analyze' mode.

Run:  python tools/generate_library.py
It writes templates/client/** and templates/listener/**. Existing hand-curated
templates are left untouched (the generator skips ids it does not own).
"""

from __future__ import annotations

import io
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CLIENT = ROOT / "crafty" / "templates" / "client"   # shipped inside the package
LISTENER = ROOT / "crafty" / "templates" / "listener"

# ids that already exist as hand-curated templates - do not overwrite
CURATED = {
    "tcp-banner", "length-prefixed-probe", "spray-demo", "poll-until",
    "selective-udp-responder", "llmnr-poison",
}

MANIFEST: list[tuple[Path, dict, str, str]] = []  # (path, template, tier, note)


def emit(dir_: Path, template: dict, tier: str, note: str = "") -> None:
    fid = template["id"]
    if fid in CURATED:
        return
    MANIFEST.append((dir_ / f"{fid}.yaml", template, tier, note))


def _info(name, tags, severity="info", author="crafty", desc=""):
    return {"name": name, "author": author, "severity": severity, "tags": tags, "description": desc}


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #
def banner(fid, name, port, extra_tags=None, words=None, min_len=1, tls=False):
    sock = {"timeout": "5s"}
    if tls:
        sock["tls"] = True
    matchers = ([{"type": "word", "part": "data", "words": words}]
                if words else [{"type": "len", "part": "data", "min": min_len}])
    t = {
        "id": fid,
        "info": _info(name, ["client", "tcp", "recon", "banner"] + (extra_tags or []),
                      desc=f"Read-first banner grab for {name}."),
        "transport": "tcp", "role": "client",
        "target": f"{{{{RHOST}}}}:{{{{RPORT|{port}}}}}",
        "socket": sock, "tempo": {"preflight": True},
        "flow": [{"recv": {"read": 1024}, "matchers": matchers,
                  "on_match": {"log": f"{name} banner captured",
                               "capture": {"to": f"loot/{fid}.txt", "part": "data"}}}],
    }
    return t


def line(fid, name, port, send, words, extra_tags=None, delim="\r\n", read=None, tls=False, defaults=None):
    sock = {"timeout": "5s"}
    if tls:
        sock["tls"] = True
    recv = {"read": read} if read else {"type": "delimiter", "delimiter": delim}
    t = {
        "id": fid,
        "info": _info(name, ["client", "tcp"] + (extra_tags or []),
                      desc=f"Send-then-read probe: {name}."),
        "transport": "tcp", "role": "client",
        "target": f"{{{{RHOST}}}}:{{{{RPORT|{port}}}}}",
        "socket": sock, "tempo": {"preflight": True},
        "flow": [{"send": {"bytes": send}, "recv": recv,
                  "matchers": [{"type": "word", "part": "data", "words": words}],
                  "on_match": {"log": f"{name}: match",
                               "capture": {"to": f"loot/{fid}.txt", "part": "data"}}}],
    }
    if defaults:
        t["defaults"] = defaults
    return t


def http(fid, name, path, port, words, extra_tags=None, tls=False, method="GET"):
    send = (f"{method} {path} HTTP/1.1\\r\\n"
            f"Host: {{{{RHOST}}}}\\r\\nUser-Agent: crafty\\r\\nAccept: */*\\r\\n"
            f"Connection: close\\r\\n\\r\\n")
    sock = {"timeout": "6s"}
    if tls:
        sock["tls"] = True
    proto = "https" if tls else "http"
    t = {
        "id": fid,
        "info": _info(name, ["client", "tcp", proto, "web"] + (extra_tags or []),
                      desc=f"HTTP probe: {name} ({method} {path})."),
        "transport": "tcp", "role": "client",
        "target": f"{{{{RHOST}}}}:{{{{RPORT|{port}}}}}",
        "socket": sock, "tempo": {"preflight": True, "rate": "20/s"},
        "flow": [{"send": {"bytes": send}, "recv": {"read": 8192},
                  "matchers": [{"type": "word", "part": "data", "words": words}],
                  "on_match": {"log": f"{name}: {{{{RHOST}}}} matched",
                               "capture": {"to": f"loot/{fid}.txt", "value": "{{RHOST}}:{{RPORT}}"}}}],
    }
    return t


def udp_text(fid, name, port, send, words, extra_tags=None, read=2048):
    t = {
        "id": fid,
        "info": _info(name, ["client", "udp"] + (extra_tags or []),
                      desc=f"UDP text probe: {name}."),
        "transport": "udp", "role": "client",
        "target": f"{{{{RHOST}}}}:{{{{RPORT|{port}}}}}",
        "socket": {"timeout": "4s"},
        "flow": [{"send": {"bytes": send}, "recv": {"read": read},
                  "matchers": [{"type": "word", "part": "data", "words": words}] if words
                              else [{"type": "len", "part": "data", "min": 1}],
                  "on_match": {"log": f"{name}: response from {{{{RHOST}}}}",
                               "capture": {"to": f"loot/{fid}.txt", "part": "data"}}}],
    }
    return t


def udp_bin(fid, name, port, bytes_dsl, extra_tags=None, matchers=None, read=1024, defaults=None):
    t = {
        "id": fid,
        "info": _info(name, ["client", "udp", "binary"] + (extra_tags or []),
                      desc=f"UDP binary probe: {name}."),
        "transport": "udp", "role": "client",
        "target": f"{{{{RHOST}}}}:{{{{RPORT|{port}}}}}",
        "socket": {"timeout": "4s"},
        "flow": [{"send": {"bytes": bytes_dsl}, "recv": {"read": read},
                  "matchers": matchers or [{"type": "len", "part": "data", "min": 1}],
                  "on_match": {"log": f"{name}: response from {{{{RHOST}}}}",
                               "capture": {"to": f"loot/{fid}.txt", "part": "data"}}}],
    }
    if defaults:
        t["defaults"] = defaults
    return t


def tcp_bin(fid, name, port, bytes_dsl, extra_tags=None, framing=None, matchers=None, defaults=None):
    t = {
        "id": fid,
        "info": _info(name, ["client", "tcp", "binary"] + (extra_tags or []),
                      desc=f"TCP binary probe: {name}."),
        "transport": "tcp", "role": "client",
        "target": f"{{{{RHOST}}}}:{{{{RPORT|{port}}}}}",
        "socket": {"timeout": "5s"}, "tempo": {"preflight": True},
        "flow": [{"send": {"bytes": bytes_dsl}, "recv": framing or {"read": 2048},
                  "matchers": matchers or [{"type": "len", "part": "data", "min": 1}],
                  "on_match": {"log": f"{name}: response from {{{{RHOST}}}}",
                               "capture": {"to": f"loot/{fid}.txt", "part": "data"}}}],
    }
    if defaults:
        t["defaults"] = defaults
    return t


def listener_catch(fid, name, transport, port, extra_tags=None, respond=None,
                   selectivity=None, mode="active", multicast=None):
    sock = {"bind": f"0.0.0.0:{{{{LPORT|{port}}}}}", "options": ["SO_REUSEADDR"]}
    if multicast:
        sock["multicast"] = multicast
    onr = {
        "extract": [{"name": "query", "type": "dsl", "expression": "str(data)"}],
        "capture": {"to": f"loot/{fid}.txt", "value": "{{peer}} -> {{query}}"},
    }
    if respond is not None:
        onr["respond"] = {"bytes": respond}
    t = {
        "id": fid,
        "info": _info(name, ["listener", transport] + (extra_tags or []), severity="high",
                      desc=f"{name}."),
        "transport": transport, "role": "listener", "mode": mode,
        "socket": sock,
    }
    if selectivity:
        t["selectivity"] = selectivity
    t["on_receive"] = onr
    return t


# --------------------------------------------------------------------------- #
# T1 - banner grabs (service speaks first)
# --------------------------------------------------------------------------- #
emit(CLIENT, banner("banner-ssh", "SSH", 22, ["ssh"], words=["SSH-"]), "T1")
emit(CLIENT, banner("banner-ftp", "FTP", 21, ["ftp"], words=["220"]), "T1")
emit(CLIENT, banner("banner-smtp", "SMTP", 25, ["smtp", "mail"], words=["220"]), "T1")
emit(CLIENT, banner("banner-smtp-submission", "SMTP submission", 587, ["smtp", "mail"], words=["220"]), "T1")
emit(CLIENT, banner("banner-pop3", "POP3", 110, ["pop3", "mail"], words=["+OK"]), "T1")
emit(CLIENT, banner("banner-imap", "IMAP", 143, ["imap", "mail"], words=["* OK"]), "T1")
emit(CLIENT, banner("banner-telnet", "Telnet", 23, ["telnet"], min_len=1), "T1")
emit(CLIENT, banner("banner-mysql", "MySQL greeting", 3306, ["mysql", "db"], min_len=5), "T1")
emit(CLIENT, banner("banner-mariadb", "MariaDB greeting", 3306, ["mariadb", "db"], min_len=5), "T1")
emit(CLIENT, banner("banner-vnc", "VNC (RFB)", 5900, ["vnc"], words=["RFB"]), "T1")
emit(CLIENT, banner("banner-irc", "IRC", 6667, ["irc"], min_len=1), "T1")
emit(CLIENT, banner("banner-nntp", "NNTP", 119, ["nntp"], words=["200", "201"]), "T1")
emit(CLIENT, banner("banner-cvs", "CVS pserver", 2401, ["cvs"], min_len=1), "T1")
emit(CLIENT, banner("banner-generic", "Generic banner grab", 0, ["generic"], min_len=1), "T1",
     note="Set RPORT; works for any service that sends a banner first.")

# TLS banner-first
emit(CLIENT, banner("banner-smtps", "SMTPS", 465, ["smtp", "tls", "mail"], words=["220"], tls=True), "T1")
emit(CLIENT, banner("banner-imaps", "IMAPS", 993, ["imap", "tls", "mail"], words=["* OK"], tls=True), "T1")
emit(CLIENT, banner("banner-pop3s", "POP3S", 995, ["pop3", "tls", "mail"], words=["+OK"], tls=True), "T1")

# --------------------------------------------------------------------------- #
# T1 - line / text probes (send then read)
# --------------------------------------------------------------------------- #
emit(CLIENT, line("probe-redis-ping", "Redis PING", 6379, "PING\\r\\n", ["+PONG", "NOAUTH", "-ERR"], ["redis", "db"]), "T1")
emit(CLIENT, line("probe-redis-info", "Redis INFO", 6379, "INFO\\r\\n", ["redis_version", "NOAUTH"], ["redis", "db"], read=4096), "T1")
emit(CLIENT, line("probe-memcached-version", "Memcached version", 11211, "version\\r\\n", ["VERSION"], ["memcached", "db"]), "T1")
emit(CLIENT, line("probe-memcached-stats", "Memcached stats", 11211, "stats\\r\\n", ["STAT"], ["memcached", "db"], read=4096), "T1")
emit(CLIENT, line("probe-echo", "Echo service", 7, "crafty-echo\\r\\n", ["crafty-echo"], ["echo"]), "T1")
emit(CLIENT, line("probe-daytime", "Daytime", 13, "\\r\\n", [":"], ["daytime"]), "T1")
emit(CLIENT, line("probe-qotd", "Quote of the day", 17, "\\r\\n", [" "], ["qotd"]), "T1")
emit(CLIENT, line("probe-whois", "WHOIS", 43, "{{QUERY}}\\r\\n", ["Domain", "NOT FOUND", "No match"], ["whois"], read=8192, defaults={"QUERY": "example.com"}), "T1")
emit(CLIENT, line("probe-finger", "Finger", 79, "{{USER}}\\r\\n", ["Login", "No such user", ":"], ["finger"], read=4096, defaults={"USER": "root"}), "T1")
emit(CLIENT, line("probe-smtp-ehlo", "SMTP EHLO", 25, "EHLO crafty.test\\r\\n", ["250"], ["smtp", "mail"], read=4096), "T1")
emit(CLIENT, line("probe-zookeeper-ruok", "ZooKeeper ruok", 2181, "ruok", ["imok"], ["zookeeper"]), "T1")
emit(CLIENT, line("probe-git-daemon", "git daemon upload-pack", 9418,
     "001agit-upload-pack /test\\x00", ["version", "ERR", "ng", "ACK"], ["git"], read=2048), "T2",
     note="pkt-line git-upload-pack request for repo '/test' (length prefix precomputed). "
          "Change the repo and the 4-hex length together.")

# --------------------------------------------------------------------------- #
# T1 - HTTP probes (paths / exposures)
# --------------------------------------------------------------------------- #
emit(CLIENT, http("http-root", "HTTP root", "/", 80, ["HTTP/"]), "T1")
emit(CLIENT, http("http-head", "HTTP HEAD", "/", 80, ["HTTP/"], method="HEAD"), "T1")
emit(CLIENT, http("http-options", "HTTP OPTIONS", "/", 80, ["HTTP/", "Allow"], method="OPTIONS"), "T1")
emit(CLIENT, http("http-title", "HTTP title/server", "/", 80, ["Server:", "<title"]), "T1")
emit(CLIENT, http("http-robots", "robots.txt", "/robots.txt", 80, ["User-agent", "Disallow"]), "T1")
emit(CLIENT, http("http-git-exposed", "Exposed .git/HEAD", "/.git/HEAD", 80, ["ref:"], ["exposure"]), "T1")
emit(CLIENT, http("http-env-exposed", "Exposed .env", "/.env", 80, ["APP_", "DB_", "SECRET", "="], ["exposure"]), "T1")
emit(CLIENT, http("http-ds-store", "Exposed .DS_Store", "/.DS_Store", 80, ["Bud1"], ["exposure"]), "T1")
emit(CLIENT, http("http-server-status", "Apache server-status", "/server-status", 80, ["Apache Status", "Server Version"], ["exposure"]), "T1")
emit(CLIENT, http("http-phpinfo", "phpinfo()", "/phpinfo.php", 80, ["phpinfo()", "PHP Version"], ["exposure"]), "T1")
emit(CLIENT, http("http-actuator", "Spring Boot actuator", "/actuator", 80, ["_links", "health"], ["exposure", "spring"]), "T1")
emit(CLIENT, http("http-actuator-env", "Spring actuator env", "/actuator/env", 80, ["propertySources"], ["exposure", "spring"]), "T1")
emit(CLIENT, http("http-swagger", "Swagger UI", "/swagger-ui.html", 80, ["Swagger", "swagger-ui"], ["api"]), "T1")
emit(CLIENT, http("http-graphql", "GraphQL endpoint", "/graphql", 80, ["GraphQL", "__schema", "errors"], ["api"], method="GET"), "T1")
emit(CLIENT, http("http-wp-login", "WordPress login", "/wp-login.php", 80, ["WordPress", "user_login"], ["cms", "wordpress"]), "T1")
emit(CLIENT, http("http-elasticsearch", "Elasticsearch", "/", 9200, ["cluster_name", "lucene_version"], ["db", "elastic"]), "T1")
emit(CLIENT, http("http-kibana", "Kibana status", "/api/status", 5601, ["kibana", "status"], ["elastic"]), "T1")
emit(CLIENT, http("http-couchdb", "CouchDB root", "/", 5984, ["couchdb", "Welcome"], ["db"]), "T1")
emit(CLIENT, http("http-prometheus", "Prometheus", "/graph", 9090, ["Prometheus"], ["monitoring"]), "T1")
emit(CLIENT, http("http-grafana", "Grafana", "/login", 3000, ["Grafana", "grafana"], ["monitoring"]), "T1")
emit(CLIENT, http("http-jenkins", "Jenkins", "/", 8080, ["Jenkins", "X-Jenkins"], ["ci"]), "T1")
emit(CLIENT, http("http-solr", "Apache Solr", "/solr/", 8983, ["Solr", "solr"], ["db", "search"]), "T1")
emit(CLIENT, http("http-docker-api", "Docker remote API", "/version", 2375, ["ApiVersion", "DockerVersion"], ["docker", "exposure"]), "T1")
emit(CLIENT, http("http-consul", "Consul", "/v1/agent/self", 8500, ["Config", "Member"], ["infra"]), "T1")
emit(CLIENT, http("http-etcd", "etcd", "/version", 2379, ["etcdserver", "etcdcluster"], ["infra"]), "T1")
emit(CLIENT, http("http-rabbitmq", "RabbitMQ mgmt", "/", 15672, ["RabbitMQ"], ["mq"]), "T1")
emit(CLIENT, http("http-minio", "MinIO", "/minio/health/live", 9000, ["HTTP/"], ["storage"]), "T1")
emit(CLIENT, http("http-proxy-detect", "Open proxy check", "http://example.com/", 8080, ["HTTP/", "Example Domain"], ["proxy"], method="GET"), "T2",
     note="Open-proxy detection depends on the target honoring absolute-URI GET.")

# TLS HTTP
emit(CLIENT, http("https-root", "HTTPS root", "/", 443, ["HTTP/"], tls=True), "T1")
emit(CLIENT, http("https-git-exposed", "HTTPS exposed .git", "/.git/HEAD", 443, ["ref:"], ["exposure"], tls=True), "T1")
emit(CLIENT, http("https-kubernetes-api", "Kubernetes API", "/version", 6443, ["gitVersion", "major"], ["k8s"], tls=True), "T1")

# TLS non-http (connect + handshake, read whatever)
emit(CLIENT, banner("tls-ldaps", "LDAPS reachability", 636, ["ldap", "tls"], min_len=0, tls=True), "T2",
     note="LDAP does not send a banner; this confirms a TLS handshake succeeds.")

# --------------------------------------------------------------------------- #
# T1/T2 - UDP probes
# --------------------------------------------------------------------------- #
emit(CLIENT, udp_text("udp-ssdp-msearch", "SSDP M-SEARCH", 1900,
     'M-SEARCH * HTTP/1.1\\r\\nHOST: 239.255.255.250:1900\\r\\nMAN: "ssdp:discover"\\r\\nMX: 1\\r\\nST: ssdp:all\\r\\n\\r\\n',
     ["HTTP/1.1 200", "LOCATION", "USN"], ["ssdp", "upnp"]), "T1")
emit(CLIENT, udp_text("udp-sip-options", "SIP OPTIONS", 5060,
     "OPTIONS sip:{{RHOST}} SIP/2.0\\r\\nVia: SIP/2.0/UDP crafty\\r\\nCSeq: 1 OPTIONS\\r\\n\\r\\n",
     ["SIP/2.0"], ["sip", "voip"]), "T2",
     note="Minimal SIP request; some servers require more complete headers.")
emit(CLIENT, udp_bin("udp-dns-a", "DNS A query (example.com)", 53,
     "{{randbytes:2}}\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00{{hex:076578616d706c6503636f6d00}}\\x00\\x01\\x00\\x01",
     ["dns"], read=512, matchers=[{"type": "len", "part": "data", "min": 12}]), "T2",
     note="QNAME is fixed to example.com; a different name needs re-encoding (or the script step).")
emit(CLIENT, udp_bin("udp-dns-version-bind", "DNS version.bind (CHAOS TXT)", 53,
     "{{randbytes:2}}\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00{{hex:0776657273696f6e0462696e6400}}\\x00\\x10\\x00\\x03",
     ["bind", "dns"], read=512, matchers=[{"type": "len", "part": "data", "min": 12}]), "T2")
emit(CLIENT, udp_bin("udp-ntp-client", "NTP client request", 123,
     "{{= concat(hex2b('1b'), b'\\x00'*47)}}", ["ntp"], read=96,
     matchers=[{"type": "len", "part": "data", "min": 48}]), "T2")
emit(CLIENT, udp_bin("udp-snmp-get-sysdescr", "SNMPv1 GET sysDescr (public)", 161,
     "{{hex:302902010004067075626c6963a01c020400000001020100020100300e300c06082b060102010101000500}}",
     ["snmp"], read=1024, matchers=[{"type": "len", "part": "data", "min": 1}]), "T2",
     note="Standard SNMPv1 GET for 1.3.6.1.2.1.1.1.0, community 'public'. Validate against a live agent.")
emit(CLIENT, udp_bin("udp-netbios-name-query", "NetBIOS name query (*)", 137,
     "{{randbytes:2}}\\x00\\x10\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00{{hex:20434b41414141414141414141414141414141414141414141414141414141410000210001}}",
     ["netbios", "smb"], read=1024, matchers=[{"type": "len", "part": "data", "min": 1}]), "T2")
emit(CLIENT, udp_bin("udp-coap-get-core", "CoAP GET /.well-known/core", 5683,
     "{{hex:40015d1fbb2e77656c6c2d6b6e6f776e04636f7265}}", ["coap", "iot"], read=1024,
     matchers=[{"type": "len", "part": "data", "min": 1}]), "T2")
emit(CLIENT, udp_bin("udp-tftp-rrq", "TFTP read request", 69,
     "{{hex:0001}}{{FILENAME}}\\x00octet\\x00", ["tftp"], read=1024,
     matchers=[{"type": "len", "part": "data", "min": 1}], defaults={"FILENAME": "test"}), "T2")
emit(CLIENT, udp_bin("udp-wsd-probe", "WS-Discovery probe", 3702,
     '<?xml version="1.0"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><e:Header><d:Types>dn:NetworkVideoTransmitter</d:Types></e:Header></e:Envelope>',
     ["wsd", "iot"], read=4096, matchers=[{"type": "len", "part": "data", "min": 1}]), "T2")
emit(CLIENT, udp_bin("udp-memcached-stats", "Memcached UDP stats", 11211,
     "{{hex:0000000000010000}}stats\\r\\n", ["memcached"], read=2048,
     matchers=[{"type": "word", "part": "data", "words": ["STAT"]}]), "T2")

# --------------------------------------------------------------------------- #
# T1/T2 - TCP binary / length-prefixed
# --------------------------------------------------------------------------- #
emit(CLIENT, tcp_bin("bin-lenprefix-u16be", "Generic u16be length-prefixed probe", 0,
     "{{len16be:PAYLOAD}}{{PAYLOAD}}", ["generic"],
     framing={"type": "length-prefix", "size": 2, "endian": "be", "counts": "body"},
     defaults={"PAYLOAD": "PING"}), "T1",
     note="Set RPORT and PAYLOAD; the u16be length prefix is computed from PAYLOAD.")
emit(CLIENT, tcp_bin("bin-lenprefix-u32be", "Generic u32be length-prefixed probe", 0,
     "{{= concat(u32be(len(PAYLOAD)), bytes(PAYLOAD))}}", ["generic"],
     framing={"type": "length-prefix", "size": 4, "endian": "be", "counts": "body"},
     defaults={"PAYLOAD": "PING"}), "T1",
     note="Set RPORT and PAYLOAD; the u32be length prefix is computed from PAYLOAD.")
emit(CLIENT, tcp_bin("bin-jetdirect-pjl", "HP JetDirect PJL info", 9100,
     "{{= concat(hex2b('1b25'), b'-12345X@PJL INFO ID\\r\\n', hex2b('1b25'), b'-12345X')}}",
     ["printer", "jetdirect"], framing={"read": 2048},
     matchers=[{"type": "len", "part": "data", "min": 1}]), "T2")
emit(CLIENT, tcp_bin("bin-modbus-read-coils", "Modbus read coils", 502,
     "{{hex:000100000006010100000001}}", ["modbus", "ics", "scada"],
     framing={"type": "length-prefix", "offset": 4, "size": 2, "endian": "be", "counts": "body"},
     matchers=[{"type": "len", "part": "data", "min": 1}]), "T2",
     note="MBAP transaction id fixed; framing reads the response by its length field.")
emit(CLIENT, tcp_bin("bin-mqtt-connect", "MQTT CONNECT", 1883,
     "{{hex:101000044d5154540402003c00046372667479}}", ["mqtt", "iot"],
     framing={"read": 64}, matchers=[{"type": "binary", "part": "data", "value": "20"}]), "T2",
     note="MQTT 3.1.1 CONNECT with client id 'crfty'; expects CONNACK (0x20).")
emit(CLIENT, tcp_bin("bin-redis-resp-ping", "Redis RESP PING", 6379,
     "*1\\r\\n$4\\r\\nPING\\r\\n", ["redis", "db"], framing={"type": "delimiter", "delimiter": "\\r\\n"},
     matchers=[{"type": "word", "part": "data", "words": ["+PONG", "NOAUTH", "-ERR"]}]), "T1")
emit(CLIENT, tcp_bin("bin-rdp-x224", "RDP X.224 connection request", 3389,
     "{{hex:030000130ee00000000000010008000300000000}}", ["rdp"],
     framing={"read": 64}, matchers=[{"type": "binary", "part": "data", "value": "0300"}]), "T2")
emit(CLIENT, tcp_bin("bin-mssql-prelogin", "MSSQL pre-login", 1433,
     "{{hex:12010034000000000000001500060100206301000026000104000a00010001010002000003000b00010004ff08000201}}",
     ["mssql", "db"], framing={"read": 1024}, matchers=[{"type": "len", "part": "data", "min": 1}]), "T2",
     note="TDS pre-login packet; validate against a live SQL Server.")

# --------------------------------------------------------------------------- #
# T3 / listeners
# --------------------------------------------------------------------------- #
emit(LISTENER, listener_catch("mdns-poison", "mDNS poisoner (DRAFT)", "udp", 5353,
     ["mdns", "multicast", "poisoning"], respond="{{= data}}", mode="analyze",
     multicast={"group": "224.0.0.251", "interface": "{{IFACE|0.0.0.0}}"},
     selectivity={"respond_to": ["*local*"], "ignore": ["*canary*"]}), "T3",
     note="Draft. mDNS answer crafting needs validation against a live resolver; defaults to analyze.")
emit(LISTENER, listener_catch("nbtns-poison", "NBT-NS poisoner (DRAFT)", "udp", 137,
     ["netbios", "smb", "poisoning"], respond="{{= data}}", mode="analyze",
     selectivity={"respond_to": ["*"], "ignore": ["*canary*", "*wpad*"]}), "T3",
     note="Draft. NBT-NS name-registration/response crafting needs live validation; defaults to analyze.")
emit(LISTENER, listener_catch("rogue-udp-catch", "Rogue UDP catch-all", "udp", 0,
     ["catch", "honeypot"], respond=None, mode="analyze"), "T1",
     note="Set LPORT. Observes and logs UDP datagrams; never responds.")
emit(LISTENER, listener_catch("rogue-tcp-catch", "Rogue TCP catch-all", "tcp", 0,
     ["catch", "honeypot"], respond=None, mode="analyze"), "T1",
     note="Set LPORT. Accepts a connection, logs the first message, closes.")
emit(LISTENER, listener_catch("honeypot-telnet", "Telnet honeypot banner", "tcp", 23,
     ["honeypot", "telnet"], respond="login: ", mode="active"), "T1")
emit(LISTENER, listener_catch("honeypot-ftp", "FTP honeypot banner", "tcp", 21,
     ["honeypot", "ftp"], respond="220 crafty FTP ready\\r\\n", mode="active"), "T1")
emit(LISTENER, listener_catch("honeypot-http", "HTTP honeypot", "tcp", 80,
     ["honeypot", "web"],
     respond="HTTP/1.1 401 Unauthorized\\r\\nWWW-Authenticate: Basic realm=\"x\"\\r\\nContent-Length: 0\\r\\n\\r\\n",
     mode="active"), "T1", note="Prompts for Basic auth and logs the connection.")

# --------------------------------------------------------------------------- #
# Demos (T1)
# --------------------------------------------------------------------------- #
emit(CLIENT, {
    "id": "demo-struct-showcase",
    "info": _info("Struct showcase", ["demo", "struct", "binary"],
                  desc="Define a message layout once; the length prefix writes itself on pack."),
    "transport": "tcp", "role": "client", "target": "{{RHOST}}:{{RPORT|9999}}",
    "socket": {"timeout": "5s"},
    "structs": {"Msg": [
        {"name": "magic", "type": "bytes", "len": 4},
        {"name": "length", "type": "u16be", "value": "len(body)"},
        {"name": "body", "type": "bytes", "len": "length"},
    ]},
    "flow": [{"send": {"bytes": "{{struct:Msg(magic=b'CRFT', body=b'hello')}}"},
              "recv": {"type": "length-prefix", "offset": 4, "size": 2, "counts": "body"},
              "matchers": [{"type": "len", "part": "data", "min": 1}]}],
}, "T1")
emit(CLIENT, {
    "id": "demo-expression-checksum",
    "info": _info("Expression checksum demo", ["demo", "expression"],
                  desc="Compute a CRC32 over the body with a bounded expression - no script step."),
    "transport": "tcp", "role": "client", "target": "{{RHOST}}:{{RPORT|9999}}",
    "flow": [{"send": {"bytes": "{{= concat(bytes(BODY), u32be(crc32(BODY)))}}"},
              "recv": {"read": 256}, "matchers": [{"type": "len", "part": "data", "min": 1}]}],
    "defaults": {"BODY": "crafty"},
}, "T1")
emit(CLIENT, {
    "id": "demo-loop-repeat",
    "info": _info("Repeat loop demo", ["demo", "control-flow"],
                  desc="Fixed bounded repetition with a delay."),
    "transport": "udp", "role": "client", "target": "{{RHOST}}:{{RPORT|9999}}",
    "flow": [{"loop": {"repeat": 3, "delay": "1s",
                       "do": [{"send": {"bytes": "ping {{randstr:4}}"}, "recv": {"read": 256},
                               "matchers": [{"type": "len", "part": "data", "min": 1}]}]}}],
}, "T1")


# --------------------------------------------------------------------------- #
# Extras - more services + common HTTP exposures (to round out the library)
# --------------------------------------------------------------------------- #
emit(CLIENT, banner("banner-rsync", "rsync daemon", 873, ["rsync"], words=["@RSYNCD"]), "T1")
emit(CLIENT, line("probe-xmpp", "XMPP stream open", 5222,
     '<?xml version="1.0"?><stream:stream to="{{RHOST}}" xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" version="1.0">',
     ["<stream", "jabber"], ["xmpp"], read=4096), "T2",
     note="Minimal XMPP stream header; some servers require TLS/SNI first.")
emit(CLIENT, tcp_bin("bin-amqp-header", "AMQP protocol header", 5672,
     "{{= concat(b'AMQP', hex2b('00000901'))}}", ["amqp", "mq"],
     framing={"read": 1024}, matchers=[{"type": "word", "part": "data", "words": ["AMQP", "connection"]}]), "T2")

emit(CLIENT, http("http-tomcat-manager", "Tomcat manager", "/manager/html", 8080, ["Tomcat", "401 "], ["exposure", "tomcat"]), "T1")
emit(CLIENT, http("http-phpmyadmin", "phpMyAdmin", "/phpmyadmin/", 80, ["phpMyAdmin"], ["exposure", "db"]), "T1")
emit(CLIENT, http("http-aws-credentials", "Exposed AWS credentials", "/.aws/credentials", 80, ["aws_access_key_id"], ["exposure", "secrets"]), "T1")
emit(CLIENT, http("http-wp-config-bak", "WordPress wp-config backup", "/wp-config.php.bak", 80, ["DB_PASSWORD", "DB_NAME"], ["exposure", "wordpress", "secrets"]), "T1")
emit(CLIENT, http("http-jupyter", "Jupyter", "/api", 8888, ["version"], ["exposure", "notebook"]), "T1")
emit(CLIENT, http("http-gitlab", "GitLab sign-in", "/users/sign_in", 80, ["GitLab"], ["devops"]), "T1")
emit(CLIENT, http("http-sonarqube", "SonarQube status", "/api/system/status", 9000, ["status", "UP", "version"], ["ci", "sonarqube"]), "T1")
emit(CLIENT, http("http-adminer", "Adminer", "/adminer.php", 80, ["Adminer"], ["exposure", "db"]), "T1")
emit(CLIENT, http("http-backup-zip", "Exposed backup.zip", "/backup.zip", 80, ["PK"], ["exposure", "backup"]), "T1")
emit(CLIENT, http("http-config-json", "Exposed config.json", "/config.json", 80, ["password", "secret", "apiKey", "token"], ["exposure", "secrets"]), "T1")


# --------------------------------------------------------------------------- #
# Write everything
# --------------------------------------------------------------------------- #
def write_all() -> None:
    CLIENT.mkdir(parents=True, exist_ok=True)
    LISTENER.mkdir(parents=True, exist_ok=True)
    count = 0
    for path, template, tier, note in MANIFEST:
        header = (
            f"# {template['info']['name']}\n"
            f"# Tier: {tier}"
            + ("  (T2 = constructed from protocol spec; validate against a live service)" if tier == "T2" else "")
            + ("  (T3 = draft; needs live validation; defaults to safe analyze mode)" if tier == "T3" else "")
            + "\n"
            + (f"# Note: {note}\n" if note else "")
            + "# AUTHORIZED TESTING ONLY.\n"
        )
        body = yaml.safe_dump(template, sort_keys=False, default_flow_style=False, width=100)
        path.write_text(header + body, encoding="utf-8")
        count += 1
    print(f"wrote {count} templates ({len(CURATED)} curated left untouched) -> total {count + len(CURATED)}")


if __name__ == "__main__":
    write_all()
