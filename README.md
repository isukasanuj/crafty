# crafty

> Craft any TCP/UDP exchange — client or listener — as a declarative template or a live console session. One engine, one model, two front doors.

`crafty` is a protocol-crafting engine for **authorized** network security testing. You describe a byte-level exchange over TCP or UDP — the socket setup, the send/recv state machine, the matchers and extractors — and `crafty` runs it, either from a shareable YAML template or interactively from a session-based console. It covers the two halves no single declarative tool unifies: **client probes** and **listener / rogue-service attacks**, for *arbitrary* protocols, with a real bidirectional binary grammar and operator-controlled footprint.

```bash
git clone https://github.com/isukasanuj/crafty
cd crafty
python -m venv .venv && source .venv/Scripts/activate   # Windows (POSIX: source .venv/bin/activate)
pip install -e .
crafty --help
```

**Status: v0 (working prototype).** The core engine, both front doors, the binary grammar, the export system, and a 109-template library are implemented and covered by 284 tests. Some spec features are deliberately deferred — see [What's built vs deferred](#whats-built-vs-deferred). **For authorized security testing only** — see [Authorized use](#authorized-use).

---

## Table of contents

1. [What crafty is (and is not)](#what-crafty-is-and-is-not)
2. [The gap it fills — honestly](#the-gap-it-fills--honestly)
3. [Competitive positioning](#competitive-positioning)
4. [Design principles](#design-principles)
5. [Quickstart](#quickstart)
6. [The binary grammar (the moat)](#the-binary-grammar-the-moat)
7. [Template schema](#template-schema)
8. [Matchers and extractors](#matchers-and-extractors)
9. [Control flow](#control-flow)
10. [Footprint, tempo, and modes](#footprint-tempo-and-modes)
11. [Listener mode](#listener-mode)
12. [The interactive console](#the-interactive-console)
13. [Export: runnable artifacts for any OS/arch](#export-runnable-artifacts-for-any-osarch)
14. [The template library](#the-template-library)
15. [Repository layout](#repository-layout)
16. [What's built vs deferred](#whats-built-vs-deferred)
17. [Development](#development)
18. [Authorized use](#authorized-use)

---

## What crafty is (and is not)

**Is:** a declarative + interactive engine for modelling arbitrary TCP/UDP protocol exchanges in either direction (client or listener), with byte-level payload control, a bidirectional binary grammar, bounded iteration, concurrent session management, and tunable footprint.

**Is not:** a port scanner (it is *port-aware*, not a scanner), a packet-crafting library (raw sockets are a deferred mode), or a "Swiss-army knife." The sharp edge is one sentence:

> **A declarative, portable grammar for arbitrary TCP/UDP protocols that spans both client and listener, drivable as a template or a live session.**

That precise claim is what no existing tool delivers. Everything else is supporting plumbing, kept subordinate on purpose.

---

## The gap it fills — honestly

Every offensive network tool bottoms out at TCP/UDP. The trivial part is the socket; the valuable part is modelling the **application protocol on top**. Tools either hard-code that for one protocol (Responder → LLMNR/NBT-NS; Kerbrute → Kerberos) or make you write code.

Who already generalises part of this:

- **Nuclei's `network` type** generalised the *client* side declaratively — but it is **client-only**, weak at binary, and has no session model.
- **Dementor** ("Responder 2.0") generalised the *listener* side via TOML + Python plugins — but it is **listener-only** and scoped to a known protocol set.
- **Metasploit** already does **both directions, concurrent, session/job-managed, from one console** (`auxiliary/scanner/*`, `auxiliary/server/capture/*`, `auxiliary/spoof/*`). crafty borrows its `use/set/run/sessions/jobs` UX. **So "bidirectional + sessions" is not the novelty** — Metasploit has shipped it for years. The difference is that each Metasploit module is hand-written Ruby; adding a protocol means writing a module.
- **Impacket** likewise does both directions (example clients + `smbserver.py` etc.), but per-protocol in Python.

**The white space, stated precisely:** nobody has a *declarative, portable template grammar* for *arbitrary* protocols that works in *both* directions, with a *real binary grammar*, drivable as a template **or** a live session. Nuclei is declarative but client-only; Dementor is config-driven but listener-only; Metasploit/Impacket span both but via code. That intersection is crafty.

---

## Competitive positioning

| Tool | Direction | Interface | Arbitrary protocols | Binary modelling | Sessions / concurrency | Listener |
|---|---|---|---|---|---|---|
| **Nuclei** `network` | Client only | YAML templates | Partial (hex + DSL, JS/Code escape) | Weak (hex strings) | No | No |
| **Dementor** | Listener only | TOML + Python plugins | No (fixed set, extensible via code) | N/A | Per-protocol servers | Yes |
| **Responder** | Listener only | CLI flags | No (hardcoded) | N/A | Single process | Yes (blanket) |
| **Metasploit** | **Both** | Ruby modules + msfconsole | No (per-protocol module) | Full (you write Ruby) | **Yes (jobs + sessions)** | Yes |
| **Impacket** | Both | Python scripts/library | No (per-protocol) | Full (you write it) | No | Yes |
| **Scapy** | Both (raw) | Python code | Yes (code-heavy) | Full (you write it) | No | Manual |
| **crafty** | **Both** | **Templates + console** | **Yes (declarative)** | **Bidirectional grammar** | **Yes (named, concurrent)** | **Yes (selective)** |

**Marketing consequence:** lead with *declarative + arbitrary + bidirectional*, and with **listener selectivity** as the concrete operational win. Do **not** lead with "bidirectional + sessions" (Metasploit owns it) or "better Responder" (Dementor owns extensible poisoning).

---

## Design principles

1. **One model, two front doors.** A template is a frozen session; a session is a live template. The console and the YAML file serialise/deserialise the *same* object.
2. **The declarative grammar is the moat.** Behaviour lives in data. This is what simultaneously buys arbitrary-protocol modelling *and* tunable footprint.
3. **Operator-controlled footprint, never "stealth."** crafty gives you dials for tempo and selectivity so you can match an engagement's noise budget. It never claims invisibility — completed TCP handshakes are logged; poisoning puts wrong answers on the wire that canaries catch. Honesty here is a feature.
4. **Bounded by default.** Every loop has a hard cap (`over` list length, `repeat`, or `until` + `max`). No unbounded `while` in data.
5. **Config stops where programming begins.** Pack, parse, iterate, and compute *values* (including checksums/digests) declaratively; anything needing real control flow is a `script` step — a line held deliberately (see [deferred](#whats-built-vs-deferred)).
6. **The round-trip rule.** Every console `set` maps to a template field, so `save` writes it back out identically. `save` serialises **config, not runtime state** (loop position, loot, sockets do not round-trip).

---

## Quickstart

**Run a template (template mode):**

```bash
crafty run templates/client/banner-ssh.yaml -t 10.0.0.5
crafty run templates/listener/selective-udp-responder.yaml --set LPORT=5355 -I eth0
crafty run templates/client/length-prefixed-probe.yaml -t 10.0.0.5 --mode dry-run
```

**Validate / understand before running:**

```bash
crafty lint templates/client/length-prefixed-probe.yaml
crafty explain templates/client/length-prefixed-probe.yaml
```

**Interactive console:**

```text
$ crafty
crafty > use length-prefixed-probe
crafty (length-prefixed-probe) > set RHOST 10.0.0.5
crafty (length-prefixed-probe) > run
crafty > use selective-udp-responder
crafty (selective-udp-responder) > set LPORT 5355
crafty (selective-udp-responder) > run -j
[*] Session 2 opened (udp/listener -> 0.0.0.0:5355)
crafty > sessions
```

---

## The binary grammar (the moat)

Three features turn "declarative for the easy cases, script for the real ones" into "declarative for most real cases." They are the core of the engine, not add-ons.

### 1. Bidirectional structs — define once, pack *and* parse

A single definition serialises outbound and parses inbound. The length prefix writes itself on pack and is used to slice on parse.

```yaml
structs:
  Greeting:
    - { name: magic,   type: bytes, len: 4 }
    - { name: version, type: u16be }
    - { name: length,  type: u16be, value: "len(body)" }   # computed on pack
    - { name: body,    type: bytes, len: "length" }        # length ref on parse

flow:
  - send: { bytes: "{{struct:Greeting(magic=b'CRFT', version=1, body=b'hello')}}" }
```

Field types: `u8/i8 … u64/i64` (be/le), `bytes`, `str`, `rest`. Nested TLV/ASN.1 still belong in a `script` step — that boundary is deliberate.

### 2. Framing — the recv loop reads one message for you

Stop hand-coding "read N → interpret length → read the rest."

```yaml
recv: { type: length-prefix, offset: 0, size: 4, endian: be, counts: body, adjust: 0 }
recv: { type: delimiter, delimiter: "\r\n", include: true }
recv: { read: 1024 }                       # fixed
```

`counts: body` (length = bytes after the header) or `total` (length includes the header). Something Nuclei's network type cannot express.

### 3. Bounded value-expressions + a crypto/encoding library

Pure expressions for *computed values* — arithmetic, slicing, field refs — with no control flow. A checksum or digest no longer forces a script step.

```yaml
send: { bytes: "{{= concat(u16be(len(body)), body, u32be(crc32(body)))}}" }
send: { bytes: "{{= concat(challenge, sha256(concat(secret, challenge)))}}" }
```

Helpers: `u8/u16be/u16le/u32be/u32le/u64…`, `pack`, `concat`, `len`, `ip4`, `hex2b/b2hex`, `b64e/b64d`, `zlib_c/zlib_d`, `crc32`, `crc16`, `md5/sha1/sha256/sha512`, `hmac`, `rand_bytes/rand_str/rand_int`. The evaluator is AST-allow-listed and sandboxed (no attribute access, imports, lambdas, or loops).

### The DSL that ties it together

Inside any `bytes:` field:

| Syntax | Meaning |
|---|---|
| `\x00\x01`, `\r\n` | literal bytes / escapes |
| `{{hex:504b0304}}` | hex literal |
| `{{u16be:EXPR}}` … | fixed-width integer |
| `{{len16be:field}}` … | length prefix of a field (`len8/16/32`, be/le) |
| `{{bytes:var}}` / `{{str:EXPR}}` | insert a value |
| `{{randbytes:16}}` / `{{randstr:8}}` | randomised input |
| `{{pack:"!IH", a, b}}` | struct-style packing |
| `{{struct:Name(f=EXPR, ...)}}` | build bytes from a defined struct |
| `{{= EXPR}}` | evaluate a bounded expression → bytes |

---

## Template schema

Clients and listeners share a header and differ below it.

### Client

```yaml
id: length-prefixed-probe
info: { name: "Length-prefixed probe", author: isukasanuj, severity: info, tags: [tcp, binary] }
transport: tcp              # tcp | udp
role: client
target: "{{RHOST}}:{{RPORT|9999}}"
socket: { timeout: 5s, tls: false }
tempo: { rate: 5/s, jitter: 0-200ms, preflight: true }
defaults: { PAYLOAD: PING }   # seeds operator params AND runtime variables
structs: { ... }
flow:
  - send: { bytes: "{{struct:Msg(payload=PAYLOAD)}}" }
    recv: { type: length-prefix, size: 2, endian: be, counts: body }
    matchers: [ { type: len, part: data, min: 3 } ]
    on_match: { log: "reply from {{RHOST}}", extract: { body: "{{data[2:]}}" } }
```

### Listener

```yaml
transport: udp
role: listener
mode: active                # active | analyze | dry-run
socket:
  bind: "0.0.0.0:{{LPORT|5355}}"
  options: [SO_REUSEADDR]
  multicast: { group: 224.0.0.252, interface: "{{IFACE|0.0.0.0}}" }
selectivity:
  respond_to: ["*.corp.local"]
  ignore: ["*-canary*", "wpad*"]
  max_responses_per_host: 3
  cooldown: 30s
on_receive:
  extract: [ { name: query, type: dsl, expression: "str(strip(data))" } ]
  respond: { bytes: "{{= concat(b'ANSWER ', bytes(query))}}" }
  capture: { to: "loot/hits.txt", value: "{{query}} <- {{peer}}" }
```

**Two placeholder namespaces:** uppercase `{{RHOST}}`/`{{RPORT|88}}` are **operator parameters** (filled in config scalars from `--set`/console `set`/`defaults:`); `{{...}}` inside `bytes:` is the **binary DSL** (runtime variables). Params are also exposed as runtime variables, so `bytes:` can use `{{RHOST}}` too.

---

## Matchers and extractors

**Matchers** (`matchers-condition: and | or`, any matcher may set `negative: true`):

- `binary` — hex at optional `offset`/`length`
- `word` — substring(s), `encoding: hex`, `condition: and|or`
- `regex` — pattern(s)
- `len` — `min`/`max`/`value`
- `status` — exchange outcome (`_status`)
- `dsl` — bounded expression over captured values + parts

**Extractors** → bind variables for later steps: `binary` (offset/length), `regex` (group), `dsl` (expression), `const`. Plus the `on_match.extract` sugar: `{ valid_user: "{{user}}" }`.

`part` values: `data` (last read), `request` (last sent), `all` (everything read).

---

## Control flow

Declarative, bounded, intent-named:

```yaml
- loop: { over: "{{USERS}}", as: user, max: 500, do: [ ... ] }   # file / inline list
- loop: { until: { matcher: success }, max: 10, delay: 2s, do: [ ... ] }
- loop: { repeat: 5, delay: 1s, do: [ ... ] }
```

Every form has a hard bound. No inline `if/else`, no `goto`, no unbounded loop — that logic goes in a `script` step.

---

## Footprint, tempo, and modes

| Knob | Applies to | Effect |
|---|---|---|
| `rate` | client | requests/sec (token bucket) |
| `jitter` | client/listener | randomised delay (`0-200ms`) |
| `preflight` | client (TCP) | confirm the port is open before spending the flow |
| `respond_to` / `ignore` | listener | which queries/victims to answer |
| `max_responses_per_host` / `cooldown` | listener | throttle poisoning noise |

**Modes (operational posture):** `active` (exchange for real), `analyze` (listener observes, never responds), `dry-run` (resolve the whole flow and emit the bytes that *would* go on the wire — send nothing). `analyze` and `dry-run` make crafty safe to run on a live engagement.

> **Honesty boundary:** these lower the odds of tripping *noisy* detections. They do not defeat a blue team actively hunting. crafty markets "tune your footprint to the noise budget," never "undetectable."

---

## Listener mode

The half Nuclei can't do, where crafty beats Responder on *control*:

- **Bind** with the right socket options; **multicast membership** (`IP_ADD_MEMBERSHIP`) for LLMNR (`224.0.0.252`) / mDNS (`224.0.0.251`).
- **Selective response** — the operational win over Responder's blanket answering: answer only named patterns, skip canary patterns, cap per host, cool down. This is "quiet by configuration."
- **Capture** — per-session loot to disk, plus a structured JSONL event stream (every send/recv/match/capture) for evidence and pipelines.

---

## The interactive console

Verbs mirror `msfconsole` / `ligolo-ng`:

| Command | Purpose |
|---|---|
| `use <template>` | load a template as the active context |
| `set` / `unset <opt> <val>` | set a parameter or config option |
| `run` / `run -j` | run foreground / background job |
| `sessions` / `sessions -i <id>` | list / interact |
| `background` / `kill <id>` / `jobs` | manage sessions |
| `save [<id>] <file>` | serialise config back to a template (round-trip) |
| `show options [-a]` / `show config` | see settable keys / resolved config |
| `search <query>` | find templates (`tag:`, `role:`, `proto:`, substring) |
| `explain [<template>]` | plain-English description |
| `export <os/arch>[,…]` / `export pyz\|exe <file>` | build a runnable artifact |
| `loot` / `banner` / `help` / `exit` | — |

Option keys follow a naming convention (`TEMPO_*`, `SEL_*`, `MCAST_*`, `TLS_*`) and each maps to a template field, per the round-trip rule.

---

## Export: runnable artifacts for any OS/arch

Turn a template (with your options baked in) into something you hand to a target.

```bash
crafty export templates/client/banner-ssh.yaml --target linux/arm64,windows/amd64 --set RHOST=10.0.0.5
crafty export templates/client/banner-ssh.yaml --format pyz -o probe.pyz
crafty export templates/client/banner-ssh.yaml --format exe        # current OS only
crafty export --list-targets
```

Three formats, chosen honestly:

| Format | Needs on target | Cross-OS/arch from one machine | Shape |
|---|---|---|---|
| **bundle** (default, `--target`) | **nothing** | **yes** — Windows/Linux/macOS × x64/x86/arm64 | zip (Windows) / tar.gz (POSIX) with an embedded CPython + launcher |
| `pyz` | a Python 3 | yes (any Python host) | one `.pyz` file |
| `exe` | nothing | **no** — current OS/arch only (PyInstaller) | one native file |

**How the bundle works:** it downloads a prebuilt, relocatable CPython *for the chosen target* from [`python-build-standalone`](https://github.com/astral-sh/python-build-standalone) (cached after first use) and packages it with the engine + your template. Unpacking a runtime executes no target code, so a Windows host can assemble a Linux/arm64 bundle with **no emulation and no container** — there is no cross-compilation; crafty only repackages an already-compiled interpreter. POSIX targets ship `.tar.gz` so the runtime's execute bits and symlinks survive.

**The honest limit:** a true single native file for *arbitrary* OS/arch from one host is not achievable for Python — that's the (deferred) Go-port story. The bundle is the pragmatic answer: native, zero-install, any target; it's a zip, not one `.exe`.

Run a bundle on the target: unzip and run the launcher (`crafty-<name>-<os>-<arch>.cmd` on Windows, `./crafty-<name>-<os>-<arch>` on POSIX). Runtime overrides still work: `--set RHOST=… --mode dry-run --explain`.

---

## The template library

**109 templates** (100 client · 9 listener), each labelled with a confidence tier in its header:

- **T1 — verified (81):** uses only engine mechanisms the test suite covers (banner grabs, line/text probes, HTTP path/exposure checks, length-prefixed binary, UDP text). Schema-valid + dry-run-clean + category-smoke-tested.
- **T2 — constructed from spec (20):** payload built from documented protocol constants (DNS, NTP, SNMP, Modbus, MQTT, RDP, MSSQL, CoAP, TFTP, WSD, SIP, git). Schema-valid, but **not reproduced against a live service** — each file says so.
- **T3 — draft (2):** poisoners (mDNS, NBT-NS) needing a live target; default to safe `analyze` mode. (The curated `llmnr-poison` is the worked example.)

Coverage: HTTP probes/exposures (`.git`, `.env`, actuator, server-status, Tomcat/Jenkins/GitLab/Grafana/Elasticsearch/Docker-API…), banner grabs (SSH/FTP/SMTP/IMAP/MySQL/VNC/rsync…), text probes (Redis/Memcached/WHOIS/Finger/ZooKeeper…), UDP (DNS/NTP/SNMP/SSDP/mDNS/CoAP/TFTP/NetBIOS…), TCP-binary (Modbus/MQTT/RDP/MSSQL/JetDirect + struct/framing showcases), and listeners (selective responders, honeypots, poisoner drafts).

The whole set is generated from `tools/generate_library.py` (reproducible and reviewable) and guarded by `tests/test_library.py`, which fails if any template ever stops linting or resolving.

> Every template is **lint-valid and dry-run-clean**. That is a real, automated bar — but it is *not* the same as "reproduced against a live service." T2/T3 say so explicitly. Validate before you rely on one in an engagement.

---

## Repository layout

```text
crafty/
├── crafty/
│   ├── cli.py              # template mode: run / lint / explain / export / console
│   ├── banner.py           # authorized-use banner + explain()
│   ├── export.py           # pyz / self-contained bundle / native exe
│   ├── console/            # interactive REPL (repl.py) + helpers (commands.py)
│   ├── core/
│   │   ├── expr.py         # bounded value-expression engine (sandboxed)
│   │   ├── structs.py      # bidirectional binary structs
│   │   ├── framing.py      # length-prefix / delimiter / fixed framing
│   │   ├── dsl.py          # the bytes: DSL resolver
│   │   ├── matchers.py / extractors.py
│   │   ├── transport.py    # tcp/udp client + listener, setsockopt, multicast, TLS
│   │   ├── engine.py       # flow executor (steps, bounded loops, modes)
│   │   ├── session.py      # Session object, registry, round-trip save
│   │   └── tempo.py        # rate / jitter / preflight
│   ├── listener/           # selectivity (quiet-by-config)
│   ├── loot/               # capture writer + structured event stream
│   └── schema/             # template parse / validate / params
├── templates/{client,listener}/   # the 109-template library
├── tools/generate_library.py      # reproducible library generator
├── tests/                          # 284 tests
├── wordlists/ · docs/ · LICENSE · pyproject.toml
```

---

## What's built vs deferred

**Built & tested (v0):** the binary grammar (expr/structs/framing/DSL), tcp/udp client + listener, bounded loops, matchers/extractors, selectivity, tempo + preflight, client TLS, the three modes, sessions + registry, CLI, console, export (pyz/bundle/exe), 109 templates, 284 tests.

**Deferred (with the decision made):**

- **`script` step → Starlark.** Resolves the open "Lua vs Starlark" question: Starlark (Go-portable, deterministic, trivially sandboxed). The step is parsed and currently skipped with a log.
- **Persistence = config-only round-trip.** Resolves the open "YAML vs session-state format" question: `save` writes config, not runtime state. No separate state format.
- **`tempo.concurrency`** is parsed but the v0 engine runs sequentially.
- **Listener rogue-TLS**, **capture-to-template** (`crafty learn`), **wizard** (`crafty new`), **named config profiles**, **cross-session variable passing** (only via `save` today), and **raw-socket mode** (SYN/spoof/malformed — a separate v2 product needing root) are not yet implemented.
- **Go port** for true single-file cross-compiled binaries — the long-term distribution story.

---

## Development

```bash
pip install -e ".[dev]"
pytest -q                          # 284 tests
python tools/generate_library.py   # regenerate the template library
```

---

## Authorized use

crafty is offensive tooling intended **solely for lawful use**: your own lab, or assessments where you hold explicit written authorization and defined scope. Poisoning and spraying templates put real attacks on real wires.

- An "authorized testing only" banner prints on console start and on `run`.
- Safe defaults: listeners are selective (not blanket); clients are conservative on rate and confirmed-open ports; poisoner templates default to `analyze`.
- See [`LICENSE`](LICENSE) for the lawful-use and no-warranty notice.

Built by [@isukasanuj](https://github.com/isukasanuj). Issues and PRs welcome at [github.com/isukasanuj/crafty](https://github.com/isukasanuj/crafty).
