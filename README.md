# crafty

> Craft any TCP/UDP exchange — client *or* listener — as a declarative template or a live console session. One engine, one model, two front doors.

![status](https://img.shields.io/badge/status-v0%20prototype-orange)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![tests](https://img.shields.io/badge/tests-284%20passing-brightgreen)
![templates](https://img.shields.io/badge/templates-109-blueviolet)
![license](https://img.shields.io/badge/license-see%20LICENSE-lightgrey)

**crafty** is a protocol-crafting engine for authorized network security testing. You describe a byte-level exchange over TCP or UDP — the socket setup, the send/recv state machine, the matchers and extractors — and crafty runs it, either from a shareable YAML template or interactively from a session-based console.

It covers the two halves no single *declarative* tool unifies: **client probes** and **listener / rogue-service attacks**, for arbitrary protocols, with a real **bidirectional binary grammar** and **operator-controlled footprint**.

> ⚠️ **For authorized security testing only.** Poisoning and probing templates put real attacks on real wires. See [Authorized use](#authorized-use).

<!-- TODO: drop a short asciinema/GIF of `crafty` console here — it sells the tool faster than any paragraph. -->

---

## Table of contents

- [Quickstart](#quickstart)
- [A 60-second example](#a-60-second-example)
- [Why crafty?](#why-crafty)
- [Features](#features)
- [The binary grammar (the moat)](#the-binary-grammar-the-moat)
- [Writing templates](#writing-templates)
- [Footprint, tempo & modes](#footprint-tempo--modes)
- [Listener mode](#listener-mode)
- [The interactive console](#the-interactive-console)
- [Export: runnable artifacts](#export-runnable-artifacts)
- [Template library](#template-library)
- [Status: built vs deferred](#status-built-vs-deferred)
- [Repository layout](#repository-layout)
- [Development](#development)
- [Authorized use](#authorized-use)
- [License & credits](#license--credits)

---

## Quickstart

```bash
git clone https://github.com/isukasanuj/crafty
cd crafty

python -m venv .venv
source .venv/bin/activate        # POSIX
# .venv\Scripts\activate         # Windows (PowerShell / cmd)

pip install -e .
crafty --help
```

Run your first template:

```bash
crafty run templates/client/banner-ssh.yaml -t 10.0.0.5
```

Or drop into the console:

```bash
crafty
```

Python 3.9+. No external services required to run the engine.

---

## A 60-second example

A length-prefixed binary probe — the kind of thing you'd normally hand-write in Scapy. Define the message **once**; crafty packs it outbound and slices it inbound.

```yaml
id: length-prefixed-probe
info: { name: "Length-prefixed probe", author: isukasanuj, severity: info, tags: [tcp, binary] }
transport: tcp
role: client
target: "{{RHOST}}:{{RPORT|9999}}"
tempo: { rate: 5/s, jitter: 0-200ms, preflight: true }

structs:
  Msg:
    - { name: magic,  type: bytes, len: 4 }
    - { name: length, type: u16be, value: "len(body)" }   # computed on pack
    - { name: body,   type: bytes, len: "length" }         # length-ref on parse

flow:
  - send: { bytes: "{{struct:Msg(magic=b'CRFT', body=PAYLOAD)}}" }
    recv: { type: length-prefix, size: 2, offset: 4, endian: be, counts: body }
    matchers: [ { type: len, part: data, min: 3 } ]
    on_match: { log: "reply from {{RHOST}}", extract: { body: "{{data[6:]}}" } }
```

```bash
# see exactly what hits the wire — send nothing
crafty run templates/client/length-prefixed-probe.yaml -t 10.0.0.5 --mode dry-run

# understand it in plain English before you trust it
crafty explain templates/client/length-prefixed-probe.yaml

# run it for real
crafty run templates/client/length-prefixed-probe.yaml -t 10.0.0.5
```

The framed `recv` loop reads one whole message for you — no hand-coded "read header → interpret length → read the rest." That's something Nuclei's `network` type can't express.

---

## Why crafty?

Every offensive network tool bottoms out at TCP/UDP. The trivial part is the socket; the valuable part is modelling the **application protocol** on top. Existing tools either hard-code that for one protocol or make you write code:

| Tool | Direction | Interface | Arbitrary protocols | Binary modelling | Sessions | Listener |
|---|---|---|---|---|---|---|
| **Nuclei** `network` | Client only | YAML templates | Partial (hex + DSL, JS/Code escape) | Weak (hex strings) | No | No |
| **Dementor** | Listener only | TOML + Python plugins | No (fixed set, extensible via code) | N/A | Per-protocol | Yes |
| **Responder** | Listener only | CLI flags | No (hardcoded) | N/A | Single process | Yes (blanket) |
| **Metasploit** | Both | Ruby modules + msfconsole | No (per-protocol module) | Full (write Ruby) | Yes | Yes |
| **Impacket** | Both | Python scripts/library | No (per-protocol) | Full (write it) | No | Yes |
| **Scapy** | Both (raw) | Python code | Yes (code-heavy) | Full (write it) | No | Manual |
| **crafty** | **Both** | **Templates + console** | **Yes (declarative)** | **Bidirectional grammar** | **Yes (named)** | **Yes (selective)** |

**The honest version of the pitch:** "bidirectional + sessions" is *not* the novelty — Metasploit has shipped that for years, and Impacket spans both directions too. But in both, adding a protocol means writing a module. Nuclei is declarative but client-only; Dementor is config-driven but listener-only.

> The white space, stated precisely: **a declarative, portable template grammar for arbitrary protocols that works in both directions, with a real binary grammar, drivable as a template or a live session.** That intersection is crafty.

So the headline is **declarative + arbitrary + bidirectional**, with **listener selectivity** as the concrete operational win — not "better Responder" and not "msfconsole for sockets."

---

## Features

- **Bidirectional binary grammar** — define a struct once, pack it outbound and parse it inbound; length prefixes write and resolve themselves.
- **Framed reads** — `length-prefix`, `delimiter`, or fixed; the recv loop assembles one message for you.
- **Bounded value-expressions** — compute checksums, digests, and encodings (`crc32`, `sha256`, `hmac`, `b64`, `zlib`, …) declaratively, no script step, no `eval`.
- **Both directions, one schema** — clients and listeners share a header and diverge below it.
- **Concurrent sessions** — run a listener and several probes at once; background, interact, `save` any of them back to a template.
- **Operator-controlled footprint** — rate, jitter, preflight, and listener selectivity to match an engagement's noise budget.
- **Three modes** — `active`, `analyze` (observe only), `dry-run` (emit the bytes, send nothing).
- **Export** — turn a template into a zero-install runnable bundle for another OS/arch, a `.pyz`, or a native `.exe`.
- **109-template library** — each labelled with an honest confidence tier.
- **284 tests** — the library fails CI the moment any template stops linting or resolving.

---

## The binary grammar (the moat)

Three features turn *"declarative for the easy cases, script for the real ones"* into *"declarative for most real cases."* They are the core of the engine.

### 1. Bidirectional structs — define once, pack and parse

```yaml
structs:
  Greeting:
    - { name: magic,   type: bytes, len: 4 }
    - { name: version, type: u16be }
    - { name: length,  type: u16be, value: "len(body)" }   # computed on pack
    - { name: body,    type: bytes, len: "length" }         # length-ref on parse
```

Field types: `u8/i8 … u64/i64` (be/le), `bytes`, `str`, `rest`. Nested TLV / ASN.1 still belong in a script step — that boundary is deliberate.

### 2. Framing — the recv loop reads one message

```yaml
recv: { type: length-prefix, offset: 0, size: 4, endian: be, counts: body, adjust: 0 }
recv: { type: delimiter, delimiter: "\r\n", include: true }
recv: { read: 1024 }                       # fixed
```

`counts: body` (length counts the bytes after the header) or `counts: total` (length includes the header).

### 3. Bounded value-expressions + a crypto/encoding library

```yaml
send: { bytes: "{{= concat(u16be(len(body)), body, u32be(crc32(body)))}}" }
send: { bytes: "{{= concat(challenge, sha256(concat(secret, challenge)))}}" }
```

Helpers: `u8/u16be/u16le/u32be/u32le/u64…`, `pack`, `concat`, `len`, `ip4`, `hex2b/b2hex`, `b64e/b64d`, `zlib_c/zlib_d`, `crc32`, `crc16`, `md5/sha1/sha256/sha512`, `hmac`, `rand_bytes/rand_str/rand_int`. The evaluator is **AST-allow-listed and sandboxed** — no attribute access, imports, lambdas, or loops.

<details>
<summary><b>The DSL that ties it together</b> (inside any <code>bytes:</code> field)</summary>

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

</details>

---

## Writing templates

Clients and listeners share a header and differ below it.

<details>
<summary><b>Client template</b></summary>

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

</details>

<details>
<summary><b>Listener template</b></summary>

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

</details>

**Two placeholder namespaces.** Uppercase `{{RHOST}}` / `{{RPORT|88}}` are **operator parameters** (filled from `--set`, console `set`, or `defaults:`). `{{...}}` inside `bytes:` is the **binary DSL** (runtime variables). Parameters are also exposed as runtime variables, so `bytes:` can reference `{{RHOST}}` too.

<details>
<summary><b>Matchers, extractors & control flow</b></summary>

**Matchers** (`matchers-condition: and | or`; any matcher may set `negative: true`):

- `binary` — hex at optional `offset`/`length`
- `word` — substring(s), `encoding: hex`, `condition: and|or`
- `regex` — pattern(s)
- `len` — `min`/`max`/`value`
- `status` — exchange outcome (`_status`)
- `dsl` — bounded expression over captured values + parts

**Extractors** → bind variables for later steps: `binary` (offset/length), `regex` (group), `dsl` (expression), `const`. Plus the `on_match.extract` sugar: `{ valid_user: "{{user}}" }`.

`part` values: `data` (last read), `request` (last sent), `all` (everything read).

**Control flow** — declarative, bounded, intent-named:

```yaml
- loop: { over: "{{USERS}}", as: user, max: 500, do: [ ... ] }   # file / inline list
- loop: { until: { matcher: success }, max: 10, delay: 2s, do: [ ... ] }
- loop: { repeat: 5, delay: 1s, do: [ ... ] }
```

Every form has a hard bound. No inline `if/else`, no `goto`, no unbounded loop — that logic goes in a (deferred) script step.

</details>

---

## Footprint, tempo & modes

| Knob | Applies to | Effect |
|---|---|---|
| `rate` | client | requests/sec (token bucket) |
| `jitter` | client/listener | randomised delay (`0-200ms`) |
| `preflight` | client (TCP) | confirm the port is open before spending the flow |
| `respond_to` / `ignore` | listener | which queries/victims to answer |
| `max_responses_per_host` / `cooldown` | listener | throttle poisoning noise |

**Modes.** `active` (exchange for real), `analyze` (listener observes, never responds), `dry-run` (resolve the whole flow and emit the bytes that *would* go on the wire — send nothing). `analyze` and `dry-run` make crafty safe to run on a live engagement.

> **Honesty boundary:** these lower the odds of tripping *noisy* detections. They do **not** defeat a blue team actively hunting — completed TCP handshakes are logged, and poisoning puts wrong answers on the wire that canaries catch. crafty markets *"tune your footprint to the noise budget,"* never *"undetectable."*

---

## Listener mode

The half Nuclei can't do, where crafty beats Responder on **control**:

- **Bind** with the right socket options; **multicast membership** (`IP_ADD_MEMBERSHIP`) for LLMNR (`224.0.0.252`) / mDNS (`224.0.0.251`).
- **Selective response** — the operational win over Responder's blanket answering: answer only named patterns, skip canary patterns, cap per host, cool down. This is *quiet by configuration*.
- **Capture** — per-session loot to disk, plus a structured JSONL event stream (every send/recv/match/capture) for evidence and pipelines.

---

## The interactive console

Verbs mirror `msfconsole` / `ligolo-ng`, so the muscle memory is already there.

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

| Command | Purpose |
|---|---|
| `use <template>` | load a template as the active context |
| `set` / `unset <opt> <val>` | set a parameter or config option |
| `run` / `run -j` | run foreground / background job |
| `sessions` / `sessions -i <id>` | list / interact |
| `background` / `kill <id>` / `jobs` | manage sessions |
| `save [<id>] <file>` | serialise config back to a template (round-trip) |
| `show options [-a]` / `show config` | settable keys / resolved config |
| `search <query>` | find templates (`tag:`, `role:`, `proto:`, substring) |
| `explain [<template>]` | plain-English description |
| `export <os/arch>` / `export pyz\|exe <file>` | build a runnable artifact |
| `loot` / `banner` / `help` / `exit` | — |

Option keys follow a naming convention (`TEMPO_*`, `SEL_*`, `MCAST_*`, `TLS_*`) and each maps to a template field — the **round-trip rule**: every `set` can be `save`d back out identically. `save` serialises *config*, not runtime state (loop position, loot, and sockets do not round-trip).

---

## Export: runnable artifacts

Turn a template (with your options baked in) into something you hand to a target.

```bash
crafty export templates/client/banner-ssh.yaml --target linux/arm64,windows/amd64 --set RHOST=10.0.0.5
crafty export templates/client/banner-ssh.yaml --format pyz -o probe.pyz
crafty export templates/client/banner-ssh.yaml --format exe        # current OS only
crafty export --list-targets
```

| Format | Needs on target | Cross-OS/arch from one machine | Shape |
|---|---|---|---|
| `bundle` (default, `--target`) | nothing | **yes** — Windows/Linux/macOS × x64/x86/arm64 | zip (Windows) / tar.gz (POSIX) with an embedded CPython + launcher |
| `pyz` | a Python 3 | yes (any Python host) | one `.pyz` file |
| `exe` | nothing | no — current OS/arch only (PyInstaller) | one native file |

The bundle downloads a prebuilt, relocatable CPython for the chosen target from [python-build-standalone](https://github.com/indygreg/python-build-standalone) (cached after first use) and packages it with the engine + your template. There's **no cross-compilation** — crafty only repackages an already-compiled interpreter — so a Windows host can assemble a Linux/arm64 bundle with no emulation or container. POSIX targets ship `.tar.gz` so execute bits and symlinks survive.

> **The honest limit:** a true single native file for arbitrary OS/arch from one host isn't achievable for Python — that's the deferred Go-port story. The bundle is the pragmatic answer: native, zero-install, any target; it's a zip, not one `.exe`.

---

## Template library

**109 templates (100 client · 9 listener)**, each labelled with a confidence tier in its header:

| Tier | Count | Meaning |
|---|---|---|
| **T1 — verified** | 81 | uses only engine mechanisms the test suite covers (banner grabs, line/text probes, HTTP checks, length-prefixed binary, UDP text). Schema-valid + dry-run-clean + category-smoke-tested. |
| **T2 — from spec** | 20 | payload built from documented protocol constants (DNS, NTP, SNMP, Modbus, MQTT, RDP, MSSQL, CoAP, TFTP, WSD, SIP, git). Schema-valid, **not** reproduced against a live service — each file says so. |
| **T3 — draft** | 2 | poisoners (mDNS, NBT-NS) needing a live target; default to safe `analyze` mode. |

**Coverage:** HTTP probes/exposures (`.git`, `.env`, actuator, server-status, Tomcat/Jenkins/GitLab/Grafana/Elasticsearch/Docker-API…), banner grabs (SSH/FTP/SMTP/IMAP/MySQL/VNC/rsync…), text probes (Redis/Memcached/WHOIS/Finger/ZooKeeper…), UDP (DNS/NTP/SNMP/SSDP/mDNS/CoAP/TFTP/NetBIOS…), TCP-binary (Modbus/MQTT/RDP/MSSQL/JetDirect + struct/framing showcases), and listeners (selective responders, honeypots, poisoner drafts).

The whole set is generated from `tools/generate_library.py` (reproducible and reviewable) and guarded by `tests/test_library.py`, which fails if any template ever stops linting or resolving.

> Every template is **lint-valid and dry-run-clean** — a real automated bar, but **not** the same as "reproduced against a live service." T2/T3 say so explicitly. Validate before you rely on one in an engagement.

---

## Status: built vs deferred

**Built & tested (v0):** the binary grammar (expr/structs/framing/DSL), tcp/udp client + listener, bounded loops, matchers/extractors, selectivity, tempo + preflight, client TLS, the three modes, sessions + registry, CLI, console, export (pyz/bundle/exe), 109 templates, 284 tests.

**Deferred — with the decision made:**

- **script step → Starlark** (resolves the old "Lua vs Starlark" question: Go-portable, deterministic, trivially sandboxed). Parsed today, skipped with a log.
- **Persistence = config-only round-trip** — `save` writes config, not runtime state. No separate state format.
- `tempo.concurrency` is parsed but the v0 engine runs sequentially.
- Listener rogue-TLS, capture-to-template (`crafty learn`), wizard (`crafty new`), named config profiles, and cross-session variable passing (only via `save` today) — not yet implemented.
- **Raw-socket mode** (SYN/spoof/malformed) — a separate v2 product needing root.
- **Go port** for true single-file cross-compiled binaries — the long-term distribution story.

---

## Repository layout

<details>
<summary>Show the tree</summary>

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

</details>

---

## Development

```bash
pip install -e ".[dev]"
pytest -q                          # 284 tests
python tools/generate_library.py   # regenerate the template library
```

Issues and PRs welcome.

---

## Authorized use

crafty is offensive tooling intended **solely for lawful use**: your own lab, or assessments where you hold explicit written authorization and defined scope. Poisoning and spraying templates put real attacks on real wires.

- An "authorized testing only" banner prints on console start and on `run`.
- Safe defaults: listeners are **selective** (not blanket); clients are conservative on rate and confirmed-open ports; poisoner templates default to `analyze`.
- See [`LICENSE`](LICENSE) for the lawful-use and no-warranty notice.

---

## License & credits

See [`LICENSE`](LICENSE). Built by [@isukasanuj](https://github.com/isukasanuj) · [github.com/isukasanuj/crafty](https://github.com/isukasanuj/crafty)
