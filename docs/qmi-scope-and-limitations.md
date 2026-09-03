# QMI passthrough — scope & limitations

This is the honest "supported / tested / limitations" statement for the QMI
passthrough feature (opt-in `QCSERIALD_QMI_SOCKET=1`), linked from the
[README's QMI Passthrough section](../README.md#qmi-passthrough-opt-in).

QMI passthrough exposes a modem's QMI (UIM) channel on macOS as a
frame-preserving unix socket, so a pure-userspace LPA can drive the eUICC
without libqmi or the Linux `cdc-wdm` / `qmi_wwan` kernel drivers.

## 1. Tested-modem matrix

Verified live — a full CTL `GET_VERSION_INFO` round-trip through the socket, with
`SEND_ENCAPSULATED_COMMAND` / `RESPONSE_AVAILABLE` / `GET_ENCAPSULATED_RESPONSE`
counts reconciling exactly — on these Qualcomm cdc-wdm parts, across five
vendors, on macOS 26.5–26.6.x:

| Modem | QMI iface | Protocol | Interrupt EP (mps) | Bulk IN / OUT | DTR/RTS needed? |
|-------|-----------|----------|--------------------|---------------|-----------------|
| **Telit LM960A18** (`1bc7:1040`) | 2 | `0xFF/0xFF/0xFF` | `0x83` (8) | `0x8e` / `0x0f` | **No** (A/B tested) |
| **Telit FN980m** | 2 | `0xFF/0xFF/0x50` | `0x83` (8) | `0x8e` / `0x0f` | not determined |
| **Fibocom FM101-GL** (`2cb7:0104`) | 4 | `0xFF/0xFF/0x50` | `0x88` (8) | `0x8e` / `0x0f` | **Yes** (A/B tested) |
| **Quectel EG25-G** | 4 | `0xFF/0xFF/0xFF` | `0x89` (8) | `0x88` / `0x05` | not determined |
| **Quectel RM520N-GL** (`2c7c:0801`) | 4 | `0xFF/0xFF/0xFF` | `0x88` (8) | `0x8e` (7168) / `0x0f` (3072) | not determined |
| **Quectel RM500Q-AE** (`2c7c:0800`) | 4 | `0xFF/0xFF/0xFF` | `0x88` (8) | `0x8e` / `0x0f` (512) | not determined |
| **Quectel EG12-GT** (`2c7c:0512`) | 4 | `0xFF/0xFF/0xFF` | `0x88` (8) | `0x8e` / `0x0f` (512) | not determined |
| **Sierra EM7565** | 8 | `0xFF/0xFF/0xFF` | `0x87` (8) | `0x8e` / `0x0f` | not determined |
| **Sierra MC7411** | 8 | `0xFF/0xFF/0xFF` | `0x86` (8) | `0x8e` / `0x0f` | not determined |
| **Sierra MC7700** (`1199:68a2`) | 8 † | `0xFF/0xFF/0xFF` | `0x85` (**64**) | `0x86` / `0x04` | not determined |

"not determined" means DTR|RTS was asserted by default
(`SET_CONTROL_LINE_STATE` returned `kr=0x0`) and the part round-tripped; whether
it *requires* the assertion was not A/B tested. Only the LM960A18 (no) and
FM101-GL (yes) were tested both ways.

† The MC7700 needs the `qmi_iface_maps[]` pin — see §2. It is also the only
tested part whose interrupt endpoint has `wMaxPacketSize` 64 rather than 8, which
the one-packet interrupt read in §5 handles without special-casing.

The three Quectel parts (RM520N-GL, RM500Q-AE, EG12-GT) were verified together on
one host with four modems attached simultaneously; each replied on the
`RESPONSE_AVAILABLE` interrupt path with `qmi_polls=0` — no poll fallback needed.

Endpoint addresses and QMI interface numbers vary widely across parts (note iface
8 on the Sierra modules and the differing bulk-EP addresses on the EG25-G), which
the `wIndex = iface_num` addressing of the encapsulated control transfers
handles. The addressing and the protocol-`0x50` detection generalize in principle
to other Qualcomm cdc-wdm parts, but remain **unproven beyond the parts listed
here** — and see §6 for parts that present a correct-looking QMI interface yet
never answer on macOS.

### Unsolicited CTL indications on first contact

Two of the Quectel parts (RM500Q-AE, EG12-GT) push an unsolicited **CTL SYNC**
(`0x0027`) indication onto the channel immediately after the bridge is built —
the standard "I have just reset" notification. A client that reads exactly one
frame and judges it will therefore see the indication rather than its own reply
and conclude the channel is broken. **A QMI client must match replies by
transaction id and skip indications**; `tools/qmi_sock_probe.py` does this (and
keeps a persistent stream buffer, since a single `recv()` can carry the
indication and the reply together).

## 2. Choosing the QMI interface on multi-candidate modems

The default selection is "first `0xFF` interface with an interrupt-IN endpoint
wins", which is correct for the vast majority of parts — they expose exactly one
QMI function.

The **Sierra MC7700** does not. It exposes two `0xFF/0xFF/0xFF` interfaces that
both carry an interrupt-IN endpoint:

| iface | interrupt EP | first notification | `SEND_ENCAPSULATED` on ep0 | what it really is |
|---|---|---|---|---|
| 3 | `0x83` (64) | `a1 20` = CDC **SERIAL_STATE** | rejected, `0xe000404f` | AT command port |
| 8 | `0x85` (64) | `a1 01` = **RESPONSE_AVAILABLE** | accepted, full round-trip | cdc-wdm QMI control |

First-match therefore binds interface 3, and the single-QMI-bridge guard (§4)
then refuses the *right* one as a second QMI bridge — leaving QMI dead on a part
whose QMI works perfectly. Two small per-VID/PID tables in `qcseriald.c` fix this
declaratively, with no probe I/O:

- **`qmi_iface_maps[]`** pins the QMI control interface number. When a modem is
  listed, only that interface is eligible for the QMI socket and every other
  `0xFF` candidate is skipped for QMI, before it is ever opened.
- **`serial_iface_maps[]`** exempts named interfaces from the QMI/RmNet skip so
  they fall through to the serial-PTY bridge. On the MC7700 this surfaces
  interface 3 as an AT port (it answers `ATI` with the full Sierra model banner)
  and interface 2 as NMEA/GPS — functions the skip would otherwise discard.

Modems **not** listed in either table are unaffected: the first-match path stays
byte-for-byte unchanged. A behavioral auto-detect (probe the interrupt EP:
`SERIAL_STATE` ⇒ serial, `RESPONSE_AVAILABLE` ⇒ QMI) is a possible
generalization, but it is **not** part of this change — the explicit tables are
the mechanism shipped here.

## 3. Per-modem DTR/RTS

The daemon asserts CDC `SET_CONTROL_LINE_STATE` (DTR|RTS, value `0x0003`) on the
QMI interface once the interrupt read is armed. This is **required** on the
FM101-GL — it emits no `RESPONSE_AVAILABLE` notifications until its control
channel is woken — but the **LM960A18 did not need it**.

The value is overridable at runtime via `QCSERIALD_QMI_DTR` (hex or decimal;
`0` / `off` / `no` skips the request entirely), which was used for the live A/B
testing. Because one of the two A/B-tested modems needs it and the other is
indifferent, this assertion **may need per-modem gating** on other cdc-wdm parts,
and the override is the escape hatch until it does.

## 4. Single client, single instance — by design

- **One socket client at a time.** A new connection to the QMI socket *replaces*
  any existing one; there is no concurrent-client multiplexing. This is an
  intentional design limit, distinct from the rapid-reconnect race that was fixed
  and live-verified — that fix ensures a just-connected client is not dropped, it
  does not add multi-client support.
- **One QMI bridge per daemon instance.** The async interrupt path uses
  file-scope buffers, so the daemon binds a single QMI interface and **refuses a
  second one loudly** (logged, left unbridged) rather than corrupting shared
  state. A modem exposing two genuine QMI functions is therefore out of scope.
  Moving the buffers into the per-bridge struct would lift this bound.
- **Several modems attached at once is fine — the daemon binds exactly one.**
  Observed with four supported modems attached simultaneously (RM520N-GL,
  RM500Q-AE, EG12-GT, LM960A18): the daemon selects a single device — via
  `--match` / `--serial`, else the first vendor-table match — enumerates only
  that device's interfaces, and leaves the others completely untouched. It does
  not scan, open, or bridge a second modem, so the second-QMI-bridge guard above
  is never reached by this configuration. What remains out of scope is *bridging*
  more than one modem from one daemon instance, not merely having several
  plugged in.

## 5. Interrupt-IN endpoint requirement (macOS)

- **An interrupt-IN endpoint is required.** The QMUX control path
  (SEND/GET_ENCAPSULATED over ep0) is gated on the modem's `RESPONSE_AVAILABLE`
  interrupt notification. A QMI function with no interrupt-IN endpoint is
  **unsupported**; the daemon logs the interface and the reason and creates no
  socket for it, rather than dropping it silently.
- **macOS one-packet interrupt read.** On macOS IOKit, sizing an interrupt
  `ReadPipeAsync` to a multiple of `wMaxPacketSize` makes the pipe coalesce that
  many packets into one late completion, which can bury the `RESPONSE_AVAILABLE`
  notification behind an earlier one. The daemon therefore reads exactly one
  packet at a time (clamped to the buffer) — a macOS-IOKit-specific workaround,
  not an arbitrary choice. (Linux reads exactly `wMaxPacketSize` and sees the
  notification immediately.) See the comment at `qmi_intr_read_len()` in
  `qcseriald.c`.
- **A poll fallback backs the interrupt up, and it is hardening, not coverage.**
  When a SEND goes unanswered, the daemon also polls `GET_ENCAPSULATED_RESPONSE`
  on ep0 within a bounded window after the SEND, and counts those fetches
  separately (`qmi_polls` in `status`). This rescues a part whose interrupt
  simply never arms. It does **not** broaden the supported-modem list: both
  proven-silent parts in §6 fail the `GET` itself, so the poll cannot help them.

## 6. Known-silent parts (accept SEND, never respond) — unsupported on macOS

Some parts **have** an interrupt-IN endpoint and **accept**
`SEND_ENCAPSULATED_COMMAND` on ep0 (`kr=0x0`), yet never deliver a QMI reply on
macOS: no `RESPONSE_AVAILABLE` interrupt ever completes **and** the direct
`GET_ENCAPSULATED_RESPONSE` fails. Two parts are proven silent:

| Modem | QMI iface | Interrupt EP (mps) | ep0 GET result | Notes |
|-------|-----------|--------------------|----------------|-------|
| **SIMCom SIM7600NA-H** (`1e0e:9001`) | 5 | `0x8b` (8) | `0xe0004051` (`kIOUSBTransactionTimeout`, NAKs) | MDM9607 |
| **Sierra EM7455** (`1199:9071`) | 8 | `0x87` (8) | `0xe000404f` ("encapsulated-not-supported") | passes on Linux |

The same physical units emit `RESPONSE_AVAILABLE` and answer `GET` on Linux
(`usbmon`-verified), so the modems are healthy — the failure is macOS-IOKit side.
The tell that this is **part-specific, not a daemon bug**: the Sierra **EM7565
passes** on the byte-identical iface-8 / EP `0x87` / mps-8 path the EM7455 fails
on, and the RM520N-GL and MC7700 positive controls complete the full
interrupt→GET path on the same macOS build.

**Not a wrong-transport problem — no bulk-pipe workaround exists.** The
raw-QMI-over-bulk hypothesis was tested on both proven-silent parts and
**conclusively rejected**: neither part's bulk-IN carries a QMUX reply, whether
prompted by an ep0 SEND or a raw bulk-OUT write. On the SIM7600NA the QMI
interface's bulk-OUT itself NAK-times-out absent a data session — there is not
even a live bulk pipe to fall back to. So the QMI reply is genuinely stuck on the
ep0 encapsulated path, and the §5 poll fallback (which also fails `GET` here)
cannot rescue these parts. They are **unsupported on macOS** until the underlying
IOKit ep0 control-IN behavior is root-caused.

Rather than report a lying `healthy` for such a channel, the daemon's `status`
reports the bridge as **`degraded`** once a SEND has gone unanswered past the
degraded window and the poll has also come up empty: the control channel accepts
commands but never answers.

## 7. Access control

The socket is created mode `0666` so a non-root client can connect, mirroring the
permissions the daemon gives its PTYs. QMI is a more privileged channel than a
serial port, though: any local user able to reach the socket path can issue QMI
requests to the modem, including ones that mutate eUICC state. The feature being
**off by default** is the mitigation; there is no per-client authentication.

The socket's **directory** is resolved by an actual `bind()`, not inferred from
the symlink probe that chooses where the PTY symlinks go. `/dev` is devfs, a
synthetic filesystem that need not support `AF_UNIX` socket inodes — a capability
the symlink probe never tested — so if the bind there fails the daemon falls back
to the invoking user's `~/dev` on a real filesystem. The socket and the serial
symlinks may then live in **different** directories; the startup banner and the
daemon log always print the socket's actual path.

## 8. Verification status of the failure paths

§4 and §5 describe how the transport behaves when a client or the interrupt path
misbehaves. Those are separate claims from the happy-path round-trip in §1, and
they are listed here with what was actually executed, so the distinction between
"tested" and "reasoned about" is not left to the reader.

Exercised live on the **Telit LM960A18** (`1bc7:1040`, QMI iface 2) on macOS:

| Failure path | Status | Evidence |
|---|---|---|
| Client disconnects mid-request | **Verified** | 25 abrupt closes with replies in flight; daemon PID unchanged, logged `client write failed (Broken pipe) — dropping client`. |
| Client connects and stops reading | **Verified** | 500 queued requests, never read; logged `client write failed (Resource temporarily unavailable) — dropping client` ~5 s in, daemon survived, next client served normally. |
| Shutdown with the socket open | **Verified** | 4 stop cycles with traffic in flight; each completed in 0.14–0.25 s, no `interrupt read still pending after abort`, socket unlinked. Two cycles caught an interrupt completion landing *during* shutdown and pumped it to completion. |
| Failed QMI bridge does not cause a teardown loop | **Verified** | Fault-injected `ReadPipeAsync` failure; over ~35 monitor intervals the bridge was marked stopped and each AT PTY was created exactly once, with zero rescan/teardown events. |
| Refusing a second QMI interface | **Not executed** | See below. |

**Why a departing client cannot kill the daemon.** A write to a socket whose peer
has gone raises `SIGPIPE`, whose default disposition **terminates the process** —
which would take every AT/DIAG/NMEA bridge down with the QMI one, with nothing in
the log pointing at QMI. Two things prevent it: `SO_NOSIGPIPE` on the accepted
client socket, and — because that option does not cover PTY or pipe writes —
`signal(SIGPIPE, SIG_IGN)` set globally in both the foreground and the daemonized
startup paths. The per-socket option alone is **not** sufficient.

**Why the second-interface refusal is unexercised.** It is not simply that the
test modem has one QMI function — the LM960A18 in fact presents *two* interfaces
matching the QMI predicate (0 and 2, both `0xFF/0xFF`). Interface 0 is rejected
earlier, by the interrupt-IN endpoint requirement in §5, and so never reaches the
`refusing to bind a second QMI bridge` guard. Reaching it needs two interfaces
that *both* pass the interrupt-EP check and are *both* genuine QMI control
functions; the MC7700 comes closest, and §2's pin resolves it before the guard is
reached. The guard is therefore defensive-by-construction and compile-verified
only.

Verified by round-trip on every restart throughout: QMUX `CTL GET_VERSION_INFO`
request in, 203-byte response out with the transaction id echoed, and
`SEND_ENCAPSULATED_COMMAND` / `RESPONSE_AVAILABLE` / `GET_ENCAPSULATED_RESPONSE`
counts reconciling exactly (524/524/524 across the failure runs) — i.e. no
notification lost and no stale reply left queued for the next client.

## 9. Counter semantics — `status` is a sample

`qmi_sends` / `qmi_responses` / `qmi_polls` are **not** read live out of the
daemon. The monitor loop writes them to `/var/run/qcseriald.status` once per
`MONITOR_INTERVAL` (**2 s**, `qcseriald.c`), and `qcseriald status` reads that
file.

Two consequences, both load-bearing for anything built on these numbers:

1. **The counters can be up to `MONITOR_INTERVAL` behind.** A `status` issued
   straight after a successful QMI round-trip can report `qmi_sends=0
   qmi_responses=0` for traffic that has demonstrably already completed —
   indistinguishable, at the moment you look, from a QMI failure. Measured live:
   a read immediately after a probe was consistently **one round-trip behind**,
   3/3.
2. **Freshness of the file is not the same as currency of the data.** A file
   written 0.08 s ago can still be missing a round-trip that happened 0.05 s ago.
   Age alone therefore cannot tell you the counters are current.

If you script against these counters, re-read after the operation you care about
and allow for one monitor interval; do not treat a recent file mtime as proof the
numbers include your last request.

## Summary

Supported today: a **single** QMI interface on a Qualcomm cdc-wdm modem that
exposes an interrupt-IN endpoint, driven by a **single** socket client, tested
live on the ten parts in §1 across five vendors. Everything else — multiple
genuine QMI functions on one modem, concurrent clients, parts without an
interrupt-IN EP, the known-silent parts of §6 (SIM7600NA / EM7455, which accept
SEND but never respond on macOS), and DTR-gating behavior on the modems that were
not A/B tested — is either bounded and logged, or called out above as unproven.
