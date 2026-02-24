# qcseriald-darwin

**An unofficial Qualcomm Serial "driver" service for macOS**

User-space USB-to-serial bridge daemon that creates virtual serial ports (`/dev/tty.qcserial-*`) for Qualcomm-based cellular modems on macOS. No kernel extensions, no DriverKit, no entitlements, no code signing required.

This is the macOS equivalent of Linux's `qcserial.ko` / `option.ko` serial port creation.

By [iamromulan](https://github.com/iamromulan) | Part of [qfenix](https://github.com/iamromulan/qfenix) (soon)

## Supported Devices

Any Qualcomm-based USB modem using vendor-specific (class 0xFF) bulk serial interfaces. Supports 13 vendors out of the box (sourced from the [qfenix](https://github.com/iamromulan/qfenix) USB database):

| VID | Vendor |
|------|--------|
| 0x2c7c | Quectel |
| 0x05c6 | Qualcomm |
| 0x3c93 | Foxconn |
| 0x3763 | Sierra (alternate) |
| 0x1199 | Sierra Wireless |
| 0x19d2 | ZTE |
| 0x12d1 | Huawei |
| 0x413c | Dell (Telit/Foxconn OEM) |
| 0x1bc7 | Telit |
| 0x1e0e | Simcom |
| 0x0846 | Netgear |
| 0x2cb7 | Fibocom |
| 0x2dee | MeiG Smart |

Tested with:

- **Quectel RM551E-GL** (VID 0x2c7c, PID 0x0122)

Additional vendors can be added to the `supported_vendors[]` table in the source.

## Created Ports

| Port | Function |
|------|----------|
| `/dev/tty.qcserial-diag` | Qualcomm DIAG (detected via USB descriptor or VID/PID table) |
| `/dev/tty.qcserial-nmea` | NMEA GPS output (auto-detected) |
| `/dev/tty.qcserial-at0` | AT command port (auto-detected via AT probe) |
| `/dev/tty.qcserial-at1` | AT command port (auto-detected via AT probe) |

ADB interfaces are automatically skipped and left available for `adb` to use directly.

## Requirements

- macOS 13+ (Ventura or later, tested on macOS 26 Tahoe)
- Xcode Command Line Tools (`xcode-select --install`)
- Root access (sudo) for USB device access and `/dev` symlinks

## Build

```bash
make
```

## Usage

```bash
# Start as daemon (prints ports, returns to shell)
sudo ./qcseriald start

# Start in foreground (for debugging or launchd)
sudo ./qcseriald start --foreground

# Check status and port health
sudo ./qcseriald status

# Restart (stop + start)
sudo ./qcseriald restart

# Stop the daemon
sudo ./qcseriald stop

# View daemon log
sudo ./qcseriald log

# Follow daemon log in real-time
sudo ./qcseriald log -f

# Show version and fenix art
./qcseriald version
```

Then in another terminal:
```bash
screen /dev/tty.qcserial-at0 115200
# Type: AT
# Response: OK
```

## Features

### Port Auto-Detection

On startup and reconnect, ports start with `-loading` suffix while the daemon identifies them:

1. **DIAG** — identified immediately by USB descriptor (subclass 0xFF, protocol 0x30) or VID/PID lookup table (~50 device models)
2. **AT ports** — detected by sending `AT\r` and checking for `OK`/`ERROR` response (~3 seconds)
3. **NMEA/GPS** — inferred as the remaining port after AT ports are identified

If the modem isn't ready yet (fresh boot), the daemon waits for the `RDY` URC before probing.

### Auto-Reconnect

When the modem is unplugged or reboots, the daemon detects the disconnection and enters a rescan loop. When the modem comes back, ports are automatically recreated and re-identified — no manual restart needed.

### ADB Coexistence

The daemon does not take device-level USB access, so ADB works simultaneously. It also automatically sets `ADB_LIBUSB=0` system-wide to work around an ADB bug with non-contiguous USB interface numbers.

### Stale State Cleanup

If the daemon is killed uncleanly (`kill -9`), running `qcseriald start` will automatically clean up stale PID files and dangling symlinks before starting fresh.

## Install (system-wide)

```bash
sudo make install
```

This installs the binary to `/usr/local/bin/` and a launchd plist for optional auto-start:
```bash
# Enable auto-start at boot
sudo launchctl load /Library/LaunchDaemons/com.iamromulan.qcseriald.plist

# Start manually via launchd
sudo launchctl start com.iamromulan.qcseriald

# Disable auto-start
sudo launchctl unload /Library/LaunchDaemons/com.iamromulan.qcseriald.plist
```

## Uninstall

```bash
sudo make uninstall
```

## How It Works

```
USB Modem (bulk endpoints)
    |  IOKit user-space USB API
qcseriald daemon (runs as root)
    |  openpty() + bridge threads
/dev/tty.qcserial-{diag,nmea,at0,at1}
    |
Any serial tool (screen, minicom, qfenix, etc.)
```

1. Enumerates all `IOUSBHostDevice` entries via IOKit
2. Finds the modem by matching vendor ID against the supported vendors table
3. Opens each vendor-specific (class 0xFF) interface via registry-based discovery
4. Creates a pseudo-TTY pair per interface using `openpty()`
5. Symlinks each PTY slave to a friendly `/dev/tty.qcserial-*` name
6. Probes unknown ports (AT command + RDY URC) for automatic identification
7. Bridges data between USB bulk endpoints and PTY masters via dedicated threads
8. Monitors bridge health and auto-reconnects on modem disconnect/reconnect

Single C file, no third-party dependencies. Links against IOKit, CoreFoundation, and libutil.

## License

MIT License. See [LICENSE](LICENSE).
