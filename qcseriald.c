/*
 * qcseriald — User-space USB-to-serial daemon for Qualcomm modems on macOS
 *
 * Part of qcseriald-darwin
 * https://github.com/iamromulan/qcseriald-darwin
 *
 * Copyright (c) 2025-2026 iamromulan
 * MIT License — see LICENSE for details.
 *
 * Opens vendor-specific (class 0xFF) USB interfaces on Qualcomm-based modems,
 * creates pseudo-TTY pairs, and bridges data between USB bulk endpoints and PTYs.
 *
 * No DriverKit, no entitlements, no provisioning profiles needed.
 *
 * Build:
 *   clang -std=c11 -o qcseriald qcseriald.c \
 *     -framework IOKit -framework CoreFoundation -lutil
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <fcntl.h>
#include <glob.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <time.h>
#include <poll.h>
#include <util.h>  /* openpty */
#include <sys/socket.h>  /* QMI unix-domain socket */
#include <sys/un.h>
#include <strings.h>  /* strcasecmp */

#include <IOKit/IOKitLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/IOUSBLib.h>
#include <CoreFoundation/CoreFoundation.h>

/* ── Version ── */

#define QCSERIALD_VERSION "1.0.6"
#define QCSERIALD_AUTHOR  "iamromulan"
#define QCSERIALD_URL     "https://github.com/iamromulan/qcseriald-darwin"

/* ── ANSI colors (matches qfenix UX scheme) ── */

#define C_RESET  "\033[0m"
#define C_RED    "\033[31m"
#define C_YELLOW "\033[33m"
#define C_GREEN  "\033[38;5;121m"
#define C_BOLD   "\033[1m"

/* ── Timestamped logging ── */

static int g_log_timestamps;  /* set to 1 when running as daemon */

/* ── Device selection ── */
/* When more than one supported modem is attached, choose WHICH one to bridge.
 * Unset (all -1 / empty) ⇒ today's first-supported-VID-wins behavior, byte-for-
 * byte. Set via `--match <vid>:<pid>` and/or `--serial <str>` on start/restart
 * (sudo-safe as argv), with env fallback QCSERIALD_MATCH / QCSERIALD_MATCH_SERIAL
 * (env needs a sudoers env_keep entry to survive `sudo`). Parsed once before the
 * daemonize fork; the child inherits these and setup_bridges() re-reads them on
 * every hotplug rescan. */
static int  g_match_vid = -1;          /* selected idVendor,  -1 = any */
static int  g_match_pid = -1;          /* selected idProduct, -1 = any */
static char g_match_serial[64] = "";   /* selected USB iSerialNumber, "" = any */
static int  g_logged_no_match = 0;     /* throttle the "no device matched" log */

/* How many times the monitor loop will tear down and rebuild EVERY bridge
 * because ONE of them died while the modem is still present. A bridge can fail
 * for a reason local to that interface — the clearest case is a QMI interrupt
 * endpoint that will not arm — and rebuilding cannot fix that, so an unbounded
 * rebuild destroys the healthy AT/NMEA/DIAG PTYs every monitor interval,
 * forever. Bounded here, then we keep the healthy bridges and mark the dead one
 * BRIDGE_STOPPED. The counter is reset whenever the set comes back fully alive,
 * or when the device itself changes. */
#define BRIDGE_REBUILD_MAX_ATTEMPTS 3
static int g_bridge_rebuilds = 0;

__attribute__((format(printf, 1, 2)))
static void logprintf(const char *fmt, ...) {
    if (g_log_timestamps) {
        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        printf("[%04d-%02d-%02d %02d:%02d:%02d] ",
               tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
               tm.tm_hour, tm.tm_min, tm.tm_sec);
    }
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

/* ── Constants ── */

#define MAX_INTERFACES    8
#define USB_BUF_SIZE      4096
#define SHUTDOWN_TIMEOUT  3   /* seconds */
#define MONITOR_INTERVAL  2   /* seconds */
#define RESCAN_INTERVAL   5   /* seconds */
#define PROBE_RDY_TIMEOUT 30  /* seconds — wait for RDY URC before AT fallback */
#define PROBE_AT_TIMEOUT  3   /* seconds — per-port AT command response timeout */

/*
 * Supported vendor IDs — Qualcomm-based modem vendors.
 * Sourced from qfenix usb_ids.h diag_vids[] table.
 */
static const struct { uint16_t vid; const char *name; } supported_vendors[] = {
    { 0x2c7c, "Quectel"                },
    { 0x05c6, "Qualcomm"               },
    { 0x3c93, "Foxconn"                },
    { 0x3763, "Sierra (alternate)"      },
    { 0x1199, "Sierra Wireless"         },
    { 0x19d2, "ZTE"                     },
    { 0x12d1, "Huawei"                  },
    { 0x413c, "Dell (Telit/Foxconn OEM)"},
    { 0x1bc7, "Telit"                   },
    { 0x1e0e, "Simcom"                  },
    { 0x0846, "Netgear"                 },
    { 0x2cb7, "Fibocom"                 },
    { 0x2dee, "MeiG Smart"             },
};
#define NUM_VENDORS (sizeof(supported_vendors) / sizeof(supported_vendors[0]))

/*
 * EDL (Emergency Download) mode VID/PID pairs — skip entirely.
 * EDL uses Sahara/Firehose protocol over bulk endpoints, not serial.
 * Bridging these would block qfenix libusb access.
 * Sourced from qfenix usb_ids.h edl_ids[] table.
 */
static const struct { uint16_t vid; uint16_t pid; } edl_ids[] = {
    { 0x05c6, 0x9008 },  /* EDL mode */
    { 0x05c6, 0x9006 },  /* Memory debug (alternate) */
    { 0x05c6, 0x900e },  /* Memory debug mode */
    { 0x05c6, 0x901d },  /* Android DIAG+EDL */
    { 0x05c6, 0x9025 },  /* Alternate EDL */
    { 0x0fce, 0x9dde },  /* Sony */
    { 0x0fce, 0xade3 },
    { 0x0fce, 0xade5 },
    { 0x0fce, 0xaded },
    { 0x1199, 0x9062 },  /* Sierra Wireless */
    { 0x1199, 0x9070 },  /* EM74xx/MC74xx EDL */
    { 0x1199, 0x9090 },  /* EM9xxx/5G EDL */
    { 0x0846, 0x68e0 },  /* Netgear */
    { 0x19d2, 0x0076 },  /* ZTE */
    { 0x1004, 0x61a1 },  /* LG memory debug */
};
#define NUM_EDL_IDS (sizeof(edl_ids) / sizeof(edl_ids[0]))

static int is_edl_device(uint16_t vid, uint16_t pid) {
    for (size_t i = 0; i < NUM_EDL_IDS; i++)
        if (edl_ids[i].vid == vid && edl_ids[i].pid == pid)
            return 1;
    return 0;
}

/*
 * DIAG interface number mapping — per VID/PID.
 * Different modem models expose the DIAG port on different USB interface numbers.
 * Default is interface 0 if not listed here.
 * Sourced from qfenix usb_ids.h diag_iface_maps[] table.
 */
static const struct { uint16_t vid; uint16_t pid; uint8_t iface; } diag_iface_maps[] = {
    /* Quectel laptop modules (interface 3) */
    { 0x2c7c, 0x0127, 3 },  /* EM05CEFC-LNV */
    { 0x2c7c, 0x0128, 3 },  /* EM060KGL Google */
    { 0x2c7c, 0x012c, 3 },  /* EM060K-GL */
    { 0x2c7c, 0x012e, 3 },  /* EM120K-GL */
    { 0x2c7c, 0x012f, 3 },  /* EM120K-GL */
    { 0x2c7c, 0x0139, 3 },  /* EM061KGL */
    { 0x2c7c, 0x013c, 3 },  /* RM255CGL (RedCap) */
    { 0x2c7c, 0x0309, 3 },  /* EM05E-EDU */
    { 0x2c7c, 0x030a, 3 },  /* EM05-G */
    { 0x2c7c, 0x030d, 3 },  /* EM05G-FCCL */
    { 0x2c7c, 0x0310, 3 },  /* EM05-CN */
    { 0x2c7c, 0x0311, 3 },  /* EM05-G-SE10 */
    { 0x2c7c, 0x0315, 3 },  /* EM05-G STD */
    { 0x2c7c, 0x0803, 3 },  /* RM520NGL ThinkPad */
    { 0x2c7c, 0x0804, 3 },  /* Zebra project */
    { 0x2c7c, 0x6008, 3 },  /* EM061KGL */
    { 0x2c7c, 0x6009, 3 },  /* EM061KGL */
    /* Quectel (interface 2) */
    { 0x2c7c, 0x0133, 2 },  /* RG650VEU */
    { 0x2c7c, 0x030b, 2 },  /* EG120KEABA */
    { 0x2c7c, 0x0514, 2 },  /* EG060K-EA */
    /* Qualcomm reference */
    { 0x05c6, 0x90db, 2 },  /* AG600K-EM / SDX55 ref */
    { 0x05c6, 0x9091, 0 },  /* SDX55 DIAG composite */
    { 0x05c6, 0x9092, 0 },  /* SDX55 alt composite */
    { 0x05c6, 0x90e8, 0 },  /* SDX65 ref QMI */
    /* Foxconn */
    { 0x3c93, 0xffff, 8 },  /* Foxconn generic */
    /* Dell/Foxconn 5G */
    { 0x413c, 0x81d7, 5 },  /* DW5820e / Telit LN940/T77W968 */
    { 0x413c, 0x81e0, 0 },  /* DW5930e / Foxconn T99W175 */
    { 0x413c, 0x81e4, 0 },  /* DW5931e / Foxconn T99W373 */
    /* Telit 4G */
    { 0x1bc7, 0x1040, 0 },  /* Telit LM960A18 QMI */
    { 0x1bc7, 0x1041, 0 },  /* Telit LM960A18 MBIM */
    { 0x1bc7, 0x1201, 0 },  /* Telit LE910C4-NF */
    /* Telit 5G */
    { 0x1bc7, 0x1050, 0 },  /* Telit FN980 (SDX55) */
    { 0x1bc7, 0x1051, 0 },  /* Telit FN980m mmWave */
    { 0x1bc7, 0x1052, 0 },  /* Telit FN980A */
    { 0x1bc7, 0x1070, 0 },  /* Telit FN990A28 (SDX65) */
    { 0x1bc7, 0x1071, 0 },  /* Telit FN990A28 QMI */
    { 0x1bc7, 0x1080, 0 },  /* Telit FM990A28 */
    /* Sierra Wireless 5G */
    { 0x1199, 0x90d2, 0 },  /* Sierra EM9190 QMI */
    { 0x1199, 0x90d3, 0 },  /* Sierra EM9190 MBIM */
    { 0x1199, 0xc080, 0 },  /* Sierra EM9191 QMI */
    { 0x1199, 0xc081, 0 },  /* Sierra EM9191 MBIM */
    { 0x1199, 0xc082, 0 },  /* Sierra EM9291 (SDX65) */
    /* Simcom */
    { 0x1e0e, 0x9001, 0 },  /* SIM8200EA-M2 (SDX55) */
    { 0x1e0e, 0x9011, 0 },  /* SIM8200EA MBIM */
    { 0x1e0e, 0x9024, 0 },  /* SIM8380G (SDX72) */
    /* Fibocom */
    { 0x2cb7, 0x0109, 0 },  /* FM150-AE (SDX55) */
    { 0x2cb7, 0x010b, 0 },  /* FM150-AE MBIM */
    { 0x2cb7, 0x0113, 0 },  /* FM160-GL QMI (SDX65) */
    { 0x2cb7, 0x0115, 0 },  /* FM160-GL MBIM */
    /* MeiG Smart */
    { 0x2dee, 0x4d57, 0 },  /* SRM825 (SDX55) */
    { 0x2dee, 0x4d63, 0 },  /* SRM930 (SDX65) */
    /* Netgear */
    { 0x0846, 0x68e2, 2 },
    /* ZTE */
    { 0x19d2, 0x1404, 2 },
};
#define NUM_DIAG_MAPS (sizeof(diag_iface_maps) / sizeof(diag_iface_maps[0]))

static int get_diag_iface(uint16_t vid, uint16_t pid) {
    for (size_t i = 0; i < NUM_DIAG_MAPS; i++) {
        if (diag_iface_maps[i].vid == vid && diag_iface_maps[i].pid == pid)
            return diag_iface_maps[i].iface;
    }
    return 0;  /* default: interface 0 */
}

/*
 * QMI control-interface number mapping — per VID/PID.
 *
 * Some modems expose MORE THAN ONE 0xFF/0xFF/0xFF interface that carries an
 * interrupt-IN endpoint, and only one of them is the real cdc-wdm QMI control
 * function. The default QMI selection is "first 0xFF-with-interrupt wins", so it
 * can bind the wrong one — after which the single-QMI-bridge guard refuses the
 * *right* one as a "second QMI bridge", leaving QMI dead.
 *
 * Sierra MC7700 (0x1199:0x68a2), measured on hardware:
 *   - interface 3 is a DM/serial function. Its interrupt EP emits CDC
 *     SERIAL_STATE, and ep0 rejects SEND_ENCAPSULATED_COMMAND (pipe stall).
 *   - interface 8 is the real cdc-wdm QMI control function; its interrupt EP
 *     emits RESPONSE_AVAILABLE and the encapsulated round-trip succeeds.
 * First-match binds iface 3, then the single-QMI guard locks out iface 8.
 * Pinning QMI to iface 8 fixes it.
 *
 * Semantics: when a modem is listed here, ONLY the named interface number is
 * eligible for the QMI socket; every other 0xFF QMI candidate is skipped for
 * QMI. Modems NOT listed are unaffected — the vast majority expose a single QMI
 * function, so first-match is already correct and that path stays byte-for-byte
 * unchanged.
 */
static const struct { uint16_t vid; uint16_t pid; uint8_t iface; } qmi_iface_maps[] = {
    { 0x1199, 0x68a2, 8 },  /* Sierra MC7700: iface 3=DM/serial, iface 8=QMI */
};
#define NUM_QMI_MAPS (sizeof(qmi_iface_maps) / sizeof(qmi_iface_maps[0]))

/* Pinned QMI control-interface number for this VID/PID, or -1 if unlisted
 * (unlisted ⇒ keep the default first-0xFF-with-interrupt-wins selection). */
static int get_qmi_iface(uint16_t vid, uint16_t pid) {
    for (size_t i = 0; i < NUM_QMI_MAPS; i++) {
        if (qmi_iface_maps[i].vid == vid && qmi_iface_maps[i].pid == pid)
            return qmi_iface_maps[i].iface;
    }
    return -1;  /* no explicit QMI interface pin for this modem */
}

/*
 * Serial (AT/DM/NMEA) interface allowlist — per VID/PID.
 *
 * On a modem whose QMI control interface is pinned by qmi_iface_maps[] above,
 * every *other* 0xFF/0xFF/0xFF candidate is skipped for QMI (the pinned-out skip
 * in setup_bridges). Some of those skipped functions are real serial ports the
 * user wants — the MC7700's interface 3 is a live AT command port: on hardware
 * it accepts SET_CONTROL_LINE_STATE (DTR|RTS, kr=0) and answers ATI with the
 * full Sierra model banner (Model: MC7700 … OK).
 *
 * Listing (vid, pid, iface) here EXEMPTS that interface from the QMI/RmNet skip
 * so it falls through to the serial-PTY bridge, where the existing -loading auto-
 * probe renames it ("at0" when it answers AT, "nmea" for $G sentences). Only
 * listed interfaces are affected; every other modem — and every unlisted
 * interface on a listed modem — is byte-for-byte unchanged.
 *
 * MC7700 note: iface 2 is GPS/NMEA that only streams $G sentences during an
 * active location session; it is listed here so it falls through to the
 * serial-PTY bridge. iface 0 is a binary DM/DIAG function with no interrupt EP
 * that rejects both DTR and AT, so it is deliberately NOT listed — it stays on
 * the QMI/RmNet skip path exactly as before.
 */
static const struct { uint16_t vid; uint16_t pid; uint8_t iface; } serial_iface_maps[] = {
    { 0x1199, 0x68a2, 3 },  /* Sierra MC7700: iface 3 = AT command port */
    { 0x1199, 0x68a2, 2 },  /* Sierra MC7700: iface 2 = NMEA/GPS port */
};
#define NUM_SERIAL_MAPS (sizeof(serial_iface_maps) / sizeof(serial_iface_maps[0]))

/* True when this VID/PID+iface is an EXPLICIT serial function that must be
 * exempted from the QMI/RmNet skip and bridged as a serial PTY. */
static int is_serial_iface(uint16_t vid, uint16_t pid, uint8_t iface) {
    for (size_t i = 0; i < NUM_SERIAL_MAPS; i++) {
        if (serial_iface_maps[i].vid == vid && serial_iface_maps[i].pid == pid
                && serial_iface_maps[i].iface == iface)
            return 1;
    }
    return 0;
}

#define PID_FILE        "/var/run/qcseriald.pid"
#define STATUS_FILE     "/var/run/qcseriald.status"
#define LOG_FILE        "/var/log/qcseriald.log"
#define SYMLINK_PREFIX  "tty.qcserial-"
#define DEV_DIR         "/dev"

/* ── Bridge states ── */

enum bridge_state {
    BRIDGE_IDLE     = 0,
    BRIDGE_RUNNING  = 1,
    BRIDGE_STOPPING = 2,
    BRIDGE_STOPPED  = 3
};

/* ── Types ── */

typedef struct {
    int                         iface_num;
    int                         pty_master;
    int                         pty_slave;   /* kept open so master writes don't EIO */
    char                        pty_name[256];
    char                        link_name[256];
    char                        func_name[32];
    IOUSBInterfaceInterface300  **iface;
    UInt8                       pipe_in;
    UInt8                       pipe_out;
    pthread_t                   usb_to_pty_thread;
    pthread_t                   pty_to_usb_thread;
    _Atomic(int)                state;
    _Atomic(int)                usb_to_pty_alive;
    _Atomic(int)                pty_to_usb_alive;
    /* ── QMI passthrough ──
     * A QMI interface is exposed as an AF_UNIX SOCK_STREAM socket carrying whole
     * QMUX frames (SEQPACKET is unavailable on macOS AF_UNIX), instead of a
     * byte-stream PTY. Only populated when is_qmi=1. The two bridge threads
     * (usb_to_pty_thread / pty_to_usb_thread fields, reused) run qmi_usb_to_sock
     * / qmi_sock_to_usb and set the same *_alive atomics so the existing
     * shutdown_bridges() join loop waits on them unchanged. */
    int                         is_qmi;        /* 1 = QMI socket bridge */
    int                         qmi_listen_fd; /* stream listener, -1 if none */
    /* The connected client fd is touched by BOTH QMI threads (the sock thread
     * recv()s on it, the interrupt thread's run-loop callback send()s replies to
     * it), so the slot is a lock-free atomic: an owner claims an fd by
     * atomic_exchange and only the thread that wins the compare-exchange back to
     * -1 may close it. That keeps one thread from close()ing an fd number the
     * other is mid-syscall on — accept() recycles fd numbers immediately, so
     * that would land a QMI reply in an unrelated descriptor. */
    _Atomic(int)                qmi_client_fd; /* connected client fd, -1 if none */
    char                        sock_path[256];/* filesystem path of the socket */
    UInt8                       pipe_intr;     /* interrupt IN pipe idx, 0 = none */
    UInt16                      intr_maxpacket;/* interrupt EP wMaxPacketSize (per-read size) */
    /* QMI poll-fallback + round-trip health. All response fetches happen on the
     * modem->sock runloop thread (interrupt callback + post-slice poll), so
     * qmi_responses / qmi_polls / qmi_poll_seen are mutated only there;
     * qmi_sends / qmi_last_send_ms are set by the sock->USB thread. The
     * cross-thread fields are atomic. sends == responses means every command
     * was answered. */
    _Atomic(uint64_t)           qmi_sends;        /* SEND_ENCAPSULATED_COMMANDs issued */
    _Atomic(uint64_t)           qmi_responses;    /* replies fetched+forwarded (interrupt or poll) */
    _Atomic(uint64_t)           qmi_polls;        /* of those, fetched via the poll fallback */
    _Atomic(uint64_t)           qmi_last_send_ms; /* monotonic ms of the last SEND */
    _Atomic(uint64_t)           qmi_last_poll_ms; /* monotonic ms of the last poll attempt */
    int                         qmi_poll_seen;    /* runloop-only: interrupt never delivered, poll works */
} bridge_t;

/* ── Globals ── */

static _Atomic(int) g_running = 1;
static const char *g_daemon_state = "starting";
static int g_edl_detected = 0;      /* 1 if EDL-mode device was seen on last scan */
static char g_edl_product[128];      /* product name of EDL device */

static bridge_t g_bridges[MAX_INTERFACES];
static int g_bridge_count = 0;
static int g_expected_bridges = 0;  /* vendor-specific interfaces found (minus ADB) */
static int g_matched_vid = 0;        /* VID of connected modem */
static uint64_t g_session_id = 0;    /* IOKit sessionID — changes on USB re-enumeration */

static pthread_mutex_t g_exit_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_exit_cond  = PTHREAD_COND_INITIALIZER;

static char g_symlink_dir[512] = DEV_DIR;

/* QMI passthrough opt-in. Default OFF: the QMI interface is skipped exactly as
 * before and no socket is created, so the transport cannot affect normal
 * operation unless asked for. Turn on by exporting QCSERIALD_QMI_SOCKET=1
 * before `start`.
 *
 * Note this gates the *socket*, not the detection: the QMI/RmNet skip below was
 * also widened to match protocol 0x50, and that applies whether or not the
 * socket is enabled — a 0xFF/0xFF/0x50 interface is now recognized as the
 * QMI/RmNet channel it is, instead of being bridged to a PTY and AT-probed. */
static int g_qmi_socket_enabled = 0;

#define QMI_SOCK_NAME  SYMLINK_PREFIX "qmi.sock"  /* tty.qcserial-qmi.sock */


/* ── Signal handler ── */

static void signal_handler(int sig) {
    (void)sig;
    atomic_store(&g_running, 0);
}

/* ── PID file management ── */

static pid_t pid_file_read(void) {
    FILE *f = fopen(PID_FILE, "r");
    if (!f) return 0;
    pid_t pid = 0;
    if (fscanf(f, "%d", &pid) != 1)
        pid = 0;
    fclose(f);
    return pid;
}

static int pid_file_write(pid_t pid) {
    FILE *f = fopen(PID_FILE, "w");
    if (!f) {
        fprintf(stderr, "Failed to write PID file %s: %s\n", PID_FILE, strerror(errno));
        return -1;
    }
    fprintf(f, "%d\n", pid);
    fclose(f);
    return 0;
}

static void pid_file_remove(void) {
    unlink(PID_FILE);
}

static int is_process_alive(pid_t pid) {
    if (pid <= 0) return 0;
    return (kill(pid, 0) == 0 || errno == EPERM);
}

/* ── Vendor lookup ── */

static const char *vendor_name(int vid) {
    for (size_t i = 0; i < NUM_VENDORS; i++) {
        if (supported_vendors[i].vid == vid)
            return supported_vendors[i].name;
    }
    return NULL;
}

/* ── Symlink directory resolution ── */

/* Resolve the invoking user's ~/dev directory into buf.
 *
 * Factored out of resolve_symlink_dir() so the QMI socket-directory fallback can
 * reuse the exact same resolution order (SUDO_USER, then LOGNAME, then the
 * root-only /var/root/dev). Returns 0 when a real user's home was resolved and 1
 * for the /var/root fallback; when out_pw is non-NULL it receives the passwd
 * entry that supplied the home, or NULL for the fallback. */
static int resolve_home_dev_dir(char *buf, size_t bufsz, struct passwd **out_pw) {
    const char *home = NULL;
    struct passwd *pw = NULL;

    const char *sudo_user = getenv("SUDO_USER");
    if (sudo_user && (pw = getpwnam(sudo_user)))
        home = pw->pw_dir;

    if (!home) {
        const char *logname = getenv("LOGNAME");
        if (logname && (pw = getpwnam(logname)))
            home = pw->pw_dir;
    }

    if (!home) {
        snprintf(buf, bufsz, "/var/root/dev");
        if (out_pw) *out_pw = NULL;
        return 1;
    }

    snprintf(buf, bufsz, "%s/dev", home);
    if (out_pw) *out_pw = pw;
    return 0;
}

static void resolve_symlink_dir(void) {
    /* Probe /dev/ with a test symlink */
    const char *test_link = DEV_DIR "/" SYMLINK_PREFIX "test";
    if (symlink("/dev/null", test_link) == 0) {
        unlink(test_link);
        snprintf(g_symlink_dir, sizeof(g_symlink_dir), "%s", DEV_DIR);
        printf("Symlink directory: %s (native)\n", g_symlink_dir);
        return;
    }

    /* /dev/ symlinks failed — fall back to ~/dev/ */
    const char *sudo_user = getenv("SUDO_USER");
    resolve_home_dev_dir(g_symlink_dir, sizeof(g_symlink_dir), NULL);

    /* Create ~/dev/ if it doesn't exist */
    struct stat st;
    if (stat(g_symlink_dir, &st) != 0) {
        if (mkdir(g_symlink_dir, 0755) == 0) {
            /* chown to real user if running via sudo */
            if (sudo_user) {
                struct passwd *pw = getpwnam(sudo_user);
                if (pw)
                    chown(g_symlink_dir, pw->pw_uid, pw->pw_gid);
            }
            printf("Created fallback symlink directory: %s\n", g_symlink_dir);
        } else {
            fprintf(stderr, C_YELLOW "Warning: could not create %s: %s\n" C_RESET,
                    g_symlink_dir, strerror(errno));
        }
    }

    printf("Symlink directory: %s (fallback — /dev/ symlinks blocked by SIP)\n", g_symlink_dir);
}

static void make_symlink_path(char *buf, size_t size, const char *name) {
    snprintf(buf, size, "%s/" SYMLINK_PREFIX "%s", g_symlink_dir, name);
}

/* ── Stale symlink cleanup ── */

static void cleanup_stale_symlinks(void) {
    /* Glob both /dev/ and the resolved g_symlink_dir (may be ~/dev/).
     * Previous sessions may have used a different directory. */
    const char *patterns[2];
    char alt_pattern[600];
    int n = 0;

    patterns[n++] = DEV_DIR "/" SYMLINK_PREFIX "*";
    if (strcmp(g_symlink_dir, DEV_DIR) != 0) {
        snprintf(alt_pattern, sizeof(alt_pattern), "%s/" SYMLINK_PREFIX "*", g_symlink_dir);
        patterns[n++] = alt_pattern;
    }

    for (int p = 0; p < n; p++) {
        glob_t gl;
        if (glob(patterns[p], 0, NULL, &gl) == 0) {
            for (size_t i = 0; i < gl.gl_pathc; i++) {
                struct stat st;
                /* If the symlink target doesn't exist, it's stale */
                if (stat(gl.gl_pathv[i], &st) != 0) {
                    printf("Removing stale symlink: %s\n", gl.gl_pathv[i]);
                    unlink(gl.gl_pathv[i]);
                }
            }
            globfree(&gl);
        }
    }
}

/* ── Thread: USB bulk IN → PTY master ── */

static int pty_slave_is_open(int master_fd)
{
    /*
     * Detect if any process has the PTY slave open.
     * macOS quirk: poll(POLLHUP) doesn't work reliably for PTYs
     * whose slave was never opened externally.  write(fd,"",0)
     * returns EIO when no slave is open, 0 when one is.
     */
    ssize_t ret = write(master_fd, "", 0);
    if (ret < 0 && errno == EIO)
        return 0;
    return 1;
}

static void *usb_to_pty(void *arg) {
    bridge_t *b = (bridge_t *)arg;
    UInt8 buf[USB_BUF_SIZE];
    IOReturn kr;
    UInt32 len;
    int notopen_count = 0;
    time_t thread_start = time(NULL);
    time_t last_good_read = thread_start;

    atomic_store(&b->usb_to_pty_alive, 1);
    logprintf("[%s] USB->PTY thread started\n", b->func_name);

    while (atomic_load(&g_running) && atomic_load(&b->state) == BRIDGE_RUNNING) {
        /*
         * Demand-driven: only read from USB when a client has the
         * PTY slave open.  This eliminates bulk IN NAK traffic on
         * idle endpoints, matching Linux usb_wwan behavior where
         * URBs are only submitted for ports with active TTY sessions.
         */
        if (!pty_slave_is_open(b->pty_master)) {
            usleep(100000);  /* 100ms */
            last_good_read = time(NULL);
            continue;
        }

        len = sizeof(buf);
        kr = (*b->iface)->ReadPipe(b->iface, b->pipe_in, buf, &len);
        if (kr != kIOReturnSuccess) {
            if (kr == kIOReturnAborted) {
                logprintf("[%s] USB->PTY ReadPipe: 0x%x (stopping)\n", b->func_name, kr);
                break;
            }
            if (kr == kIOReturnNotResponding) {
                /* Transient hiccup — retry with timeout.
                 * Genuine disconnect if it persists for 5+ seconds. */
                (*b->iface)->ClearPipeStall(b->iface, b->pipe_in);
                if (time(NULL) - last_good_read > 5) {
                    logprintf("[%s] USB->PTY: not responding for 5s, giving up\n",
                             b->func_name);
                    break;
                }
                usleep(10000);  /* 10ms */
                continue;
            }
            if (kr == (IOReturn)0xe00002c0 ||   /* kIOReturnNotOpen */
                kr == (IOReturn)0xe00002eb) {   /* kIOUSBPipeStalled */
                notopen_count++;
                if (notopen_count == 1 || notopen_count == 100 ||
                    notopen_count % 1000 == 0)
                    logprintf("[%s] USB->PTY ReadPipe: 0x%x (retry #%d)\n",
                              b->func_name, kr, notopen_count);
                /* Give up if no successful reads for 15s — pipe is
                 * permanently broken (stale handle, modem switched
                 * modes, or genuine disconnect). */
                if (time(NULL) - last_good_read > 15) {
                    logprintf("[%s] USB->PTY: pipe broken (0x%x, no data for %ds) "
                              "— giving up\n",
                              b->func_name, kr,
                              (int)(time(NULL) - last_good_read));
                    break;
                }
                (*b->iface)->ClearPipeStall(b->iface, b->pipe_in);
                usleep(10000);  /* 10ms */
                continue;
            }
            /* Unknown error — treat like broken pipe with same timeout */
            logprintf("[%s] USB->PTY ReadPipe error: 0x%x\n", b->func_name, kr);
            if (time(NULL) - last_good_read > 15) {
                logprintf("[%s] USB->PTY: persistent error, no data for %ds "
                          "— giving up\n", b->func_name,
                          (int)(time(NULL) - last_good_read));
                break;
            }
            usleep(10000);
            continue;
        }
        last_good_read = time(NULL);
        if (len > 0) {
            ssize_t written = 0;
            while (written < (ssize_t)len) {
                ssize_t n = write(b->pty_master, buf + written, len - written);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EINTR) continue;
                    if (errno == EIO) {
                        /* No slave open yet — discard this data and continue */
                        break;
                    }
                    logprintf("[%s] USB->PTY write error: %s\n", b->func_name, strerror(errno));
                    goto done;
                }
                written += n;
            }
        }
    }
    logprintf("[%s] USB->PTY loop ended (running=%d state=%d)\n",
              b->func_name, atomic_load(&g_running), atomic_load(&b->state));
done:
    atomic_store(&b->usb_to_pty_alive, 0);
    logprintf("[%s] USB->PTY thread exiting\n", b->func_name);

    pthread_mutex_lock(&g_exit_mutex);
    pthread_cond_signal(&g_exit_cond);
    pthread_mutex_unlock(&g_exit_mutex);

    return NULL;
}

/* ── Thread: PTY master → USB bulk OUT ── */

static void *pty_to_usb(void *arg) {
    bridge_t *b = (bridge_t *)arg;
    UInt8 buf[USB_BUF_SIZE];
    IOReturn kr;

    atomic_store(&b->pty_to_usb_alive, 1);
    logprintf("[%s] PTY->USB thread started\n", b->func_name);

    /* Use non-blocking reads with poll so we can check g_running frequently */
    int flags = fcntl(b->pty_master, F_GETFL, 0);
    if (flags >= 0)
        fcntl(b->pty_master, F_SETFL, flags | O_NONBLOCK);

    while (atomic_load(&g_running) && atomic_load(&b->state) == BRIDGE_RUNNING) {
        ssize_t n = read(b->pty_master, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                /* No data available — brief sleep then recheck state */
                usleep(10000);  /* 10ms */
                continue;
            }
            if (errno == EIO) {
                /* No slave open yet — wait for a client to connect */
                usleep(10000);  /* 10ms */
                continue;
            }
            break;  /* real error (e.g. EBADF from closed master during shutdown) */
        }
        if (n == 0) {
            /* Slave side closed or not open — wait and retry */
            usleep(10000);  /* 10ms */
            continue;
        }

        /* Re-check state before attempting USB write (avoids blocking on dead interface) */
        if (!atomic_load(&g_running) || atomic_load(&b->state) != BRIDGE_RUNNING)
            break;

        kr = (*b->iface)->WritePipe(b->iface, b->pipe_out, buf, (UInt32)n);
        if (kr != kIOReturnSuccess) {
            if (kr == kIOReturnAborted || kr == kIOReturnNotResponding)
                break;
            logprintf("[%s] WritePipe error: 0x%x\n", b->func_name, kr);
        }
    }

    atomic_store(&b->pty_to_usb_alive, 0);
    logprintf("[%s] PTY->USB thread exiting\n", b->func_name);

    pthread_mutex_lock(&g_exit_mutex);
    pthread_cond_signal(&g_exit_cond);
    pthread_mutex_unlock(&g_exit_mutex);

    return NULL;
}

/* ── QMI passthrough bridge ──────────────────────────
 *
 * A Qualcomm QMI (UIM/control) interface is message-framed (QMUX), not a byte
 * stream, so the PTY bridge above is the wrong shape for it. We expose it as an
 * AF_UNIX socket, letting an on-macOS LPA talk QMI without libqmi or the Linux
 * cdc-wdm/qmi_wwan drivers.
 *
 * USB transport:
 * this interface is a qmi_wwan / cdc-wdm function. The QMI control channel does
 * NOT ride the bulk pair — those carry RMNET/IP network data. QMUX travels over
 * ep0 as CDC-WDM **encapsulated** class requests, gated on an interrupt-IN
 * notification (e.g. the FM101-GL exposes interrupt EP 0x88 + bulk 0x8e/0x0f):
 *   - host->modem: SEND_ENCAPSULATED_COMMAND  (bmRequestType 0x21, bRequest 0x00,
 *                  wValue 0, wIndex = iface, data = one QMUX frame).
 *   - modem->host: the interrupt-IN EP delivers RESPONSE_AVAILABLE (0x01); the
 *                  host then pulls the reply with GET_ENCAPSULATED_RESPONSE
 *                  (bmRequestType 0xA1, bRequest 0x01, wValue 0, wIndex = iface),
 *                  up to wMaxCommand bytes (we use QMI_MAX_CONTROL).
 *
 * Socket transport: the natural fit is SOCK_SEQPACKET (one datagram == one QMUX
 * frame), but **macOS AF_UNIX does not support SOCK_SEQPACKET** — socket() there
 * returns EPROTONOSUPPORT (verified live). Darwin unix sockets are STREAM or
 * DGRAM only, so we use SOCK_STREAM (connection-oriented accept() model) and let
 * the peer reassemble the byte stream by the QMUX length field. Each
 * GET_ENCAPSULATED_RESPONSE already yields one whole frame, which we write to the
 * client with a single stream write; the client-side stream is reframed via
 * qmi_head_frame() before each SEND_ENCAPSULATED_COMMAND.
 *
 * QMUX wire framing:
 *     0x01 | len:u16 LE | flags | service | client | <SDU...>
 * where `len` counts every byte after the 0x01 tag, so a whole frame is
 * (1 + len) bytes. A socket recv may carry several frames or end mid frame, so
 * the sock->modem direction accumulates bytes and slices via qmi_head_frame(). */

#define QMUX_TAG        0x01
#define QMI_ACCUM_MAX   65536   /* reassembly ceiling; QMUX frames are < 4 KiB */
#define QMI_MAX_CONTROL 4096    /* GET_ENCAPSULATED_RESPONSE buffer (cdc-wdm wMaxCommand) */

/* CDC-WDM encapsulated class requests (USB CDC spec, WMC subclass). */
#define QMI_SEND_ENCAPSULATED_COMMAND  0x00
#define QMI_GET_ENCAPSULATED_RESPONSE  0x01
#define QMI_NOTIF_RESPONSE_AVAILABLE   0x01  /* interrupt-IN bNotification */

/* Poll-fallback timing. Several macOS parts (SIM7600NA, EM7455,
 * MC7700) accept a SEND but never deliver the RESPONSE_AVAILABLE interrupt to
 * the daemon, and the FM101-GL control channel can wedge the same way — all
 * present as a `healthy` bridge that never answers. If a SEND gets no interrupt
 * within QMI_POLL_TIMEOUT_MS, the modem->sock runloop polls
 * GET_ENCAPSULATED_RESPONSE directly (interrupt stays the fast path for the
 * parts that do fire). Once a bridge has been rescued by a poll at least once
 * (interrupt provably not delivered by IOKit for this part), it drops to
 * QMI_POLL_FAST_MS so later round-trips don't eat the full timeout. A bridge
 * with an outstanding SEND older than QMI_DEGRADED_MS — command accepted, and
 * even the poll returns nothing — reports `degraded` in status instead of
 * lying `healthy`. */
#define QMI_POLL_TIMEOUT_MS  300
#define QMI_POLL_FAST_MS      40
#define QMI_DEGRADED_MS     2000
/* SO_SNDTIMEO on the QMI client socket. A client that has not drained a
 * byte in this long is stalled, and the runloop thread must not wait on it. */
#define QMI_SEND_TIMEOUT_SEC 3
#define QMI_POLL_GET_TIMEOUT_MS 250  /* bound the poll's GET so a NAKing part
                                      * (SIM7600NA) can't block the runloop */

/* CDC ACM SET_CONTROL_LINE_STATE (USB CDC PSTN spec §6.3.12). Some cdc-wdm
 * modems (e.g. the FM101-GL) will not emit RESPONSE_AVAILABLE notifications until the
 * host activates the control channel by asserting DTR/RTS on the QMI interface;
 * the LM960A18 did not need it. wValue bit0=DTR, bit1=RTS. Sent once after the
 * interrupt read is armed. Value overridable at runtime via QCSERIALD_QMI_DTR
 * (hex/dec; "0" or "off" skips it) for live A/B testing. */
#define QMI_SET_CONTROL_LINE_STATE     0x22
#define QMI_DTR_DEFAULT                0x0003  /* DTR | RTS */

/* Return the byte length of the complete QMUX frame at acc[0], or 0 if a whole
 * frame isn't buffered yet. Drops any leading garbage (resync) and bogus-length
 * tag bytes by shifting `acc` down in place, so on a 0 return acc[0] is either a
 * valid tag with an incomplete frame, or the buffer is empty. Shared by both
 * bridge directions. */
static size_t qmi_head_frame(UInt8 *acc, size_t *acc_len, const char *tag)
{
    for (;;) {
        if (*acc_len < 3)
            return 0;
        if (acc[0] != QMUX_TAG) {
            /* Desync: hunt for the next tag byte rather than wedging. */
            size_t skip = 1;
            while (skip < *acc_len && acc[skip] != QMUX_TAG)
                skip++;
            logprintf("[%s] QMI: resync, dropped %zu byte(s) before tag\n",
                      tag, skip);
            memmove(acc, acc + skip, *acc_len - skip);
            *acc_len -= skip;
            continue;
        }
        size_t framelen = 1 + (size_t)(acc[1] | (acc[2] << 8));
        if (framelen < 4 || framelen > QMI_ACCUM_MAX) {
            logprintf("[%s] QMI: bogus frame len %zu — dropping tag byte\n",
                      tag, framelen);
            memmove(acc, acc + 1, *acc_len - 1);
            (*acc_len)--;
            continue;
        }
        if (*acc_len < framelen)
            return 0;  /* incomplete — wait for more data */
        return framelen;
    }
}

/* Consume `n` bytes from the head of `acc`, shifting the remainder down. */
static void qmi_consume(UInt8 *acc, size_t *acc_len, size_t n)
{
    memmove(acc, acc + n, *acc_len - n);
    *acc_len -= n;
}

/* Write all `n` bytes to the client socket, tolerating short writes and EINTR.
 * Returns 0 on success, -1 if the peer is gone OR has stopped reading.
 *
 * The accepted socket carries SO_SNDTIMEO (see qmi_accept), so EAGAIN here means
 * "this client has not drained a byte in QMI_SEND_TIMEOUT_SEC" -- a stalled
 * peer, not a transient condition. It MUST NOT be retried: this runs on the QMI
 * runloop thread, so spinning would freeze the bridge exactly as the missing
 * timeout used to. Treat it as fatal to the client and let the caller drop it;
 * the daemon keeps serving and a fresh client can connect. EINTR is still
 * a real retry -- a signal, not a slow peer. */
static int qmi_send_all(int fd, const UInt8 *p, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t s = send(fd, p + off, n - off, 0);
        if (s < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (s == 0)
            return -1;
        off += (size_t)s;
    }
    return 0;
}

/* File-scope buffers for the single QMI bridge's async interrupt path (the async
 * completion runs on the run-loop thread, so these outlive any stack frame).
 * Only one QMI bridge exists per daemon instance — enforced at bind time (issue
 * a second QMI interface is refused rather than sharing these buffers), so
 * a single set suffices. Move these into bridge_t to lift that bound. */
static UInt8 g_qmi_notif[64];
static UInt8 g_qmi_resp[QMI_MAX_CONTROL];

/* CDC interrupt notifications must be read ONE USB packet at a time. On macOS
 * IOKit, sizing an interrupt ReadPipeAsync to a multiple of wMaxPacketSize makes
 * the pipe accumulate that many packets before the async read completes — so a
 * 64-byte read on an 8-byte cdc-wdm interrupt EP coalesces up to 8 notifications
 * into one late completion, burying the RESPONSE_AVAILABLE (0xa1 0x01) behind an
 * earlier notification where the [1]==RESPONSE_AVAILABLE gate never sees it (the
 * "SEND ACKs but the modem stays silent" failure; Linux reads exactly
 * wMaxPacketSize and gets a1 01 immediately). Read one packet, clamped to buf. */
static inline UInt32 qmi_intr_read_len(const bridge_t *b) {
    UInt32 mps = b->intr_maxpacket ? b->intr_maxpacket : 8;
    return mps > sizeof(g_qmi_notif) ? (UInt32)sizeof(g_qmi_notif) : mps;
}

/* Monotonic milliseconds, for the QMI poll-fallback timing. */
static uint64_t qmi_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Pull one QMI reply via GET_ENCAPSULATED_RESPONSE and stream it to the client.
 * Returns 1 if the modem returned a reply (round-trip completed, regardless of
 * whether the client write then succeeded), 0 if nothing was waiting. The
 * return + the qmi_responses bump drive the poll-fallback accounting:
 * called both from the interrupt callback and from the runloop poll, always on
 * the modem->sock thread, so there is no concurrency on these fields.
 *
 * timeout_ms > 0 bounds the control transfer via ControlRequestTO — used by the
 * poll fallback, because a part that NAKs GET (observed on the SIM7600NA, which
 * times out GET even when a reply should be waiting) would otherwise block this
 * runloop thread for the full default control timeout (~5s), stalling shutdown
 * and any real interrupt. timeout_ms == 0 keeps the proven unbounded
 * ControlRequest for the interrupt-driven path, where a RESPONSE_AVAILABLE has
 * already fired so the reply is ready and returns immediately. */
static int qmi_get_and_forward(bridge_t *b, UInt32 timeout_ms)
{
    IOReturn kr;
    UInt32 wLenDone;
    if (timeout_ms > 0) {
        IOUSBDevRequestTO req;
        memset(&req, 0, sizeof(req));
        req.bmRequestType = USBmakebmRequestType(kUSBIn, kUSBClass, kUSBInterface);
        req.bRequest = QMI_GET_ENCAPSULATED_RESPONSE;
        req.wValue = 0;
        req.wIndex = b->iface_num;
        req.wLength = QMI_MAX_CONTROL;
        req.pData = g_qmi_resp;
        req.noDataTimeout = timeout_ms;
        req.completionTimeout = timeout_ms;
        kr = (*b->iface)->ControlRequestTO(b->iface, 0, &req);
        wLenDone = req.wLenDone;
    } else {
        IOUSBDevRequest req;
        memset(&req, 0, sizeof(req));
        req.bmRequestType = USBmakebmRequestType(kUSBIn, kUSBClass, kUSBInterface);
        req.bRequest = QMI_GET_ENCAPSULATED_RESPONSE;
        req.wValue = 0;
        req.wIndex = b->iface_num;
        req.wLength = QMI_MAX_CONTROL;
        req.pData = g_qmi_resp;
        kr = (*b->iface)->ControlRequest(b->iface, 0, &req);
        wLenDone = req.wLenDone;
    }
    logprintf("[%s] QMI GET_ENCAPSULATED_RESPONSE: kr=0x%x wLenDone=%u%s\n",
              b->func_name, kr, wLenDone, timeout_ms ? " (poll)" : "");
    if (kr != kIOReturnSuccess || wLenDone == 0)
        return 0;
    /* A reply came back — the round-trip completed. Count it here (not after the
     * client write) so the sends/responses invariant tracks the modem, not the
     * client: a dropped client is a client problem, the modem still answered. */
    atomic_fetch_add(&b->qmi_responses, 1);
    int client = atomic_load(&b->qmi_client_fd);
    if (client < 0)
        return 1;
    if (qmi_send_all(client, g_qmi_resp, wLenDone) < 0) {
        int err = errno;   /* save before logprintf, which may clobber it */
        /* EAGAIN/EWOULDBLOCK is the SO_SNDTIMEO expiry: the client is still
         * connected but has stopped reading. Name it, because it is otherwise
         * indistinguishable in the log from a client that simply went away. */
        if (err == EAGAIN || err == EWOULDBLOCK)
            logprintf("[%s] QMI: client stopped reading (no progress in %ds, "
                      "SO_SNDTIMEO) — dropping it; the daemon keeps serving and a "
                      "fresh client can connect\n",
                      b->func_name, QMI_SEND_TIMEOUT_SEC);
        else
            logprintf("[%s] QMI: client write failed (%s) — dropping client\n",
                      b->func_name, strerror(err));
        /* Drop only the fd we wrote to, and only if it's still the slot's
         * client. A replace on the accept thread may have swapped in a new
         * client since we loaded `client` above; blindly exchanging + closing
         * whatever is in the slot would clobber that new client. */
        int expected = client;
        if (atomic_compare_exchange_strong(&b->qmi_client_fd, &expected, -1))
            close(client);
    }
    return 1;
}

/* Async completion for the interrupt-IN read (the RESPONSE_AVAILABLE
 * notification). Runs on the modem->sock thread's CFRunLoop. arg0 = bytes
 * transferred. Re-arms the read unless shutting down. */
static void qmi_intr_callback(void *refcon, IOReturn result, void *arg0)
{
    bridge_t *b = (bridge_t *)refcon;
    UInt32 nbytes = (UInt32)(uintptr_t)arg0;

    if (result == kIOReturnAborted) {
        CFRunLoopStop(CFRunLoopGetCurrent());
        return;
    }
    if (result == kIOReturnSuccess) {
        logprintf("[%s] QMI: interrupt notif nbytes=%u [%02x %02x %02x %02x]\n",
                  b->func_name, nbytes,
                  nbytes > 0 ? g_qmi_notif[0] : 0, nbytes > 1 ? g_qmi_notif[1] : 0,
                  nbytes > 2 ? g_qmi_notif[2] : 0, nbytes > 3 ? g_qmi_notif[3] : 0);
        /* CDC notification = [bmRequestType, bNotification, wValue(2), wIndex(2),
         * wLength(2)]. RESPONSE_AVAILABLE means a QMI reply is waiting on ep0. */
        if (nbytes >= 2 && g_qmi_notif[1] == QMI_NOTIF_RESPONSE_AVAILABLE)
            qmi_get_and_forward(b, 0);  /* reply is ready — unbounded GET */
    } else {
        logprintf("[%s] QMI: interrupt async result 0x%x\n", b->func_name, result);
        (*b->iface)->ClearPipeStall(b->iface, b->pipe_intr);
    }

    /* Re-arm the interrupt read unless we're shutting down. */
    if (atomic_load(&g_running) && atomic_load(&b->state) == BRIDGE_RUNNING) {
        IOReturn kr = (*b->iface)->ReadPipeAsync(b->iface, b->pipe_intr,
                                                 g_qmi_notif, qmi_intr_read_len(b),
                                                 qmi_intr_callback, b);
        if (kr != kIOReturnSuccess) {
            logprintf("[%s] QMI: re-arm ReadPipeAsync failed 0x%x\n",
                      b->func_name, kr);
            CFRunLoopStop(CFRunLoopGetCurrent());
        }
    } else {
        CFRunLoopStop(CFRunLoopGetCurrent());
    }
}

/* Assert CDC line state (DTR/RTS) on the QMI interface to activate the control
 * channel (the FM101 emits no RESPONSE_AVAILABLE until this is done).
 * Value from QCSERIALD_QMI_DTR (hex or dec; "0"/"off"/"no" skips the request);
 * default DTR|RTS. No-op returns without a control transfer. */
static void qmi_set_control_line_state(bridge_t *b)
{
    UInt16 val = QMI_DTR_DEFAULT;
    const char *env = getenv("QCSERIALD_QMI_DTR");
    if (env && *env) {
        if (strcasecmp(env, "off") == 0 || strcasecmp(env, "no") == 0) {
            logprintf("[%s] QMI: SET_CONTROL_LINE_STATE skipped (QCSERIALD_QMI_DTR=%s)\n",
                      b->func_name, env);
            return;
        }
        val = (UInt16)strtol(env, NULL, 0);  /* 0x.. hex or decimal; "0" => clear */
    }

    IOUSBDevRequest req;
    req.bmRequestType = USBmakebmRequestType(kUSBOut, kUSBClass, kUSBInterface);
    req.bRequest = QMI_SET_CONTROL_LINE_STATE;
    req.wValue = val;
    req.wIndex = b->iface_num;
    req.wLength = 0;
    req.pData = NULL;
    IOReturn kr = (*b->iface)->ControlRequest(b->iface, 0, &req);
    logprintf("[%s] QMI SET_CONTROL_LINE_STATE: kr=0x%x wValue=0x%04x (DTR=%d RTS=%d) wIndex=%d\n",
              b->func_name, kr, val, (val & 1) ? 1 : 0, (val & 2) ? 1 : 0, b->iface_num);
}

/* Thread: modem → socket. Services the interrupt-IN endpoint ASYNCHRONOUSLY via
 * a CFRunLoop — the correct macOS mechanism for interrupt endpoints (a plain
 * synchronous ReadPipe on an interrupt pipe is not serviced reliably; this is
 * how libusb's Darwin backend does it). On each RESPONSE_AVAILABLE notification
 * it pulls the reply with GET_ENCAPSULATED_RESPONSE and streams it to the client.
 * Reuses usb_to_pty_alive so shutdown_bridges() waits on it unchanged. */
static void *qmi_usb_to_sock(void *arg)
{
    bridge_t *b = (bridge_t *)arg;

    atomic_store(&b->usb_to_pty_alive, 1);
    logprintf("[%s] QMI modem->sock thread started (async interrupt pipe %d)\n",
              b->func_name, b->pipe_intr);

    CFRunLoopSourceRef src = NULL;
    IOReturn kr = (*b->iface)->CreateInterfaceAsyncEventSource(b->iface, &src);
    if (kr != kIOReturnSuccess || !src) {
        logprintf("[%s] QMI: CreateInterfaceAsyncEventSource failed 0x%x\n",
                  b->func_name, kr);
        goto out;
    }
    CFRunLoopAddSource(CFRunLoopGetCurrent(), src, kCFRunLoopDefaultMode);

    kr = (*b->iface)->ReadPipeAsync(b->iface, b->pipe_intr,
                                    g_qmi_notif, qmi_intr_read_len(b),
                                    qmi_intr_callback, b);
    if (kr != kIOReturnSuccess) {
        logprintf("[%s] QMI: initial ReadPipeAsync failed 0x%x\n", b->func_name, kr);
        goto out_src;
    }
    logprintf("[%s] QMI: async listening on interrupt pipe %d for RESPONSE_AVAILABLE\n",
              b->func_name, b->pipe_intr);

    /* Activate the control channel (DTR/RTS) now that the interrupt read is
     * armed — the FM101 stays silent otherwise. */
    qmi_set_control_line_state(b);

    /* Run in short slices so shutdown is noticed promptly. AbortPipe (shutdown
     * step 3b) completes the pending async read with kIOReturnAborted, whose
     * callback stops the loop. Between slices, run the poll fallback: if a
     * SEND has gone unanswered past the timeout, the RESPONSE_AVAILABLE
     * interrupt is not coming — pull the reply directly. This runs on the same
     * thread as qmi_intr_callback, so its qmi_get_and_forward() can never race
     * the interrupt-driven one. */
    while (atomic_load(&g_running) && atomic_load(&b->state) == BRIDGE_RUNNING) {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.2, false);

        uint64_t s = atomic_load(&b->qmi_sends);
        uint64_t r = atomic_load(&b->qmi_responses);
        if (s <= r)
            continue;  /* every SEND answered — nothing outstanding */

        uint64_t now = qmi_now_ms();
        uint64_t since_send = now - atomic_load(&b->qmi_last_send_ms);
        uint64_t wait = b->qmi_poll_seen ? QMI_POLL_FAST_MS : QMI_POLL_TIMEOUT_MS;
        /* Poll only within the QMI_DEGRADED_MS window after the SEND. Past that,
         * neither the interrupt nor the poll answered (e.g. the SIM7600NA, which
         * NAKs GET; or a wedged control channel): give up on this SEND — the bridge reads
         * `degraded` in status — and stop hammering the control pipe until the
         * next SEND resets the window. `qmi_sends` stays ahead of
         * `qmi_responses`, which is exactly what the health check keys on. */
        if (since_send >= QMI_DEGRADED_MS)
            continue;
        /* Wait `wait` ms after the SEND for the interrupt; then poll at most once
         * per `wait` window so a slow-but-working part isn't hammered. */
        if (since_send < wait ||
            now - atomic_load(&b->qmi_last_poll_ms) < wait)
            continue;

        atomic_store(&b->qmi_last_poll_ms, now);
        if (qmi_get_and_forward(b, QMI_POLL_GET_TIMEOUT_MS)) {
            /* Poll produced a reply the interrupt never announced — this part
             * needs the fallback; tighten its timeout for subsequent commands. */
            atomic_fetch_add(&b->qmi_polls, 1);
            if (!b->qmi_poll_seen) {
                b->qmi_poll_seen = 1;
                logprintf("[%s] QMI: interrupt not delivered — poll fallback "
                          "engaged (subsequent round-trips poll after %dms)\n",
                          b->func_name, QMI_POLL_FAST_MS);
            }
        }
    }

out_src:
    if (src) {
        CFRunLoopRemoveSource(CFRunLoopGetCurrent(), src, kCFRunLoopDefaultMode);
        CFRelease(src);
    }
out:
    atomic_store(&b->usb_to_pty_alive, 0);
    logprintf("[%s] QMI modem->sock thread exiting\n", b->func_name);
    pthread_mutex_lock(&g_exit_mutex);
    pthread_cond_signal(&g_exit_cond);
    pthread_mutex_unlock(&g_exit_mutex);
    return NULL;
}

/* Thread: socket → modem. Owns the listener + connected client (one at a time; a
 * new connection replaces the old). Reassembles the client's byte stream into
 * whole QMUX frames and sends each with one SEND_ENCAPSULATED_COMMAND on ep0.
 * Reuses pty_to_usb_alive. */
static void *qmi_sock_to_usb(void *arg)
{
    bridge_t *b = (bridge_t *)arg;
    UInt8 buf[USB_BUF_SIZE];
    static _Thread_local UInt8 acc[QMI_ACCUM_MAX];
    size_t acc_len = 0;

    atomic_store(&b->pty_to_usb_alive, 1);
    logprintf("[%s] QMI sock->USB thread started (socket: %s)\n",
              b->func_name, b->sock_path);

    while (atomic_load(&g_running) && atomic_load(&b->state) == BRIDGE_RUNNING) {
        int client = atomic_load(&b->qmi_client_fd);

        struct pollfd pfds[2];
        int nfds = 0;
        int listen_idx = -1, client_idx = -1;
        if (b->qmi_listen_fd >= 0) {
            pfds[nfds].fd = b->qmi_listen_fd;
            pfds[nfds].events = POLLIN;
            listen_idx = nfds++;
        }
        if (client >= 0) {
            pfds[nfds].fd = client;
            pfds[nfds].events = POLLIN;
            client_idx = nfds++;
        }
        if (nfds == 0) { usleep(100000); continue; }

        int pr = poll(pfds, nfds, 200);
        if (pr <= 0)
            continue;

        /* New connection: accept and (single-client) replace any existing. */
        if (listen_idx >= 0 && (pfds[listen_idx].revents & POLLIN)) {
            int nc = accept(b->qmi_listen_fd, NULL, NULL);
            if (nc >= 0) {
                /* Harden the client socket before it is ever written to.
                 *
                 * SO_NOSIGPIPE: without it a send() to a peer that has gone away
                 * raises SIGPIPE, whose default disposition TERMINATES the
                 * daemon -- taking every bridge down, not just QMI. Measured:
                 * stall the sole client, close it, daemon exits 141 (128+13).
                 *
                 * SO_SNDTIMEO: without it the socket is blocking with no
                 * deadline, so a client that stops reading blocks qmi_send_all()
                 * forever. That send runs on the QMI runloop thread (from
                 * qmi_intr_callback and the poll fallback), so one stalled client
                 * silently freezes the whole QMI bridge. Measured: qmi_sends
                 * climbed to 800 while qmi_responses stuck at 50. */
                int one = 1;
                if (setsockopt(nc, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) < 0)
                    logprintf("[%s] QMI: SO_NOSIGPIPE failed: %s\n",
                              b->func_name, strerror(errno));
                struct timeval sndto = { QMI_SEND_TIMEOUT_SEC, 0 };
                if (setsockopt(nc, SOL_SOCKET, SO_SNDTIMEO, &sndto, sizeof(sndto)) < 0)
                    logprintf("[%s] QMI: SO_SNDTIMEO failed: %s\n",
                              b->func_name, strerror(errno));
                int old = atomic_exchange(&b->qmi_client_fd, nc);
                if (old >= 0) {
                    logprintf("[%s] QMI: replacing existing client\n", b->func_name);
                    close(old);
                }
                acc_len = 0;  /* fresh framing for the new client */
                logprintf("[%s] QMI: client connected\n", b->func_name);
                /* Rebuild the poll set around the just-accepted client before
                 * touching any client fd. `client`/`client_idx`, captured at the
                 * top of this iteration, still refer to the *old* fd we may have
                 * just closed; falling through to the client block would recv()
                 * on that stale fd, hit the disconnect path, and clobber the fd
                 * we just installed (the just-connected client
                 * dropped in <1ms with no recv). */
                continue;
            }
        }

        /* Client stream → reassemble QMUX → one SEND_ENCAPSULATED_COMMAND each. */
        if (client_idx >= 0 && (pfds[client_idx].revents & (POLLIN | POLLHUP))) {
            ssize_t n = recv(client, buf, sizeof(buf), 0);
            if (n <= 0) {
                logprintf("[%s] QMI: client disconnected\n", b->func_name);
                /* Clear the slot only if it still holds the fd we just read, and
                 * close only when that compare-exchange wins. A concurrent
                 * replace (accept) or interrupt-side drop may already own that
                 * fd; closing whatever is *currently* in the slot could clobber
                 * a newer client, or double-close. */
                int expected = client;
                if (atomic_compare_exchange_strong(&b->qmi_client_fd,
                                                   &expected, -1))
                    close(client);
                acc_len = 0;
                continue;
            }
            if (acc_len + (size_t)n > QMI_ACCUM_MAX) {
                logprintf("[%s] QMI: sock accumulator overflow — resetting framing\n",
                          b->func_name);
                acc_len = 0;
                continue;
            }
            logprintf("[%s] QMI: recv %zd byte(s) from client (acc now %zu)\n",
                      b->func_name, n, acc_len + (size_t)n);
            memcpy(acc + acc_len, buf, (size_t)n);
            acc_len += (size_t)n;

            size_t framelen;
            while ((framelen = qmi_head_frame(acc, &acc_len, b->func_name)) > 0) {
                if (!atomic_load(&g_running) ||
                    atomic_load(&b->state) != BRIDGE_RUNNING)
                    goto done;
                IOUSBDevRequest req;
                memset(&req, 0, sizeof(req));
                req.bmRequestType =
                    USBmakebmRequestType(kUSBOut, kUSBClass, kUSBInterface);
                req.bRequest = QMI_SEND_ENCAPSULATED_COMMAND;
                req.wValue = 0;
                req.wIndex = b->iface_num;
                req.wLength = (UInt16)framelen;
                req.pData = acc;
                IOReturn kr = (*b->iface)->ControlRequest(b->iface, 0, &req);
                logprintf("[%s] QMI SEND_ENCAPSULATED_COMMAND: kr=0x%x "
                          "wLength=%zu wLenDone=%u (wIndex=%d)\n",
                          b->func_name, kr, framelen, req.wLenDone, b->iface_num);
                if (kr == kIOReturnSuccess) {
                    /* Arm the poll fallback: record the SEND so the
                     * modem->sock runloop can poll for the reply if no
                     * RESPONSE_AVAILABLE interrupt arrives within the timeout.
                     * Order matters — stamp the time before bumping the count so
                     * the runloop never sees sends>responses with a stale/zero
                     * timestamp. */
                    atomic_store(&b->qmi_last_send_ms, qmi_now_ms());
                    atomic_fetch_add(&b->qmi_sends, 1);
                } else {
                    if (kr == kIOReturnAborted || kr == kIOReturnNotResponding)
                        goto done;
                    logprintf("[%s] QMI SEND_ENCAPSULATED_COMMAND: 0x%x\n",
                              b->func_name, kr);
                }
                qmi_consume(acc, &acc_len, framelen);
            }
        }
    }
done:;

    atomic_store(&b->pty_to_usb_alive, 0);
    logprintf("[%s] QMI sock->USB thread exiting\n", b->func_name);
    pthread_mutex_lock(&g_exit_mutex);
    pthread_cond_signal(&g_exit_cond);
    pthread_mutex_unlock(&g_exit_mutex);
    return NULL;
}

/* Create the AF_UNIX SOCK_STREAM listener for a QMI bridge. (SEQPACKET would be
 * the natural fit but macOS AF_UNIX doesn't support it — see the transport note
 * above.) Returns 0 on success (b->qmi_listen_fd / b->sock_path populated), -1
 * on failure. */
static int qmi_setup_socket(bridge_t *b)
{
    /* The socket directory is resolved by an actual bind(), NOT inferred from the
     * symlink probe that chose g_symlink_dir. g_symlink_dir may be
     * native /dev (devfs) on a host where /dev symlinks are permitted, and devfs
     * is a synthetic filesystem that need not support AF_UNIX socket inodes — a
     * capability the symlink probe never tested. So try g_symlink_dir first (the
     * common case: the socket lives beside the PTY symlinks), and if bind() there
     * fails, fall back to the invoking user's ~/dev on a real filesystem. The
     * socket and the serial symlinks may then live in different directories; the
     * startup banner and README note the socket's own path.
     *
     * On the SIP-enabled hosts tested to date, g_symlink_dir is already ~/dev (a
     * real fs) because the /dev symlink probe fails first, so bind() succeeds on
     * the first candidate and this fallback never runs — the working path is
     * unchanged. */
    char cand[2][512];
    int ncand = 0;
    snprintf(cand[ncand++], sizeof(cand[0]), "%s", g_symlink_dir);

    char home_dev[512];
    if (resolve_home_dev_dir(home_dev, sizeof(home_dev), NULL) == 0 &&
        strcmp(home_dev, g_symlink_dir) != 0) {
        snprintf(cand[ncand++], sizeof(cand[0]), "%s", home_dev);
    }

    int last_errno = 0;
    for (int i = 0; i < ncand; i++) {
        /* Best-effort ensure the directory exists (the ~/dev fallback may not
         * have been created by resolve_symlink_dir when /dev was chosen). */
        struct stat dst;
        if (stat(cand[i], &dst) != 0)
            mkdir(cand[i], 0755);

        char path[600];
        snprintf(path, sizeof(path), "%s/%s", cand[i], QMI_SOCK_NAME);

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        if (strlen(path) >= sizeof(addr.sun_path)) {
            logprintf("QMI: socket path too long: %s\n", path);
            continue;
        }
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            logprintf("QMI: socket() failed: %s\n", strerror(errno));
            return -1;
        }

        unlink(path);  /* clear any stale socket from a prior run */
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            last_errno = errno;
            logprintf("QMI: bind(%s) failed: %s%s\n", path, strerror(errno),
                      (i + 1 < ncand) ? " — trying a real-filesystem fallback" : "");
            close(fd);
            continue;
        }

        /* World-accessible so a non-root LPA can connect (mirrors PTY chmod 0666). */
        chmod(path, 0666);
        if (listen(fd, 1) < 0) {
            last_errno = errno;
            logprintf("QMI: listen(%s) failed: %s\n", path, strerror(errno));
            close(fd);
            unlink(path);
            continue;
        }

        snprintf(b->sock_path, sizeof(b->sock_path), "%s", path);
        if (strcmp(cand[i], g_symlink_dir) != 0)
            logprintf("QMI: socket bound in %s (not the symlink dir %s — devfs "
                      "does not support socket inodes)\n",
                      cand[i], g_symlink_dir);
        b->qmi_listen_fd = fd;
        atomic_store(&b->qmi_client_fd, -1);
        return 0;
    }

    logprintf("QMI: could not bind the QMI socket in any candidate directory "
              "(last error: %s); QMI passthrough unavailable\n",
              last_errno ? strerror(last_errno) : "unknown");
    return -1;
}

/* ── USB device recovery ──
 *
 * When USBInterfaceOpen() fails with kIOReturnExclusiveAccess after an unclean
 * shutdown, attempt to clear stale locks via device-level seize + re-enumeration.
 * This is only used in the recovery path — normal operation never opens the device.
 */

static int attempt_usb_recovery(io_service_t device_service) {
    IOCFPlugInInterface **plug = NULL;
    IOUSBDeviceInterface187 **dev = NULL;
    SInt32 score;
    IOReturn kr;

    kr = IOCreatePlugInInterfaceForService(device_service,
            kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID,
            &plug, &score);
    if (kr != kIOReturnSuccess || !plug) {
        logprintf("Recovery: failed to create device plugin: 0x%x\n", kr);
        return -1;
    }

    (*plug)->QueryInterface(plug,
            CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID187),
            (LPVOID *)&dev);
    (*plug)->Release(plug);
    if (!dev) {
        logprintf("Recovery: failed to get device interface\n");
        return -1;
    }

    /* Seize the device — may succeed even with stale interface locks since
     * our normal path never does USBDeviceOpen(). */
    kr = (*dev)->USBDeviceOpenSeize(dev);
    if (kr != kIOReturnSuccess) {
        logprintf("Recovery: USBDeviceOpenSeize failed: 0x%x\n", kr);
        (*dev)->Release(dev);
        return -1;
    }

    /* Re-enumerate: terminates all clients, simulates unplug/replug */
    logprintf("Recovery: triggering USB re-enumeration to clear stale locks...\n");
    kr = (*dev)->USBDeviceReEnumerate(dev, 0);

    (*dev)->USBDeviceClose(dev);
    (*dev)->Release(dev);

    if (kr != kIOReturnSuccess) {
        logprintf("Recovery: USBDeviceReEnumerate failed: 0x%x\n", kr);
        return -1;
    }

    /* Wait for re-enumeration to complete — device disappears and re-appears.
     * 5s is needed for the kernel to tear down old services, re-probe the
     * device, create new IOUSBHostInterface children, and populate properties. */
    logprintf("Recovery: waiting for USB re-enumeration (5s)...\n");
    sleep(5);
    return 0;
}

/* ── Setup: find USB device and open interfaces ── */

/* Read a device's USB serial string into out (empty on failure). Mirrors the
 * existing "USB Product Name" read style. */
static void read_usb_serial(io_service_t dev, char *out, size_t outlen) {
    out[0] = '\0';
    CFStringRef s = IORegistryEntryCreateCFProperty(dev, CFSTR("USB Serial Number"),
                                                    kCFAllocatorDefault, 0);
    if (s) {
        CFStringGetCString(s, out, outlen, kCFStringEncodingUTF8);
        CFRelease(s);
    }
}

/* True when a device selector is active (any of --match vid/pid, --serial). */
static int selector_active(void) {
    return g_match_vid >= 0 || g_match_pid >= 0 || g_match_serial[0] != '\0';
}

/* True when (vid,pid,serial) satisfies the active selector. Unset selector
 * fields match anything; serial compare is case-insensitive exact. */
static int device_matches_selector(int vid, int pid, const char *serial) {
    if (g_match_vid >= 0 && vid != g_match_vid) return 0;
    if (g_match_pid >= 0 && pid != g_match_pid) return 0;
    if (g_match_serial[0] && strcasecmp(serial, g_match_serial) != 0) return 0;
    return 1;
}

static int setup_bridges(void) {
    g_edl_detected = 0;
    g_edl_product[0] = '\0';

    /* Find the USB device — match all IOUSBHostDevice, filter VID manually */
    CFMutableDictionaryRef match = IOServiceMatching("IOUSBHostDevice");
    if (!match) {
        logprintf("Failed to create matching dict\n");
        return -1;
    }

    io_iterator_t dev_iter;
    IOReturn kr = IOServiceGetMatchingServices(kIOMainPortDefault, match, &dev_iter);
    if (kr != kIOReturnSuccess) {
        logprintf("IOServiceGetMatchingServices failed: 0x%x\n", kr);
        return -1;
    }

    io_service_t device = IO_OBJECT_NULL;
    const char *matched_vendor = NULL;
    int matched_vid = 0, matched_pid = 0;
    io_service_t candidate;
    while ((candidate = IOIteratorNext(dev_iter))) {
        CFNumberRef vid_ref = IORegistryEntryCreateCFProperty(candidate, CFSTR("idVendor"),
                                                               kCFAllocatorDefault, 0);
        if (vid_ref) {
            int vid = 0;
            CFNumberGetValue(vid_ref, kCFNumberIntType, &vid);
            CFRelease(vid_ref);
            matched_vendor = vendor_name(vid);
            if (matched_vendor) {
                matched_vid = vid;
                /* Also get PID for interface mapping */
                CFNumberRef pid_ref = IORegistryEntryCreateCFProperty(candidate, CFSTR("idProduct"),
                                                                       kCFAllocatorDefault, 0);
                if (pid_ref) {
                    CFNumberGetValue(pid_ref, kCFNumberIntType, &matched_pid);
                    CFRelease(pid_ref);
                }
                /* Skip EDL-mode devices — they use Sahara/Firehose,
                 * not serial. Bridging them blocks qfenix libusb. */
                if (is_edl_device((uint16_t)vid, (uint16_t)matched_pid)) {
                    g_edl_detected = 1;
                    /* Grab product name for status display */
                    CFStringRef prod = IORegistryEntryCreateCFProperty(
                        candidate, CFSTR("USB Product Name"),
                        kCFAllocatorDefault, 0);
                    if (prod) {
                        CFStringGetCString(prod, g_edl_product,
                                           sizeof(g_edl_product),
                                           kCFStringEncodingUTF8);
                        CFRelease(prod);
                    } else {
                        snprintf(g_edl_product, sizeof(g_edl_product),
                                 "VID 0x%04x PID 0x%04x", vid, matched_pid);
                    }
                    logprintf("EDL device detected: %s (libusb port — skipping)\n",
                              g_edl_product);
                    IOObjectRelease(candidate);
                    matched_vendor = NULL;
                    continue;
                }
                /* Device selection: when a selector is active, skip any
                 * supported, non-EDL candidate that doesn't match it and keep
                 * scanning. Unset selector ⇒ first-match wins, as before. */
                if (selector_active()) {
                    char serial[64];
                    read_usb_serial(candidate, serial, sizeof(serial));
                    if (!device_matches_selector(vid, matched_pid, serial)) {
                        IOObjectRelease(candidate);
                        matched_vendor = NULL;
                        continue;
                    }
                }
                device = candidate;
                break;
            }
        }
        IOObjectRelease(candidate);
    }
    IOObjectRelease(dev_iter);

    if (!device) {
        /* Selector active but nothing matched: say so ONCE (setup_bridges runs
         * every rescan, ~5s) so the retry loop isn't silent and we don't quietly
         * grab an unrelated modem. Re-armed on the next successful match. */
        if (selector_active() && !g_logged_no_match) {
            char want[96];
            int n = 0;
            if (g_match_vid >= 0 || g_match_pid >= 0)
                n += snprintf(want + n, sizeof(want) - n, "vid:pid=%04x:%04x",
                              g_match_vid < 0 ? 0 : g_match_vid,
                              g_match_pid < 0 ? 0 : g_match_pid);
            if (g_match_serial[0])
                snprintf(want + n, sizeof(want) - n, "%sserial=%s",
                         n ? " " : "", g_match_serial);
            logprintf("No device matched selector (%s) — will keep retrying\n", want);
            g_logged_no_match = 1;
        }
        return -1;  /* No modem found — caller will retry */
    }
    g_logged_no_match = 0;  /* re-arm the no-match log for future rescans */

    /* Log the bound unit's USB serial too: on hosts with two modems that share
     * an identical VID:PID (e.g. two LM960A18-CP at 0x1bc7:0x1040) the vendor/VID/
     * PID/product lines are identical, so the serial is the only field that
     * identifies which physical unit was bound. Read unconditionally (not only
     * under a --serial selector); "-" when the device exposes no serial. */
    char bound_serial[64];
    read_usb_serial(device, bound_serial, sizeof(bound_serial));
    logprintf("Matched vendor: %s (VID 0x%04x PID 0x%04x serial %s)\n",
              matched_vendor, matched_vid, matched_pid,
              bound_serial[0] ? bound_serial : "-");
    g_matched_vid = matched_vid;

    /* Store sessionID for re-enumeration detection in monitor */
    CFNumberRef sessionRef = IORegistryEntryCreateCFProperty(device,
        CFSTR("sessionID"), kCFAllocatorDefault, 0);
    if (sessionRef) {
        long long sid = 0;
        CFNumberGetValue(sessionRef, kCFNumberLongLongType, &sid);
        g_session_id = (uint64_t)sid;
        CFRelease(sessionRef);
    }

    /* Get product name */
    CFStringRef product = IORegistryEntryCreateCFProperty(device, CFSTR("USB Product Name"),
                                                          kCFAllocatorDefault, 0);
    if (product) {
        char name[128];
        CFStringGetCString(product, name, sizeof(name), kCFStringEncodingUTF8);
        logprintf("Found: %s\n", name);
        CFRelease(product);
    }

    /* IOUSBHostDevice appears in the IOKit registry before its pipe
     * endpoints are fully configured. Opening interfaces too early
     * results in ReadPipe returning kIOReturnNotOpen (0xe00002c0) on
     * every call. A 2s delay lets the USB host stack finish setting
     * up bulk endpoint transfers. Harmless on startup when the device
     * has been present for a while. */
    sleep(2);

    /* Look up known DIAG interface number for this VID/PID */
    int known_diag_iface = get_diag_iface((uint16_t)matched_vid, (uint16_t)matched_pid);
    /* Multi-candidate QMI disambiguation: -1 unless this VID/PID pins a specific
     * QMI control-interface number (e.g. the MC7700 pins iface 8). */
    int qmi_iface_pinned = get_qmi_iface((uint16_t)matched_vid, (uint16_t)matched_pid);

    /* Find vendor-specific interfaces via IOKit registry (no device-level exclusive access needed).
     * This avoids USBDeviceOpen() which would block ADB and cause stale-lock issues. */
    io_iterator_t child_iter;
    kr = IORegistryEntryCreateIterator(device, kIOServicePlane,
                                        kIORegistryIterateRecursively, &child_iter);
    if (kr != kIOReturnSuccess) {
        logprintf("Failed to create child iterator: 0x%x\n", kr);
        IOObjectRelease(device);
        return -1;
    }

    int exclusive_access_hit = 0;
    int iface_count = 0;  /* total vendor-specific non-ADB interfaces found */
    io_service_t child;
    while ((child = IOIteratorNext(child_iter)) && g_bridge_count < MAX_INTERFACES) {
        /* Only process IOUSBHostInterface nodes */
        if (!IOObjectConformsTo(child, "IOUSBHostInterface")) {
            IOObjectRelease(child);
            continue;
        }

        /* Filter for vendor-specific class (0xFF) */
        CFNumberRef class_ref = IORegistryEntryCreateCFProperty(child, CFSTR("bInterfaceClass"),
                                                                  kCFAllocatorDefault, 0);
        if (!class_ref) { IOObjectRelease(child); continue; }
        int iface_class = 0;
        CFNumberGetValue(class_ref, kCFNumberIntType, &iface_class);
        CFRelease(class_ref);
        if (iface_class != 0xFF) { IOObjectRelease(child); continue; }

        io_service_t iface_service = child;  /* renamed for clarity below */
        IOCFPlugInInterface **iplug = NULL;
        IOUSBInterfaceInterface300 **iface = NULL;
        SInt32 iscore;

        kr = IOCreatePlugInInterfaceForService(iface_service,
                                                kIOUSBInterfaceUserClientTypeID,
                                                kIOCFPlugInInterfaceID, &iplug, &iscore);
        IOObjectRelease(iface_service);
        if (kr != kIOReturnSuccess || !iplug) continue;

        (*iplug)->QueryInterface(iplug, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID300),
                                (LPVOID *)&iface);
        (*iplug)->Release(iplug);
        if (!iface) continue;

        UInt8 iface_num = 0;
        (*iface)->GetInterfaceNumber(iface, &iface_num);

        UInt8 iface_subclass = 0, iface_protocol = 0;
        (*iface)->GetInterfaceSubClass(iface, &iface_subclass);
        (*iface)->GetInterfaceProtocol(iface, &iface_protocol);

        /* Skip ADB interface (subclass 0x42, protocol 0x01) */
        if (iface_subclass == 0x42 && iface_protocol == 0x01) {
            logprintf("Skipping ADB interface %d (use 'adb devices' directly)\n", iface_num);
            (*iface)->Release(iface);
            continue;
        }

        /* Skip QMI/RmNet interface. QMI is a binary (QMUX-framed) modem
         * control protocol, not a serial byte stream, so bridging it to a PTY
         * and AT-probing it is wrong on both counts.
         *   - 0xFF/0xFF/0xFF: QMI/RmNet on many Qualcomm modems.
         *   - 0xFF/0xFF/0x50: the qmi_wwan (RMNET/QMI) channel on the Fibocom
         *     FM101-GL mode 17 (2cb7:0104, interface 4); Linux binds it as
         *     cdc-wdm0. Protocol 0x50 != 0xFF, so the old check missed it and
         *     the interface got mis-bridged as a bogus port + AT-probed.
         * Distinct from DIAG which is 0xFF/0xFF/0x30.
         * A serial_iface_maps[] entry exempts a named interface from this skip
         * so a real AT/NMEA function that happens to wear the RmNet descriptor
         * falls through to the serial-PTY bridge instead of being discarded. */
        if (iface_subclass == 0xFF &&
            (iface_protocol == 0xFF || iface_protocol == 0x50) &&
            !is_serial_iface((uint16_t)matched_vid, (uint16_t)matched_pid, iface_num)) {
            if (!g_qmi_socket_enabled) {
                logprintf("Skipping QMI/RmNet interface %d (subclass 0x%02x proto 0x%02x)\n",
                          iface_num, iface_subclass, iface_protocol);
                (*iface)->Release(iface);
                continue;
            }

            /* Multi-candidate QMI disambiguation: when this VID/PID pins a
             * specific QMI interface number, bind ONLY that one and skip every
             * other 0xFF QMI candidate (e.g. the MC7700's iface 3 DM/serial
             * function, whose interrupt EP emits SERIAL_STATE and whose ep0
             * rejects SEND_ENCAPSULATED). This runs before USBInterfaceOpen, so
             * a skipped candidate is never opened. Unlisted modems have
             * qmi_iface_pinned == -1 and keep the default first-match selection
             * byte-for-byte. */
            if (qmi_iface_pinned >= 0 && iface_num != qmi_iface_pinned) {
                logprintf("QMI interface %d: skipping — modem 0x%04x:0x%04x pins "
                          "QMI to interface %d; this interface is not the cdc-wdm "
                          "QMI control function\n",
                          iface_num, matched_vid, matched_pid, qmi_iface_pinned);
                (*iface)->Release(iface);
                continue;
            }

            /* ── QMI passthrough enabled: expose as a unix socket ── */
            logprintf("QMI interface %d (subclass 0x%02x proto 0x%02x): "
                      "exposing as unix stream socket\n",
                      iface_num, iface_subclass, iface_protocol);

            kr = (*iface)->USBInterfaceOpen(iface);
            if (kr != kIOReturnSuccess) {
                if (kr == (IOReturn)0xe00002c5)
                    exclusive_access_hit = 1;
                logprintf("QMI: failed to open interface %d: 0x%x\n", iface_num, kr);
                (*iface)->Release(iface);
                continue;
            }

            UInt8 qn_ep = 0;
            (*iface)->GetNumEndpoints(iface, &qn_ep);
            UInt8 q_in = 0, q_out = 0, q_intr = 0;
            UInt16 q_intr_mps = 0;
            for (UInt8 i = 1; i <= qn_ep; i++) {
                UInt8 dir, num, ttype, ival; UInt16 mps;
                (*iface)->GetPipeProperties(iface, i, &dir, &num, &ttype, &mps, &ival);
                /* Log the full descriptor so the pipe->endpoint mapping can be
                 * confirmed against the modem's real addresses (that pipe_intr
                 * is the interrupt IN and the bulk pair is right). The
                 * endpoint address is (dir<<7)|num: dir 1=IN. */
                const char *tname = ttype == kUSBBulk ? "bulk" :
                                    ttype == kUSBInterrupt ? "interrupt" :
                                    ttype == kUSBControl ? "control" : "iso";
                logprintf("QMI iface %d pipe %d: ep 0x%02x %s-%s maxPacket=%u interval=%u\n",
                          iface_num, i, (unsigned)((dir == kUSBIn ? 0x80 : 0) | num),
                          tname, dir == kUSBIn ? "IN" : "OUT", mps, ival);
                if (ttype == kUSBBulk) {
                    /* Bulk pair carries RMNET/IP data, not QMI — recorded but
                     * unused by the encapsulated QMI bridge. */
                    if (dir == kUSBIn && q_in == 0) q_in = i;
                    else if (dir == kUSBOut && q_out == 0) q_out = i;
                } else if (ttype == kUSBInterrupt && dir == kUSBIn && q_intr == 0) {
                    q_intr = i;  /* RESPONSE_AVAILABLE notifications (cdc-wdm) */
                    q_intr_mps = mps;
                }
            }
            /* QMI control travels over ep0 (SEND/GET_ENCAPSULATED) gated on the
             * interrupt-IN notification, so the interrupt EP is what we require. */
            if (q_intr == 0) {
                logprintf("QMI interface %d: unsupported — QMI passthrough needs "
                          "an interrupt IN endpoint (RESPONSE_AVAILABLE "
                          "notifications), and this modem's QMI function exposes "
                          "none; no QMI socket will be created for it\n",
                          iface_num);
                (*iface)->USBInterfaceClose(iface);
                (*iface)->Release(iface);
                continue;
            }

            /* One QMI bridge per daemon instance. The async interrupt path uses
             * file-scope buffers (g_qmi_notif / g_qmi_resp), and the socket name
             * is a single fixed path, so a second QMI bridge would corrupt the
             * first's in-flight response and bind over its socket. Modems in the
             * tested set expose one QMI function each, so this is a bound rather
             * than a live limit — but it is enforced, not assumed. */
            int qmi_already_bound = 0;
            for (int bi = 0; bi < g_bridge_count; bi++) {
                if (g_bridges[bi].is_qmi) { qmi_already_bound = 1; break; }
            }
            if (qmi_already_bound) {
                logprintf("QMI interface %d: refusing to bind a second QMI "
                          "bridge — this daemon supports one QMI interface\n",
                          iface_num);
                (*iface)->USBInterfaceClose(iface);
                (*iface)->Release(iface);
                continue;
            }

            bridge_t *qb = &g_bridges[g_bridge_count];
            memset(qb, 0, sizeof(*qb));
            qb->iface_num = iface_num;
            qb->pty_master = -1;   /* not a PTY — keep shutdown's close() guards off */
            qb->pty_slave = -1;
            qb->iface = iface;
            qb->pipe_in = q_in;
            qb->pipe_out = q_out;
            qb->pipe_intr = q_intr;
            qb->intr_maxpacket = q_intr_mps;
            qb->is_qmi = 1;
            qb->qmi_listen_fd = -1;
            atomic_store(&qb->qmi_client_fd, -1);
            snprintf(qb->func_name, sizeof(qb->func_name), "qmi");
            atomic_store(&qb->state, BRIDGE_RUNNING);

            if (qmi_setup_socket(qb) < 0) {
                logprintf("QMI: socket setup failed for interface %d\n", iface_num);
                (*iface)->USBInterfaceClose(iface);
                (*iface)->Release(iface);
                continue;
            }
            snprintf(qb->link_name, sizeof(qb->link_name), "%s", qb->sock_path);

            logprintf("Interface %d (qmi): unix stream socket -> %s\n",
                      iface_num, qb->sock_path);
            logprintf("  Bulk IN pipe %d, Bulk OUT pipe %d, Intr IN pipe %d, %d endpoints\n",
                      q_in, q_out, q_intr, qn_ep);

            pthread_attr_t qattr;
            pthread_attr_init(&qattr);
            pthread_attr_setdetachstate(&qattr, PTHREAD_CREATE_DETACHED);
            pthread_create(&qb->usb_to_pty_thread, &qattr, qmi_usb_to_sock, qb);
            pthread_create(&qb->pty_to_usb_thread, &qattr, qmi_sock_to_usb, qb);
            pthread_attr_destroy(&qattr);

            iface_count++;
            g_bridge_count++;
            continue;
        }

        iface_count++;
        kr = (*iface)->USBInterfaceOpen(iface);
        if (kr != kIOReturnSuccess) {
            if (kr == (IOReturn)0xe00002c5)  /* kIOReturnExclusiveAccess */
                exclusive_access_hit = 1;
            logprintf("Failed to open interface %d: 0x%x\n", iface_num, kr);
            (*iface)->Release(iface);
            continue;
        }

        /* Find bulk IN and OUT endpoints */
        UInt8 num_endpoints = 0;
        (*iface)->GetNumEndpoints(iface, &num_endpoints);

        UInt8 pipe_in = 0, pipe_out = 0;
        for (UInt8 i = 1; i <= num_endpoints; i++) {
            UInt8 direction, number, transfer_type, interval;
            UInt16 max_packet;
            (*iface)->GetPipeProperties(iface, i, &direction, &number,
                                         &transfer_type, &max_packet, &interval);
            if (transfer_type == kUSBBulk) {
                if (direction == kUSBIn && pipe_in == 0)
                    pipe_in = i;
                else if (direction == kUSBOut && pipe_out == 0)
                    pipe_out = i;
            }
        }

        if (pipe_in == 0 || pipe_out == 0) {
            logprintf("Interface %d: no bulk IN/OUT pair, skipping\n", iface_num);
            (*iface)->USBInterfaceClose(iface);
            (*iface)->Release(iface);
            continue;
        }

        /* Create PTY pair */
        int master, slave;
        char slave_name[256];
        if (openpty(&master, &slave, slave_name, NULL, NULL) < 0) {
            perror("openpty");
            (*iface)->USBInterfaceClose(iface);
            (*iface)->Release(iface);
            continue;
        }

        /* Set raw mode on PTY */
        struct termios tio;
        tcgetattr(master, &tio);
        cfmakeraw(&tio);
        tcsetattr(master, TCSANOW, &tio);

        /* Make PTY slave accessible to non-root users.
         * Close slave fd so pty_slave_is_open() can detect when no
         * external client has the slave open (write returns EIO).
         * The PTY pair stays valid as long as the master fd is open;
         * external processes can still open the slave via the symlink. */
        chmod(slave_name, 0666);
        close(slave);
        slave = -1;

        /* Determine port name:
         * 1. DIAG: protocol 0x30, OR VID/PID table match on interface number
         * 2. ADB: already skipped above
         * 3. Everything else: "port<N>" using interface number */
        char func_buf[32];
        const char *func;
        if (iface_subclass == 0xFF && iface_protocol == 0x30) {
            func = "diag";
        } else if (iface_num == known_diag_iface && iface_protocol != 0x30) {
            /* VID/PID table says this interface is DIAG but it lacks the
             * protocol marker — trust the table */
            func = "diag";
        } else {
            snprintf(func_buf, sizeof(func_buf), "port%d-loading", iface_num);
            func = func_buf;
        }

        /* Create a symlink with a friendly name */
        char link[256];
        make_symlink_path(link, sizeof(link), func);
        unlink(link);
        if (symlink(slave_name, link) < 0) {
            logprintf("Warning: symlink %s -> %s failed: %s\n",
                      link, slave_name, strerror(errno));
            snprintf(link, sizeof(link), "%s", slave_name);
        }

        bridge_t *b = &g_bridges[g_bridge_count];
        memset(b, 0, sizeof(*b));
        b->iface_num = iface_num;
        b->pty_master = master;
        b->pty_slave = slave;
        strncpy(b->pty_name, slave_name, sizeof(b->pty_name) - 1);
        strncpy(b->link_name, link, sizeof(b->link_name) - 1);
        strncpy(b->func_name, func, sizeof(b->func_name) - 1);
        b->iface = iface;
        b->pipe_in = pipe_in;
        b->pipe_out = pipe_out;
        atomic_store(&b->state, BRIDGE_RUNNING);
        atomic_store(&b->usb_to_pty_alive, 0);
        atomic_store(&b->pty_to_usb_alive, 0);

        logprintf("Interface %d (%s): %s -> %s\n", iface_num, func, slave_name, link);
        logprintf("  Bulk IN pipe %d, Bulk OUT pipe %d, %d endpoints\n",
                  pipe_in, pipe_out, num_endpoints);

        /* Create threads as detached */
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&b->usb_to_pty_thread, &attr, usb_to_pty, b);
        pthread_create(&b->pty_to_usb_thread, &attr, pty_to_usb, b);
        pthread_attr_destroy(&attr);

        g_bridge_count++;
    }

    IOObjectRelease(child_iter);
    g_expected_bridges = iface_count;

    /* If we got exclusive access errors, don't attempt USB re-enumeration —
     * it creates broken pipe handles (0xe00002c0) that never recover.
     * Instead, let the rescan loop retry every 5s. The kernel will
     * eventually clean up stale locks from the previous daemon session.
     * After many failed attempts, try re-enumeration as a last resort. */
    static int exclusive_retries;
    if (g_bridge_count == 0 && exclusive_access_hit) {
        exclusive_retries++;
        if (exclusive_retries <= 6) {
            /* First 30 seconds: just wait for kernel cleanup */
            logprintf("Exclusive access on all interfaces (attempt %d/6, "
                      "waiting for kernel cleanup)...\n", exclusive_retries);
        } else if (exclusive_retries == 7) {
            /* Last resort: try re-enumeration once */
            logprintf("Exclusive access persists — trying USB re-enumeration...\n");
            if (attempt_usb_recovery(device) == 0) {
                IOObjectRelease(device);
                return setup_bridges();
            }
            logprintf("Recovery failed — modem unplug/replug may be required\n");
        } else {
            logprintf("Exclusive access persists (attempt %d) — "
                      "physical replug may be required\n", exclusive_retries);
        }
    } else if (g_bridge_count > 0) {
        exclusive_retries = 0;  /* reset on success */
    }

    IOObjectRelease(device);

    if (g_bridge_count == 0) {
        if (matched_vendor)
            logprintf("Device found but no interfaces opened\n");
        return -1;
    }

    return 0;
}

/* Forward declaration */
static void write_status_file(void);

/* ── Port rename helper ── */

static void rename_bridge(bridge_t *b, const char *new_name) {
    char new_link[256];
    make_symlink_path(new_link, sizeof(new_link), new_name);

    if (strcmp(b->link_name, new_link) == 0)
        return;  /* already named correctly */

    unlink(b->link_name);
    unlink(new_link);
    if (symlink(b->pty_name, new_link) < 0) {
        logprintf("Warning: symlink %s -> %s failed: %s\n",
                  new_link, b->pty_name, strerror(errno));
        return;
    }

    logprintf("  Identified: %s -> %s/" SYMLINK_PREFIX "%s\n", b->func_name, g_symlink_dir, new_name);
    strncpy(b->link_name, new_link, sizeof(b->link_name) - 1);
    strncpy(b->func_name, new_name, sizeof(b->func_name) - 1);
}

/* ── Port auto-detection via URC/AT probing ──
 *
 * After bridges are up, probe unknown ports to identify AT vs NMEA:
 * 1. Listen on all unknown ports for the "RDY" URC (modem ready signal)
 * 2. If RDY heard, that port is AT — shorten timeout for remaining ports
 * 3. After timeout (30s) with no RDY on any port, send AT\r as fallback
 * 4. Ports emitting "$G" NMEA sentences are named "nmea"
 * 5. Ports responding to AT/emitting RDY are named "at0", "at1", ...
 * 6. Unidentified ports keep generic "portN" name
 */

enum port_type { PORT_UNKNOWN = 0, PORT_AT, PORT_NMEA };

static void probe_ports(void) {
    /* Collect unknown (non-diag) bridges */
    int idx[MAX_INTERFACES];       /* index into g_bridges[] */
    int fds[MAX_INTERFACES];       /* slave fds */
    enum port_type types[MAX_INTERFACES];
    int count = 0;

    for (int i = 0; i < g_bridge_count && count < MAX_INTERFACES; i++) {
        if (strstr(g_bridges[i].func_name, "-loading") == NULL)
            continue;  /* already identified (diag, etc.) */

        int fd = open(g_bridges[i].link_name, O_RDWR | O_NONBLOCK | O_NOCTTY);
        if (fd < 0) {
            logprintf("Probe: failed to open %s: %s\n",
                      g_bridges[i].link_name, strerror(errno));
            continue;
        }

        /* Set raw mode */
        struct termios tio;
        tcgetattr(fd, &tio);
        cfmakeraw(&tio);
        tcsetattr(fd, TCSANOW, &tio);

        idx[count] = i;
        fds[count] = fd;
        types[count] = PORT_UNKNOWN;
        count++;
    }

    if (count == 0)
        return;

    /* Phase 1: Try AT immediately on all ports.
     * If the modem is already running, AT ports respond instantly with OK.
     * Also check for buffered RDY URC and NMEA data that arrived before open.
     *
     * Strategy: send AT\r on all ports simultaneously, then poll for responses.
     * If ANY port responds, the modem is ready — keep probing the rest.
     * If NO port responds, the modem isn't ready yet — move to Phase 2 (RDY wait). */
    logprintf("Probing %d unknown port(s)...\n", count);

    /* Drain any data that arrived before we opened the slave.
     * This catches RDY URC if the modem was already ready when we
     * opened the interfaces — the usb_to_pty thread wrote it to the
     * PTY master and it's sitting in the PTY buffer. */
    char accum[MAX_INTERFACES][512];
    int accum_len[MAX_INTERFACES];
    memset(accum_len, 0, sizeof(accum_len));
    int any_responded = 0;

    for (int i = 0; i < count; i++) {
        ssize_t n = read(fds[i], accum[i], sizeof(accum[i]) - 1);
        if (n > 0) {
            accum_len[i] = (int)n;
            accum[i][n] = '\0';
            if (strstr(accum[i], "RDY") || strstr(accum[i], "OK") ||
                strstr(accum[i], "ERROR")) {
                types[i] = PORT_AT;
                any_responded = 1;
                logprintf("  [%s] Buffered RDY/AT data found — AT port\n",
                          g_bridges[idx[i]].func_name);
            } else if (strstr(accum[i], "$G")) {
                types[i] = PORT_NMEA;
                any_responded = 1;
                logprintf("  [%s] Buffered NMEA data — GPS port\n",
                          g_bridges[idx[i]].func_name);
            }
        }
    }

    /* Send AT on all still-unknown ports simultaneously.
     * Only flush output (TCOFLUSH) — preserve any pending input data. */
    int unknown_for_at = 0;
    for (int i = 0; i < count; i++) {
        if (types[i] != PORT_UNKNOWN) continue;
        tcflush(fds[i], TCOFLUSH);
        write(fds[i], "AT\r", 3);
        unknown_for_at++;
    }
    if (unknown_for_at > 0)
        logprintf("Sent AT on %d port(s), waiting for response...\n", unknown_for_at);

    time_t at_start = time(NULL);
    while (time(NULL) - at_start < PROBE_AT_TIMEOUT && atomic_load(&g_running)) {
        struct pollfd pfds[MAX_INTERFACES];
        int poll_count = 0;
        int poll_map[MAX_INTERFACES];

        for (int i = 0; i < count; i++) {
            if (types[i] != PORT_UNKNOWN) continue;
            pfds[poll_count].fd = fds[i];
            pfds[poll_count].events = POLLIN;
            poll_map[poll_count] = i;
            poll_count++;
        }

        if (poll_count == 0) break;

        int ret = poll(pfds, poll_count, 500);
        if (ret <= 0) continue;

        for (int p = 0; p < poll_count; p++) {
            if (!(pfds[p].revents & POLLIN)) continue;

            int i = poll_map[p];
            int space = (int)sizeof(accum[i]) - accum_len[i] - 1;
            if (space <= 0) continue;

            ssize_t n = read(fds[i], accum[i] + accum_len[i], space);
            if (n <= 0) continue;
            accum_len[i] += n;
            accum[i][accum_len[i]] = '\0';

            /* Check for AT response or buffered RDY */
            if (strstr(accum[i], "OK") || strstr(accum[i], "ERROR") ||
                strstr(accum[i], "RDY")) {
                types[i] = PORT_AT;
                any_responded = 1;
                logprintf("  [%s] AT port detected\n", g_bridges[idx[i]].func_name);
            }
            /* Check for NMEA data */
            else if (strstr(accum[i], "$G")) {
                types[i] = PORT_NMEA;
                any_responded = 1;
                logprintf("  [%s] NMEA data detected — GPS port\n",
                          g_bridges[idx[i]].func_name);
            }
        }
    }

    /* If any port responded, try AT again on remaining unknowns (modem is ready) */
    if (any_responded) {
        int unknown_remain = 0;
        for (int i = 0; i < count; i++) {
            if (types[i] == PORT_UNKNOWN) unknown_remain++;
        }
        if (unknown_remain > 0 && atomic_load(&g_running)) {
            logprintf("Retrying AT on %d remaining port(s)...\n", unknown_remain);
            for (int i = 0; i < count; i++) {
                if (types[i] != PORT_UNKNOWN) continue;
                if (!atomic_load(&g_running)) break;

                tcflush(fds[i], TCOFLUSH);
                write(fds[i], "AT\r", 3);

                char resp[256] = {0};
                int resp_len = 0;
                time_t retry_start = time(NULL);
                while (time(NULL) - retry_start < PROBE_AT_TIMEOUT) {
                    struct pollfd pfd = { .fd = fds[i], .events = POLLIN };
                    int ret = poll(&pfd, 1, 500);
                    if (ret <= 0) continue;
                    ssize_t n = read(fds[i], resp + resp_len,
                                    sizeof(resp) - resp_len - 1);
                    if (n > 0) {
                        resp_len += n;
                        resp[resp_len] = '\0';
                        if (strstr(resp, "OK") || strstr(resp, "ERROR") ||
                            strstr(resp, "RDY"))
                            break;
                    }
                }
                if (strstr(resp, "OK") || strstr(resp, "ERROR") ||
                    strstr(resp, "RDY")) {
                    types[i] = PORT_AT;
                    logprintf("  [%s] AT port detected\n", g_bridges[idx[i]].func_name);
                }
            }
        }
        goto done;
    }

    /* Phase 2: No port responded to AT — modem not ready yet.
     * Wait for RDY URC (up to PROBE_RDY_TIMEOUT seconds), then retry AT.
     * RDY on ANY port means modem is ready, so immediately AT-probe the rest. */
    logprintf("No AT response — modem not ready, waiting for RDY URC (up to %ds)...\n",
              PROBE_RDY_TIMEOUT);

    time_t rdy_start = time(NULL);
    int modem_ready = 0;

    while (time(NULL) - rdy_start < PROBE_RDY_TIMEOUT &&
           atomic_load(&g_running) && !modem_ready) {
        struct pollfd pfds[MAX_INTERFACES];
        int poll_count = 0;
        int poll_map[MAX_INTERFACES];

        for (int i = 0; i < count; i++) {
            if (types[i] != PORT_UNKNOWN) continue;
            pfds[poll_count].fd = fds[i];
            pfds[poll_count].events = POLLIN;
            poll_map[poll_count] = i;
            poll_count++;
        }
        if (poll_count == 0) break;

        int ret = poll(pfds, poll_count, 1000);
        if (ret <= 0) continue;

        for (int p = 0; p < poll_count; p++) {
            if (!(pfds[p].revents & POLLIN)) continue;

            int i = poll_map[p];
            int space = (int)sizeof(accum[i]) - accum_len[i] - 1;
            if (space <= 0) {
                int keep = (int)sizeof(accum[i]) / 2;
                memmove(accum[i], accum[i] + accum_len[i] - keep, keep);
                accum_len[i] = keep;
                space = (int)sizeof(accum[i]) - accum_len[i] - 1;
            }

            ssize_t n = read(fds[i], accum[i] + accum_len[i], space);
            if (n <= 0) continue;
            accum_len[i] += n;
            accum[i][accum_len[i]] = '\0';

            if (strstr(accum[i], "RDY")) {
                types[i] = PORT_AT;
                modem_ready = 1;
                logprintf("  [%s] RDY URC — AT port (modem ready)\n",
                          g_bridges[idx[i]].func_name);
            } else if (strstr(accum[i], "$G")) {
                types[i] = PORT_NMEA;
                logprintf("  [%s] NMEA data — GPS port\n",
                          g_bridges[idx[i]].func_name);
            }
        }
    }

    /* AT-probe any remaining unknown ports */
    {
        int unknown_remain = 0;
        for (int i = 0; i < count; i++) {
            if (types[i] == PORT_UNKNOWN) unknown_remain++;
        }
        if (unknown_remain > 0 && atomic_load(&g_running)) {
            logprintf("AT-probing %d remaining port(s)...\n", unknown_remain);
            for (int i = 0; i < count; i++) {
                if (types[i] != PORT_UNKNOWN) continue;
                if (!atomic_load(&g_running)) break;

                tcflush(fds[i], TCOFLUSH);
                write(fds[i], "AT\r", 3);

                char resp[256] = {0};
                int resp_len = 0;
                time_t retry_start = time(NULL);
                while (time(NULL) - retry_start < PROBE_AT_TIMEOUT) {
                    struct pollfd pfd = { .fd = fds[i], .events = POLLIN };
                    int ret = poll(&pfd, 1, 500);
                    if (ret <= 0) continue;
                    ssize_t n = read(fds[i], resp + resp_len,
                                    sizeof(resp) - resp_len - 1);
                    if (n > 0) {
                        resp_len += n;
                        resp[resp_len] = '\0';
                        if (strstr(resp, "OK") || strstr(resp, "ERROR") ||
                            strstr(resp, "RDY"))
                            break;
                    }
                }
                if (strstr(resp, "OK") || strstr(resp, "ERROR") ||
                    strstr(resp, "RDY")) {
                    types[i] = PORT_AT;
                    logprintf("  [%s] AT port detected\n", g_bridges[idx[i]].func_name);
                } else {
                    logprintf("  [%s] No response\n", g_bridges[idx[i]].func_name);
                }
            }
        }
    }

done:
    /* Close all slave fds */
    for (int i = 0; i < count; i++)
        close(fds[i]);

    /* If AT ports were found and exactly one port remains unknown,
     * it's almost certainly the NMEA/GPS port — label it as such. */
    int at_found = 0, unknown_count = 0, nmea_found = 0;
    for (int i = 0; i < count; i++) {
        if (types[i] == PORT_AT) at_found++;
        else if (types[i] == PORT_NMEA) nmea_found++;
        else unknown_count++;
    }
    if (at_found > 0 && unknown_count == 1 && nmea_found == 0) {
        for (int i = 0; i < count; i++) {
            if (types[i] == PORT_UNKNOWN) {
                types[i] = PORT_NMEA;
                logprintf("  [%s] Remaining port assumed NMEA/GPS\n",
                          g_bridges[idx[i]].func_name);
                break;
            }
        }
    }

    /* Rename ports based on identification results */
    int at_index = 0;
    int nmea_done = 0;

    for (int i = 0; i < count; i++) {
        bridge_t *b = &g_bridges[idx[i]];
        char name_buf[32];

        switch (types[i]) {
        case PORT_AT:
            snprintf(name_buf, sizeof(name_buf), "at%d", at_index++);
            rename_bridge(b, name_buf);
            break;
        case PORT_NMEA:
            if (!nmea_done) {
                rename_bridge(b, "nmea");
                nmea_done = 1;
            } else {
                snprintf(name_buf, sizeof(name_buf), "nmea%d", nmea_done++);
                rename_bridge(b, name_buf);
            }
            break;
        default:
            snprintf(name_buf, sizeof(name_buf), "port%d", b->iface_num);
            rename_bridge(b, name_buf);
            break;
        }
    }

    write_status_file();
}

/* ── Robust shutdown ── */

static void shutdown_bridges(void) {
    if (g_bridge_count == 0)
        return;

    logprintf("Shutting down %d bridge(s)...\n", g_bridge_count);

    /* 1. Set all bridges to STOPPING */
    for (int i = 0; i < g_bridge_count; i++) {
        atomic_store(&g_bridges[i].state, BRIDGE_STOPPING);
    }

    /* 2. Close PTY masters FIRST to unblock read() in pty_to_usb threads.
     *    Must happen before AbortPipe — if the USB interface is dead (modem
     *    disconnected), AbortPipe may not work, but closing the master fd
     *    will make read() return EBADF and break the pty_to_usb thread out. */
    for (int i = 0; i < g_bridge_count; i++) {
        if (g_bridges[i].pty_slave >= 0) {
            close(g_bridges[i].pty_slave);
            g_bridges[i].pty_slave = -1;
        }
        if (g_bridges[i].pty_master >= 0) {
            close(g_bridges[i].pty_master);
            g_bridges[i].pty_master = -1;
        }
    }

    /* 3. Abort BOTH pipe_in AND pipe_out to unblock ReadPipe/WritePipe.
     *    Pipe indices are 1-based, so 0 means "this bridge has no such pipe" —
     *    a QMI bridge on a cdc-wdm function with no bulk pair has both at 0, and
     *    aborting pipe 0 would abort the default *control* pipe, which is the
     *    one its encapsulated QMI transfers ride on. */
    for (int i = 0; i < g_bridge_count; i++) {
        bridge_t *b = &g_bridges[i];
        if (b->iface) {
            if (b->pipe_in)
                (*b->iface)->AbortPipe(b->iface, b->pipe_in);
            if (b->pipe_out)
                (*b->iface)->AbortPipe(b->iface, b->pipe_out);
        }
    }

    /* 3b. QMI bridges: abort the interrupt pipe so the modem->sock thread's
     *     read returns at once, close socket fds so the accept loop wakes, and
     *     remove the on-disk socket. The client slot is claimed with an atomic
     *     exchange so only one thread can ever close that fd. */
    for (int i = 0; i < g_bridge_count; i++) {
        bridge_t *b = &g_bridges[i];
        if (!b->is_qmi)
            continue;
        if (b->iface && b->pipe_intr)
            (*b->iface)->AbortPipe(b->iface, b->pipe_intr);
        int client = atomic_exchange(&b->qmi_client_fd, -1);
        if (client >= 0)
            close(client);
        if (b->qmi_listen_fd >= 0) {
            close(b->qmi_listen_fd);
            b->qmi_listen_fd = -1;
        }
        if (b->sock_path[0])
            unlink(b->sock_path);
    }

    /* 4. Wait for threads with timeout using condition variable */
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += SHUTDOWN_TIMEOUT;

    pthread_mutex_lock(&g_exit_mutex);
    for (;;) {
        int all_done = 1;
        for (int i = 0; i < g_bridge_count; i++) {
            if (atomic_load(&g_bridges[i].usb_to_pty_alive) ||
                atomic_load(&g_bridges[i].pty_to_usb_alive)) {
                all_done = 0;
                break;
            }
        }
        if (all_done) break;

        int rc = pthread_cond_timedwait(&g_exit_cond, &g_exit_mutex, &deadline);
        if (rc == ETIMEDOUT) {
            logprintf("Shutdown timeout — stuck threads:\n");
            for (int i = 0; i < g_bridge_count; i++) {
                bridge_t *b = &g_bridges[i];
                int u2p = atomic_load(&b->usb_to_pty_alive);
                int p2u = atomic_load(&b->pty_to_usb_alive);
                if (u2p || p2u)
                    logprintf("  [%s] usb_to_pty=%d pty_to_usb=%d\n",
                              b->func_name, u2p, p2u);
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_exit_mutex);

    /* 5. Close USB interfaces and remove symlinks */
    for (int i = 0; i < g_bridge_count; i++) {
        bridge_t *b = &g_bridges[i];
        atomic_store(&b->state, BRIDGE_STOPPED);

        if (b->iface) {
            (*b->iface)->USBInterfaceClose(b->iface);
            (*b->iface)->Release(b->iface);
            b->iface = NULL;
        }

        if (b->link_name[0] && strcmp(b->link_name, b->pty_name) != 0)
            unlink(b->link_name);
    }

    g_bridge_count = 0;
    logprintf("All bridges shut down\n");
}

/* ── Status file ── */

static void write_status_file(void) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", STATUS_FILE);
    FILE *f = fopen(tmp, "w");
    if (!f) return;

    fprintf(f, "pid=%d\n", getpid());
    fprintf(f, "state=%s\n", g_daemon_state);
    if (g_edl_detected)
        fprintf(f, "edl=%s\n", g_edl_product);
    fprintf(f, "bridges=%d\n", g_bridge_count);
    for (int i = 0; i < g_bridge_count; i++) {
        bridge_t *b = &g_bridges[i];
        int u2p = atomic_load(&b->usb_to_pty_alive);
        int p2u = atomic_load(&b->pty_to_usb_alive);
        const char *health = (u2p && p2u) ? "healthy" : "dead";
        if (b->is_qmi && u2p && p2u) {
            /* Round-trip-aware health: both threads alive but a SEND has gone
             * unanswered past QMI_DEGRADED_MS — and the poll fallback also came
             * up empty — means the control channel accepts commands but never
             * responds. Report that instead of a lying `healthy`. The poll
             * rescues the merely-interrupt-silent parts, so this flags only
             * genuinely stuck channels. */
            uint64_t sent = atomic_load(&b->qmi_sends);
            uint64_t got  = atomic_load(&b->qmi_responses);
            if (sent > got &&
                qmi_now_ms() - atomic_load(&b->qmi_last_send_ms) > QMI_DEGRADED_MS)
                health = "degraded";
        }
        if (b->is_qmi) {
            fprintf(f, "port.%s=%s usb2pty=%d pty2usb=%d qmi_sends=%llu "
                    "qmi_responses=%llu qmi_polls=%llu link=%s\n",
                    b->func_name, health, u2p, p2u,
                    (unsigned long long)atomic_load(&b->qmi_sends),
                    (unsigned long long)atomic_load(&b->qmi_responses),
                    (unsigned long long)atomic_load(&b->qmi_polls), b->link_name);
        } else {
            fprintf(f, "port.%s=%s usb2pty=%d pty2usb=%d link=%s\n",
                    b->func_name, health, u2p, p2u, b->link_name);
        }
    }
    fclose(f);
    rename(tmp, STATUS_FILE);
}

/* ── Health monitor + auto-restart loop ── */

static void run_monitor_loop(void) {
    int prev_bridge_count = 0;  /* remember how many bridges we had before disconnect */

    while (atomic_load(&g_running)) {
        /* Health check — two methods:
         * 1. Thread death (any thread, not just all)
         * 2. IOKit sessionID — detects modem reboot / USB
         *    re-enumeration even when threads are idle.
         *    Pure IOKit registry query, zero USB traffic. */
        int alive_count = 0;
        int active_count = 0;
        for (int i = 0; i < g_bridge_count; i++) {
            /* Only bridges still meant to be running are evidence about the
             * modem. A bridge that failed to start and marked itself STOPPED
             * (see qmi_usb_to_sock) would otherwise read as a dead bridge every
             * interval and trigger an endless teardown/rebuild of the healthy
             * ones, since the failure recurs on every rebuild. */
            if (atomic_load(&g_bridges[i].state) != BRIDGE_RUNNING)
                continue;
            active_count++;
            if (atomic_load(&g_bridges[i].usb_to_pty_alive))
                alive_count++;
        }

        int device_ok = 1;
        if (g_bridge_count > 0 && g_matched_vid) {
            device_ok = 0;
            io_iterator_t iter;
            kern_return_t kr = IOServiceGetMatchingServices(
                kIOMainPortDefault,
                IOServiceMatching("IOUSBHostDevice"), &iter);
            if (kr == KERN_SUCCESS) {
                io_service_t dev;
                while ((dev = IOIteratorNext(iter))) {
                    CFNumberRef vidRef = IORegistryEntryCreateCFProperty(
                        dev, CFSTR("idVendor"),
                        kCFAllocatorDefault, 0);
                    if (vidRef) {
                        int vid = 0;
                        CFNumberGetValue(vidRef, kCFNumberIntType, &vid);
                        CFRelease(vidRef);
                        if (vid == g_matched_vid) {
                            CFNumberRef sidRef = IORegistryEntryCreateCFProperty(
                                dev, CFSTR("sessionID"),
                                kCFAllocatorDefault, 0);
                            if (sidRef) {
                                long long sid = 0;
                                CFNumberGetValue(sidRef,
                                    kCFNumberLongLongType, &sid);
                                CFRelease(sidRef);
                                if ((uint64_t)sid == g_session_id)
                                    device_ok = 1;
                            }
                        }
                    }
                    IOObjectRelease(dev);
                    if (device_ok) break;
                }
                IOObjectRelease(iter);
            }
        }

        write_status_file();

        /* Three distinct conditions used to share one predicate and one message
         * ("All bridges dead — modem likely disconnected"), which fired with 4
         * of 5 bridges healthy and a modem that had not moved. They need
         * different responses:
         *
         *   !device_ok             the device really went away or re-enumerated
         *                          (authoritative: IOKit sessionID). Tear
         *                          everything down; the rescan path rebuilds.
         *   alive_count == 0       every bridge died with the device still
         *                          present. Tear down and rebuild — this is the
         *                          only case the old message described.
         *   0 < alive < active     ONE bridge died while the others are fine.
         *                          Rebuilding the whole set destroys healthy
         *                          PTYs, and against a persistent fault (an
         *                          interrupt EP that will not arm) it never
         *                          terminates. Bounded rebuilds, then run
         *                          degraded.
         */
        if (g_bridge_count > 0 && !device_ok) {
            logprintf(C_YELLOW "Modem disconnected or re-enumerated (IOKit "
                      "sessionID changed) — shutting down %d bridge(s)\n" C_RESET,
                      g_bridge_count);
            if (g_bridge_count > prev_bridge_count)
                prev_bridge_count = g_bridge_count;
            g_bridge_rebuilds = 0;   /* different device instance — fresh budget */
            shutdown_bridges();
            g_daemon_state = "waiting";
            write_status_file();
            /* Fall through to rescan path below */
        } else if (g_bridge_count > 0 && active_count > 0 && alive_count == 0) {
            logprintf(C_YELLOW "All %d bridge(s) dead while the modem is still "
                      "present — rebuilding\n" C_RESET, active_count);
            if (g_bridge_count > prev_bridge_count)
                prev_bridge_count = g_bridge_count;
            g_bridge_rebuilds = 0;
            shutdown_bridges();
            g_daemon_state = "waiting";
            write_status_file();
            /* Fall through to rescan path below */
        } else if (g_bridge_count > 0 && alive_count < active_count) {
            /* Name the bridges that actually died. The old wording is what made
             * this class of fault invisible in a log. */
            for (int i = 0; i < g_bridge_count; i++) {
                bridge_t *b = &g_bridges[i];
                if (atomic_load(&b->state) == BRIDGE_STOPPED)
                    continue;
                if (!atomic_load(&b->usb_to_pty_alive))
                    logprintf(C_YELLOW "Bridge [%s] (interface %d) died; %d of %d "
                              "bridge(s) still alive\n" C_RESET,
                              b->func_name, b->iface_num, alive_count, active_count);
            }
            if (g_bridge_rebuilds < BRIDGE_REBUILD_MAX_ATTEMPTS) {
                g_bridge_rebuilds++;
                logprintf(C_YELLOW "Rebuilding all bridges (attempt %d of %d)\n"
                          C_RESET, g_bridge_rebuilds, BRIDGE_REBUILD_MAX_ATTEMPTS);
                if (g_bridge_count > prev_bridge_count)
                    prev_bridge_count = g_bridge_count;
                shutdown_bridges();
                g_daemon_state = "waiting";
                write_status_file();
                /* Fall through to rescan path below */
            } else {
                /* Give up rebuilding and keep what works. Demoting a dead bridge
                 * to BRIDGE_STOPPED drops it out of the counts above AND stops
                 * its surviving sibling thread, which loops on
                 * state == BRIDGE_RUNNING — so no per-bridge teardown path is
                 * needed. At least one bridge is alive here (alive_count > 0),
                 * so the daemon can never demote its way down to an empty set. */
                int demoted = 0;
                for (int i = 0; i < g_bridge_count; i++) {
                    bridge_t *b = &g_bridges[i];
                    if (atomic_load(&b->state) == BRIDGE_STOPPED)
                        continue;
                    if (!atomic_load(&b->usb_to_pty_alive)) {
                        atomic_store(&b->state, BRIDGE_STOPPED);
                        demoted++;
                    }
                }
                logprintf(C_RED "Gave up rebuilding after %d attempt(s): %d "
                          "bridge(s) stay dead, %d healthy bridge(s) keep running. "
                          "A bridge that dies again on every rebuild has a fault "
                          "local to its interface, and tearing the healthy ports "
                          "down cannot fix it. Restart the daemon or replug the "
                          "modem to retry.\n" C_RESET,
                          BRIDGE_REBUILD_MAX_ATTEMPTS, demoted, alive_count);
                g_bridge_rebuilds = 0;   /* a LATER death deserves its own budget */
                g_daemon_state = "degraded";
                write_status_file();
            }
        } else if (g_bridge_count > 0 && g_bridge_rebuilds > 0) {
            logprintf(C_GREEN "All %d bridge(s) alive again after %d rebuild "
                      "attempt(s) — clearing the counter\n" C_RESET,
                      active_count, g_bridge_rebuilds);
            g_bridge_rebuilds = 0;
        }

        if (g_bridge_count == 0) {
            /* No bridges — either daemon started before modem was plugged in,
             * or modem disconnected and bridges were torn down above.
             * Periodically try to discover the modem. */
            logprintf(C_YELLOW "Waiting for modem...\n" C_RESET);
            int retries_with_partial = 0;
            prev_bridge_count = 0;  /* next modem may have different interface count */
            while (atomic_load(&g_running)) {
                for (int s = 0; s < RESCAN_INTERVAL && atomic_load(&g_running); s++)
                    sleep(1);

                if (!atomic_load(&g_running)) break;

                if (setup_bridges() != 0) {
                    /* No modem — update status (shows EDL if detected) */
                    write_status_file();
                    continue;
                }
                /* Compare against expected count (from interface scan) or
                 * previous bridge count to detect partial reconnection.
                 * Tear down and retry — stale locks may still be clearing. */
                int expected = prev_bridge_count > 0 ? prev_bridge_count : g_expected_bridges;
                if (g_bridge_count < expected && retries_with_partial < 5) {
                    logprintf(C_YELLOW "Partial setup (%d/%d interfaces) — retrying in %ds...\n" C_RESET,
                              g_bridge_count, expected, RESCAN_INTERVAL);
                    shutdown_bridges();
                    retries_with_partial++;
                    continue;
                }
                probe_ports();
                g_daemon_state = "running";
                logprintf(C_GREEN "Modem found — %d bridge(s) active\n" C_RESET, g_bridge_count);
                prev_bridge_count = g_bridge_count;
                logprintf("\n" C_BOLD "Active ports:" C_RESET "\n");
                for (int i = 0; i < g_bridge_count; i++)
                    logprintf("  " C_GREEN "%s" C_RESET "\n", g_bridges[i].link_name);
                break;
            }
            continue;  /* restart monitor loop */
        }

        /* Sleep interruptibly */
        for (int s = 0; s < MONITOR_INTERVAL && atomic_load(&g_running); s++)
            sleep(1);
    }
}

/* ── ADB_LIBUSB=0 environment setup ── */

static int check_launchctl_env(void)
{
	FILE *fp = popen("launchctl getenv ADB_LIBUSB 2>/dev/null", "r");
	if (!fp)
		return 0;
	char buf[32] = {0};
	if (fgets(buf, sizeof(buf), fp))
		buf[strcspn(buf, "\n")] = '\0';
	pclose(fp);
	return (strcmp(buf, "0") == 0);
}

static void set_adb_libusb_env(void)
{
	/* Set ADB_LIBUSB=0 so adb uses the native macOS backend.
	 * ADB 34+ defaults to libusb which has a bug with non-contiguous USB
	 * interface numbers (e.g. 0,1,2,3,5 — no 4) causing LIBUSB_ERROR_NOT_FOUND.
	 *
	 * On macOS 14+ with SIP enabled, system-wide launchctl setenv may be
	 * restricted. Fall back to user-domain launchctl, then warn. */

	/* Try system-wide (works when SIP allows it) */
	system("launchctl setenv ADB_LIBUSB 0 2>/dev/null");
	if (check_launchctl_env()) {
		printf("ADB_LIBUSB=0 set (system-wide via launchctl)\n");
		return;
	}

	/* System-wide failed — try user domain via real user's UID */
	uid_t target_uid = getuid();
	const char *sudo_user = getenv("SUDO_USER");
	if (sudo_user) {
		struct passwd *pw = getpwnam(sudo_user);
		if (pw)
			target_uid = pw->pw_uid;
	}

	char cmd[256];
	snprintf(cmd, sizeof(cmd),
		 "launchctl asuser %u launchctl setenv ADB_LIBUSB 0 2>/dev/null",
		 target_uid);
	system(cmd);

	if (check_launchctl_env()) {
		printf("ADB_LIBUSB=0 set (user domain via launchctl)\n");
		return;
	}

	/* Both failed — set in our own process env and warn */
	setenv("ADB_LIBUSB", "0", 1);
	fprintf(stderr, C_YELLOW "Warning: could not set ADB_LIBUSB=0 via launchctl (SIP restriction)\n" C_RESET);
	fprintf(stderr, C_YELLOW "ADB may have issues with this modem. To fix permanently, add to ~/.zshrc:\n" C_RESET);
	fprintf(stderr, C_YELLOW "  export ADB_LIBUSB=0\n" C_RESET);
}

/* ── Kill all stale qcseriald instances ──
 *
 * PID file checks are insufficient because instances can be started from
 * different paths (standalone binary, qfenix subcommand, /usr/local/bin)
 * each writing to different PID file locations.  This function scans the
 * process table by name and kills everything that isn't us.
 */

static void kill_stale_instances(void) {
    pid_t self = getpid();
    FILE *fp = popen("pgrep -f 'qcseriald (start|start --foreground)'", "r");
    if (!fp)
        return;

    char line[32];
    int killed = 0;
    while (fgets(line, sizeof(line), fp)) {
        pid_t pid = (pid_t)atoi(line);
        if (pid <= 0 || pid == self)
            continue;

        if (kill(pid, SIGTERM) == 0) {
            printf("Killed stale qcseriald instance (PID %d)\n", pid);
            killed++;
        }
    }
    pclose(fp);

    if (killed > 0) {
        /* Give them a moment to exit gracefully */
        usleep(500000);  /* 500ms */
        /* Force-kill any survivors */
        fp = popen("pgrep -f 'qcseriald (start|start --foreground)'", "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                pid_t pid = (pid_t)atoi(line);
                if (pid > 0 && pid != self)
                    kill(pid, SIGKILL);
            }
            pclose(fp);
        }
    }

    /* Clean up PID files from all known locations */
    unlink("/var/run/qcseriald.pid");
    unlink("/tmp/qcseriald.pid");
}

/* ── Root privilege check ── */

static int require_root(const char *command) {
    if (getuid() == 0)
        return 0;
    fprintf(stderr, C_RED "Error: " C_RESET "'qcseriald %s' requires root privileges.\n", command);
    fprintf(stderr, "Run with: " C_GREEN "sudo qcseriald %s" C_RESET "\n", command);
    return 1;
}

/* ── cmd_start ── */

static int cmd_start(int foreground) {
    if (require_root("start"))
        return 1;

    /* QMI passthrough opt-in: off unless QCSERIALD_QMI_SOCKET is a truthy
     * value ("1"/"yes"/"true"). Default keeps the skip behavior. */
    const char *qmi_env = getenv("QCSERIALD_QMI_SOCKET");
    g_qmi_socket_enabled = (qmi_env && (qmi_env[0] == '1' ||
                            strcasecmp(qmi_env, "yes") == 0 ||
                            strcasecmp(qmi_env, "true") == 0));

    /* Kill ALL existing qcseriald instances (from any path/PID file) */
    kill_stale_instances();
    resolve_symlink_dir();
    cleanup_stale_symlinks();

    /* Printed before the scan, so it states intent rather than fact — whether a
     * QMI interface is actually found (and the socket actually binds) is
     * reported by setup_bridges(). */
    if (g_qmi_socket_enabled)
        printf(C_YELLOW "QMI passthrough ENABLED: if a QMI interface is found it "
               "will be exposed as a unix stream socket at %s/%s\n" C_RESET,
               g_symlink_dir, QMI_SOCK_NAME);

    set_adb_libusb_env();

    if (foreground) {
        /* Run in foreground (for launchd or manual debugging) */
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        /* A write to a socket or pipe whose peer has gone raises SIGPIPE, whose
         * DEFAULT action kills the process. A QMI client disconnecting mid-write
         * would otherwise take the whole daemon down — every bridge, not just the
         * QMI one (observed as exit 141 = 128+13). Belt and braces with the
         * per-socket SO_NOSIGPIPE, which does not cover PTY or pipe writes. */
        signal(SIGPIPE, SIG_IGN);

        printf(C_BOLD C_GREEN "qcseriald" C_RESET " v%s — User-space USB serial bridge (foreground)\n", QCSERIALD_VERSION);
        printf("Looking for supported modem (%zu vendors)...\n", NUM_VENDORS);

        pid_file_write(getpid());

        if (setup_bridges() < 0) {
            fprintf(stderr, C_YELLOW "No modem found — entering rescan mode\n" C_RESET);
            g_daemon_state = "waiting";
        } else {
            probe_ports();
            g_daemon_state = "running";
            printf("\n%d serial port(s) created:\n", g_bridge_count);
            for (int i = 0; i < g_bridge_count; i++)
                printf("  %s\n", g_bridges[i].link_name);
            printf("\n");
        }

        run_monitor_loop();

        printf("Shutting down...\n");
        shutdown_bridges();
        pid_file_remove();
        unlink(STATUS_FILE);
        printf("Done\n");
        return 0;
    }

    /* Daemonize: fork, report back to parent via pipe */
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("pipe");
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child > 0) {
        /* Parent: wait for child to report status */
        close(pipefd[1]);

        char report[1024];
        ssize_t n = 0;
        ssize_t total = 0;
        while ((n = read(pipefd[0], report + total, sizeof(report) - 1 - total)) > 0)
            total += n;
        close(pipefd[0]);
        report[total] = '\0';

        if (total > 0 && report[0] == '+') {
            /* Success: print port list */
            printf("%s", report + 1);
            return 0;
        } else if (total > 0) {
            /* Failure */
            fprintf(stderr, "%s", report + 1);
            return 1;
        } else {
            fprintf(stderr, "Child process died unexpectedly\n");
            return 1;
        }
    }

    /* Child: become daemon */
    close(pipefd[0]);

    if (setsid() < 0) {
        dprintf(pipefd[1], "-setsid failed: %s\n", strerror(errno));
        close(pipefd[1]);
        _exit(1);
    }

    /* Redirect stdout/stderr to log file (truncate — old logs are stale) */
    int logfd = open(LOG_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (logfd >= 0) {
        dup2(logfd, STDOUT_FILENO);
        dup2(logfd, STDERR_FILENO);
        close(logfd);
    }
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    g_log_timestamps = 1;

    /* Close stdin */
    int devnull = open("/dev/null", O_RDONLY);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        close(devnull);
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);   /* see the foreground path above */

    logprintf(C_BOLD C_GREEN "qcseriald" C_RESET " v%s daemon starting (PID %d)\n", QCSERIALD_VERSION, getpid());
    logprintf("Looking for supported modem (%zu vendors)...\n", NUM_VENDORS);

    pid_file_write(getpid());

    if (setup_bridges() < 0) {
        /* No modem — report to parent and enter rescan mode */
        dprintf(pipefd[1], "+" C_BOLD C_GREEN "qcseriald" C_RESET " started (PID %d)\n" C_YELLOW "No modem found — waiting for connection...\n" C_RESET, getpid());
        close(pipefd[1]);

        g_daemon_state = "waiting";
        logprintf(C_YELLOW "No modem found — entering rescan mode\n" C_RESET);
    } else {
        /* Report initial ports to parent (names may still be -loading) */
        char msg[2048];
        int off = snprintf(msg, sizeof(msg),
                           "+" C_BOLD C_GREEN "qcseriald" C_RESET " started (PID %d)\n%d serial port(s) created (" C_GREEN "identifying ports..." C_RESET "):\n",
                           getpid(), g_bridge_count);
        for (int i = 0; i < g_bridge_count && off < (int)sizeof(msg) - 128; i++)
            off += snprintf(msg + off, sizeof(msg) - off, "  " C_GREEN "%s" C_RESET "\n", g_bridges[i].link_name);

        write(pipefd[1], msg, off);
        close(pipefd[1]);

        logprintf("\n%d serial port(s) created — " C_GREEN "probing for port identification..." C_RESET "\n", g_bridge_count);

        /* Probe unknown ports (may take up to 30s for RDY timeout) */
        probe_ports();
        g_daemon_state = "running";

        logprintf("\n" C_BOLD "Final port assignment:" C_RESET "\n");
        for (int i = 0; i < g_bridge_count; i++)
            logprintf("  " C_GREEN "%s" C_RESET "\n", g_bridges[i].link_name);
    }

    run_monitor_loop();

    logprintf("Daemon shutting down...\n");
    shutdown_bridges();
    pid_file_remove();
    unlink(STATUS_FILE);
    logprintf("Done\n");
    _exit(0);
}

/* ── cmd_stop ── */

static int cmd_stop(void) {
    if (require_root("stop"))
        return 1;

    resolve_symlink_dir();
    pid_t pid = pid_file_read();
    if (!pid || !is_process_alive(pid)) {
        printf(C_YELLOW "qcseriald is not running\n" C_RESET);
        if (pid) pid_file_remove();
        cleanup_stale_symlinks();
        return 0;
    }

    printf("Stopping qcseriald (PID %d)...\n", pid);
    kill(pid, SIGTERM);

    /* Poll for exit — allow SHUTDOWN_TIMEOUT + 2s for monitor loop exit overhead */
    for (int i = 0; i < (SHUTDOWN_TIMEOUT + 2) * 10; i++) {
        usleep(100000);  /* 100ms */
        if (!is_process_alive(pid)) {
            printf(C_GREEN "Stopped\n" C_RESET);
            pid_file_remove();
            cleanup_stale_symlinks();
            return 0;
        }
    }

    /* Force kill */
    fprintf(stderr, C_RED "Process didn't exit gracefully — sending SIGKILL\n" C_RESET);
    kill(pid, SIGKILL);
    usleep(200000);
    pid_file_remove();
    cleanup_stale_symlinks();
    printf(C_YELLOW "Killed\n" C_RESET);
    return 0;
}

/* ── cmd_status ── */

static int cmd_status(void) {
    pid_t pid = pid_file_read();
    if (!pid || !is_process_alive(pid)) {
        printf(C_YELLOW "qcseriald is not running\n" C_RESET);
        if (pid) {
            printf("  (stale PID file for PID %d)\n", pid);
        }
        return 1;
    }

    printf(C_GREEN "qcseriald is running" C_RESET " (PID %d)\n", pid);

    /* Read status file */
    FILE *f = fopen(STATUS_FILE, "r");
    if (!f) {
        printf("  (no status file — daemon may be starting up)\n");
        return 0;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Strip trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';

        if (strncmp(line, "state=", 6) == 0) {
            const char *state = line + 6;
            if (strcmp(state, "waiting") == 0)
                printf("  " C_YELLOW "Waiting for modem to reconnect..." C_RESET "\n");
            else if (strcmp(state, "starting") == 0)
                printf("  " C_YELLOW "Starting up..." C_RESET "\n");
            else if (strcmp(state, "degraded") == 0)
                printf("  " C_RED "Running degraded — one or more bridges are dead "
                       "and rebuilding did not recover them" C_RESET "\n");
        } else if (strncmp(line, "edl=", 4) == 0) {
            printf("  " C_YELLOW "EDL device detected: %s (libusb port — not bridged)" C_RESET "\n", line + 4);
        } else if (strncmp(line, "bridges=", 8) == 0) {
            printf("  " C_BOLD "Bridges:" C_RESET " %s\n", line + 8);
        } else if (strncmp(line, "port.", 5) == 0) {
            /* Match on the health token specifically ("=healthy"/"=degraded"),
             * not the bare word: link paths and port names can contain either
             * with a naive search. degraded = accepts commands, never answers. */
            const char *color = strstr(line, "=healthy") ? C_GREEN
                              : strstr(line, "=degraded") ? C_YELLOW : C_RED;
            printf("  %s%s" C_RESET "\n", color, line);
        }
    }
    fclose(f);
    return 0;
}

/* ── Usage ── */

static int cmd_printlog(int follow) {
    if (access(LOG_FILE, R_OK) != 0) {
        fprintf(stderr, "No log file found at %s\n", LOG_FILE);
        return 1;
    }

    if (follow) {
        /* tail -f — exec so signal handling works naturally */
        execlp("tail", "tail", "-f", LOG_FILE, NULL);
        perror("tail");
        return 1;
    }

    /* Print entire log */
    FILE *f = fopen(LOG_FILE, "r");
    if (!f) {
        perror(LOG_FILE);
        return 1;
    }
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        fwrite(buf, 1, n, stdout);
    fclose(f);
    return 0;
}

static void cmd_version(void) {
    printf(C_BOLD C_GREEN
        "                             .*@@@-.                        \n"
        "                                  :@@@@-                    \n"
        "                                     @@@@#.                 \n"
        "      .+-                               #@@@@%%.+@-         \n"
        "    -@*@*@%%                                @@@@@::@@=       \n"
        ".+%%@@@@@@@@@%%=.                            =@@@@# #@@- .. \n"
        "    .@@@@@:                                :@@@@@ =@@@..%%=  \n"
        "      .%%- " C_RESET C_GREEN "                                 -@@@@@:=@@@@  @@#\n"
        "      .#-         .%%@@@@@@#.               +@@@@@.#@@@@  @@@.\n"
        "       :.             .%%@@@@@@@@@@@%%.     .@@@@@+:@@@@@  @@@-\n"
        "                        -@@@@@@@@@@@@@@@..@@@@@@.-@@@@@ .@@@-\n"
        "                          =@@@@@@@@*  .@@@@@@. @@@@@@..@@@@-\n"
        "                           @@@@@@:.-@@@@@@.  @@@@@@= %%@@@@@.\n"
        "                          .@@@@. *@@@@@@- .+@@@@@@-.@@@@@@+\n"
        "                          %%@@. =@@@@@*.  +@@@@@@%%.=@@@@@@%%\n"
        "                         =@.+@@@@@. -@@@@@@@*.:@@@@@@@*.\n"
        "                          ..@@@@= .@@@@@@: #@@@@@@@:\n"
        "                           .@@@@  +@@@@..%%@@@@@+.\n"
        "                            @@@.  @@@. @@@*    .@.\n"
        "                         -*: .@@* :@@. @@.  -..@@\n"
        "                       =@@@@@@.*@- :@%%  @* =@:=@#\n"
        "                      .@@@-+@@@@:%%@..%%- ...%%:@@:\n"
        "                       :@@ :+   *@     *@@#*@@@.\n"
        "                                  .*@@@:=@@@@:\n"
        "                            .@@@@#.-@@@@@.\n"
        "                         -@@@@@  @@@@@@%%\n"
        "                        :@@@@# =@@@@@@%%\n"
        "                         #@@@. @@@@@@*\n"
        "                              :@@@@@=\n"
        "                                   .=@@@@@-\n"
        C_RESET "\n");

    printf(C_BOLD C_GREEN "  qcseriald" C_RESET " v%s\n", QCSERIALD_VERSION);
    printf("  User-space Qualcomm USB serial bridge daemon for macOS\n");
    printf("  by " C_BOLD "%s" C_RESET "\n", QCSERIALD_AUTHOR);
    printf("  %s\n", QCSERIALD_URL);
    printf("  Part of " C_BOLD C_GREEN "qfenix" C_RESET "\n\n");
    printf("  Log file: %s\n", LOG_FILE);
}

static void usage(void) {
    fprintf(stderr, C_BOLD C_GREEN "qcseriald" C_RESET " v%s by %s\n", QCSERIALD_VERSION, QCSERIALD_AUTHOR);
    fprintf(stderr, "%s\n", QCSERIALD_URL);
    fprintf(stderr, "\n");
    fprintf(stderr, C_BOLD "Usage:" C_RESET " qcseriald <command> [options]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, C_BOLD "Commands:" C_RESET "\n");
    fprintf(stderr, "  " C_GREEN "start" C_RESET "              Daemonize, print ports, exit\n");
    fprintf(stderr, "  " C_GREEN "start --foreground" C_RESET " Run in foreground (for launchd)\n");
    fprintf(stderr, "  " C_GREEN "stop" C_RESET "               Stop running daemon\n");
    fprintf(stderr, "  " C_GREEN "restart" C_RESET "            Stop + start (clean reset)\n");
    fprintf(stderr, "  " C_GREEN "status" C_RESET "             Show running state and port health\n");
    fprintf(stderr, "  " C_GREEN "log" C_RESET "                Print daemon log (%s)\n", LOG_FILE);
    fprintf(stderr, "  " C_GREEN "log -f" C_RESET "             Follow daemon log (tail -f)\n");
    fprintf(stderr, "  " C_GREEN "version" C_RESET "            Show version and fenix art\n");
    fprintf(stderr, "\n");
    fprintf(stderr, C_BOLD "start / restart options:" C_RESET "\n");
    fprintf(stderr, "  " C_GREEN "-f, --foreground" C_RESET "   Run in foreground (for launchd)\n");
    fprintf(stderr, "  " C_GREEN "--match VID:PID" C_RESET "    Bind only this modem (hex, e.g. 2c7c:0801) when\n");
    fprintf(stderr, "                     several supported modems are attached. Either field\n");
    fprintf(stderr, "                     may be omitted (2c7c: = any Quectel PID).\n");
    fprintf(stderr, "  " C_GREEN "--serial STR" C_RESET "       Bind only the modem with this USB serial (exact,\n");
    fprintf(stderr, "                     case-insensitive); combine with --match to break ties.\n");
    fprintf(stderr, "                     Env fallback: QCSERIALD_MATCH, QCSERIALD_MATCH_SERIAL\n");
    fprintf(stderr, "                     (env needs sudoers env_keep to survive sudo).\n");
}

/* Parse a device-selection spec "<vid>[:<pid>]" (hex) into g_match_vid /
 * g_match_pid. Absent or invalid fields stay -1 (= match any). */
static void parse_match_spec(const char *spec) {
    if (!spec || !*spec) return;
    char buf[32];
    snprintf(buf, sizeof(buf), "%s", spec);
    char *colon = strchr(buf, ':');
    if (colon) *colon = '\0';
    if (buf[0]) {
        char *end = NULL;
        long v = strtol(buf, &end, 16);
        if (*end == '\0' && v >= 0 && v <= 0xffff) g_match_vid = (int)v;
        else fprintf(stderr, C_YELLOW "Ignoring bad --match VID: %s\n" C_RESET, buf);
    }
    if (colon && colon[1]) {
        char *end = NULL;
        long p = strtol(colon + 1, &end, 16);
        if (*end == '\0' && p >= 0 && p <= 0xffff) g_match_pid = (int)p;
        else fprintf(stderr, C_YELLOW "Ignoring bad --match PID: %s\n" C_RESET, colon + 1);
    }
}

/* Env fallback for device selection: fills any selector field the flags left
 * unset. QCSERIALD_MATCH="vid:pid", QCSERIALD_MATCH_SERIAL="serial". Env is
 * stripped by `sudo` unless whitelisted in sudoers env_keep — the flags are the
 * sudo-safe path. */
static void apply_selector_env(void) {
    const char *m = getenv("QCSERIALD_MATCH");
    if (m && *m && g_match_vid < 0 && g_match_pid < 0)
        parse_match_spec(m);
    const char *s = getenv("QCSERIALD_MATCH_SERIAL");
    if (s && *s && g_match_serial[0] == '\0')
        snprintf(g_match_serial, sizeof(g_match_serial), "%s", s);
}

/* Parse start/restart options starting at argv[from]. Sets *foreground and the
 * device-selection globals (g_match_vid/pid/serial). */
static void parse_start_opts(int argc, char **argv, int from, int *foreground) {
    for (int i = from; i < argc; i++) {
        if (strcmp(argv[i], "--foreground") == 0 || strcmp(argv[i], "-f") == 0) {
            *foreground = 1;
        } else if (strncmp(argv[i], "--match=", 8) == 0) {
            parse_match_spec(argv[i] + 8);
        } else if (strcmp(argv[i], "--match") == 0) {
            if (i + 1 < argc)
                parse_match_spec(argv[++i]);
            else
                fprintf(stderr, C_YELLOW "--match requires a VID:PID argument\n" C_RESET);
        } else if (strncmp(argv[i], "--serial=", 9) == 0) {
            snprintf(g_match_serial, sizeof(g_match_serial), "%s", argv[i] + 9);
        } else if (strcmp(argv[i], "--serial") == 0) {
            if (i + 1 < argc)
                snprintf(g_match_serial, sizeof(g_match_serial), "%s", argv[++i]);
            else
                fprintf(stderr, C_YELLOW "--serial requires a STRING argument\n" C_RESET);
        } else {
            fprintf(stderr, C_YELLOW "Ignoring unknown start option: %s\n" C_RESET, argv[i]);
        }
    }
    /* Env fallback fills any selector field the flags didn't set. */
    apply_selector_env();
}

/* ── Main ── */

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc < 2) {
        usage();
        return 1;
    }

    if (strcmp(argv[1], "start") == 0) {
        int foreground = 0;
        parse_start_opts(argc, argv, 2, &foreground);
        return cmd_start(foreground);
    } else if (strcmp(argv[1], "stop") == 0) {
        return cmd_stop();
    } else if (strcmp(argv[1], "restart") == 0) {
        if (require_root("restart"))
            return 1;
        cmd_stop();
        int foreground = 0;
        parse_start_opts(argc, argv, 2, &foreground);
        return cmd_start(foreground);
    } else if (strcmp(argv[1], "status") == 0) {
        return cmd_status();
    } else if (strcmp(argv[1], "log") == 0) {
        int follow = (argc >= 3 && strcmp(argv[2], "-f") == 0);
        return cmd_printlog(follow);
    } else if (strcmp(argv[1], "version") == 0 ||
               strcmp(argv[1], "--version") == 0 ||
               strcmp(argv[1], "-v") == 0) {
        cmd_version();
        return 0;
    } else {
        fprintf(stderr, C_RED "Unknown command: %s\n" C_RESET, argv[1]);
        usage();
        return 1;
    }
}
