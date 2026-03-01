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
#include <stdatomic.h>
#include <time.h>
#include <poll.h>
#include <util.h>  /* openpty */

#include <IOKit/IOKitLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/IOUSBLib.h>
#include <CoreFoundation/CoreFoundation.h>

/* ── Version ── */

#define QCSERIALD_VERSION "1.0.3"
#define QCSERIALD_AUTHOR  "iamromulan"
#define QCSERIALD_URL     "https://github.com/iamromulan/qcseriald-darwin"

/* ── ANSI colors (matches qfenix UX scheme) ── */

#define C_RESET  "\033[0m"
#define C_RED    "\033[31m"
#define C_YELLOW "\033[33m"
#define C_GREEN  "\033[38;5;121m"
#define C_BOLD   "\033[1m"

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
} bridge_t;

/* ── Globals ── */

static _Atomic(int) g_running = 1;

static bridge_t g_bridges[MAX_INTERFACES];
static int g_bridge_count = 0;

static pthread_mutex_t g_exit_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_exit_cond  = PTHREAD_COND_INITIALIZER;

static char g_symlink_dir[512] = DEV_DIR;


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
    const char *home = NULL;
    const char *sudo_user = getenv("SUDO_USER");
    if (sudo_user) {
        struct passwd *pw = getpwnam(sudo_user);
        if (pw)
            home = pw->pw_dir;
    }
    if (!home) {
        const char *logname = getenv("LOGNAME");
        if (logname) {
            struct passwd *pw = getpwnam(logname);
            if (pw)
                home = pw->pw_dir;
        }
    }
    if (!home)
        home = "/var/root";

    snprintf(g_symlink_dir, sizeof(g_symlink_dir), "%s/dev", home);

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

static void *usb_to_pty(void *arg) {
    bridge_t *b = (bridge_t *)arg;
    UInt8 buf[USB_BUF_SIZE];
    IOReturn kr;
    UInt32 len;

    atomic_store(&b->usb_to_pty_alive, 1);
    printf("[%s] USB->PTY thread started\n", b->func_name);

    while (atomic_load(&g_running) && atomic_load(&b->state) == BRIDGE_RUNNING) {
        len = sizeof(buf);
        kr = (*b->iface)->ReadPipe(b->iface, b->pipe_in, buf, &len);
        if (kr != kIOReturnSuccess) {
            if (kr == kIOReturnAborted || kr == kIOReturnNotResponding) {
                printf("[%s] USB->PTY ReadPipe: 0x%x (stopping)\n", b->func_name, kr);
                break;
            }
            if (kr == (IOReturn)0xe00002eb) {  /* kIOUSBPipeStalled */
                (*b->iface)->ClearPipeStall(b->iface, b->pipe_in);
                usleep(100000);
                continue;
            }
            fprintf(stderr, "[%s] USB->PTY ReadPipe error: 0x%x\n", b->func_name, kr);
            usleep(10000);
            continue;
        }
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
                    fprintf(stderr, "[%s] USB->PTY write error: %s\n", b->func_name, strerror(errno));
                    goto done;
                }
                written += n;
            }
        }
    }
    printf("[%s] USB->PTY loop ended (running=%d state=%d)\n",
           b->func_name, atomic_load(&g_running), atomic_load(&b->state));
done:
    atomic_store(&b->usb_to_pty_alive, 0);
    printf("[%s] USB->PTY thread exiting\n", b->func_name);

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
    printf("[%s] PTY->USB thread started\n", b->func_name);

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
            fprintf(stderr, "[%s] WritePipe error: 0x%x\n", b->func_name, kr);
        }
    }

    atomic_store(&b->pty_to_usb_alive, 0);
    printf("[%s] PTY->USB thread exiting\n", b->func_name);

    pthread_mutex_lock(&g_exit_mutex);
    pthread_cond_signal(&g_exit_cond);
    pthread_mutex_unlock(&g_exit_mutex);

    return NULL;
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
        fprintf(stderr, "Recovery: failed to create device plugin: 0x%x\n", kr);
        return -1;
    }

    (*plug)->QueryInterface(plug,
            CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID187),
            (LPVOID *)&dev);
    (*plug)->Release(plug);
    if (!dev) {
        fprintf(stderr, "Recovery: failed to get device interface\n");
        return -1;
    }

    /* Seize the device — may succeed even with stale interface locks since
     * our normal path never does USBDeviceOpen(). */
    kr = (*dev)->USBDeviceOpenSeize(dev);
    if (kr != kIOReturnSuccess) {
        fprintf(stderr, "Recovery: USBDeviceOpenSeize failed: 0x%x\n", kr);
        (*dev)->Release(dev);
        return -1;
    }

    /* Re-enumerate: terminates all clients, simulates unplug/replug */
    printf("Recovery: triggering USB re-enumeration to clear stale locks...\n");
    kr = (*dev)->USBDeviceReEnumerate(dev, 0);

    (*dev)->USBDeviceClose(dev);
    (*dev)->Release(dev);

    if (kr != kIOReturnSuccess) {
        fprintf(stderr, "Recovery: USBDeviceReEnumerate failed: 0x%x\n", kr);
        return -1;
    }

    /* Wait for re-enumeration to complete — device disappears and re-appears */
    printf("Recovery: waiting for USB re-enumeration (3s)...\n");
    sleep(3);
    return 0;
}

/* ── Setup: find USB device and open interfaces ── */

static int setup_bridges(void) {
    /* Find the USB device — match all IOUSBHostDevice, filter VID manually */
    CFMutableDictionaryRef match = IOServiceMatching("IOUSBHostDevice");
    if (!match) {
        fprintf(stderr, "Failed to create matching dict\n");
        return -1;
    }

    io_iterator_t dev_iter;
    IOReturn kr = IOServiceGetMatchingServices(kIOMainPortDefault, match, &dev_iter);
    if (kr != kIOReturnSuccess) {
        fprintf(stderr, "IOServiceGetMatchingServices failed: 0x%x\n", kr);
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
                device = candidate;
                break;
            }
        }
        IOObjectRelease(candidate);
    }
    IOObjectRelease(dev_iter);

    if (!device) {
        return -1;  /* No modem found — caller will retry */
    }

    printf("Matched vendor: %s (VID 0x%04x PID 0x%04x)\n", matched_vendor, matched_vid, matched_pid);

    /* Get product name */
    CFStringRef product = IORegistryEntryCreateCFProperty(device, CFSTR("USB Product Name"),
                                                          kCFAllocatorDefault, 0);
    if (product) {
        char name[128];
        CFStringGetCString(product, name, sizeof(name), kCFStringEncodingUTF8);
        printf("Found: %s\n", name);
        CFRelease(product);
    }

    /* Look up known DIAG interface number for this VID/PID */
    int known_diag_iface = get_diag_iface((uint16_t)matched_vid, (uint16_t)matched_pid);

    /* Find vendor-specific interfaces via IOKit registry (no device-level exclusive access needed).
     * This avoids USBDeviceOpen() which would block ADB and cause stale-lock issues. */
    io_iterator_t child_iter;
    kr = IORegistryEntryCreateIterator(device, kIOServicePlane,
                                        kIORegistryIterateRecursively, &child_iter);
    if (kr != kIOReturnSuccess) {
        fprintf(stderr, "Failed to create child iterator: 0x%x\n", kr);
        IOObjectRelease(device);
        return -1;
    }

    int exclusive_access_hit = 0;
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
            printf("Skipping ADB interface %d (use 'adb devices' directly)\n", iface_num);
            (*iface)->Release(iface);
            continue;
        }

        kr = (*iface)->USBInterfaceOpen(iface);
        if (kr != kIOReturnSuccess) {
            if (kr == (IOReturn)0xe00002c5)  /* kIOReturnExclusiveAccess */
                exclusive_access_hit = 1;
            fprintf(stderr, "Failed to open interface %d: 0x%x\n", iface_num, kr);
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
            printf("Interface %d: no bulk IN/OUT pair, skipping\n", iface_num);
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

        /* Make PTY slave accessible to non-root users, then close it */
        chmod(slave_name, 0666);
        close(slave);

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
            fprintf(stderr, "Warning: symlink %s -> %s failed: %s\n",
                    link, slave_name, strerror(errno));
            snprintf(link, sizeof(link), "%s", slave_name);
        }

        bridge_t *b = &g_bridges[g_bridge_count];
        memset(b, 0, sizeof(*b));
        b->iface_num = iface_num;
        b->pty_master = master;
        strncpy(b->pty_name, slave_name, sizeof(b->pty_name) - 1);
        strncpy(b->link_name, link, sizeof(b->link_name) - 1);
        strncpy(b->func_name, func, sizeof(b->func_name) - 1);
        b->iface = iface;
        b->pipe_in = pipe_in;
        b->pipe_out = pipe_out;
        atomic_store(&b->state, BRIDGE_RUNNING);
        atomic_store(&b->usb_to_pty_alive, 0);
        atomic_store(&b->pty_to_usb_alive, 0);

        printf("Interface %d (%s): %s -> %s\n", iface_num, func, slave_name, link);
        printf("  Bulk IN pipe %d, Bulk OUT pipe %d, %d endpoints\n",
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

    /* If we got exclusive access errors and opened zero bridges, attempt recovery */
    if (g_bridge_count == 0 && exclusive_access_hit) {
        printf("Exclusive access conflict — attempting USB re-enumeration recovery...\n");
        if (attempt_usb_recovery(device) == 0) {
            IOObjectRelease(device);
            /* Retry from scratch after re-enumeration */
            return setup_bridges();
        }
        fprintf(stderr, "Recovery failed — modem unplug/replug may be required\n");
    }

    IOObjectRelease(device);

    if (g_bridge_count == 0)
        return -1;

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
        fprintf(stderr, "Warning: symlink %s -> %s failed: %s\n",
                new_link, b->pty_name, strerror(errno));
        return;
    }

    printf("  Identified: %s -> %s/" SYMLINK_PREFIX "%s\n", b->func_name, g_symlink_dir, new_name);
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
            fprintf(stderr, "Probe: failed to open %s: %s\n",
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
    printf("Probing %d unknown port(s) — trying AT command...\n", count);

    /* Send AT on all unknown ports simultaneously */
    for (int i = 0; i < count; i++) {
        tcflush(fds[i], TCIOFLUSH);
        write(fds[i], "AT\r", 3);
    }

    /* Collect responses (up to PROBE_AT_TIMEOUT seconds) */
    char accum[MAX_INTERFACES][512];
    int accum_len[MAX_INTERFACES];
    memset(accum_len, 0, sizeof(accum_len));
    int any_responded = 0;

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
                printf("  [%s] AT port detected\n", g_bridges[idx[i]].func_name);
            }
            /* Check for NMEA data */
            else if (strstr(accum[i], "$G")) {
                types[i] = PORT_NMEA;
                any_responded = 1;
                printf("  [%s] NMEA data detected — GPS port\n",
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
            printf("Retrying AT on %d remaining port(s)...\n", unknown_remain);
            for (int i = 0; i < count; i++) {
                if (types[i] != PORT_UNKNOWN) continue;
                if (!atomic_load(&g_running)) break;

                tcflush(fds[i], TCIOFLUSH);
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
                    printf("  [%s] AT port detected\n", g_bridges[idx[i]].func_name);
                }
            }
        }
        goto done;
    }

    /* Phase 2: No port responded to AT — modem not ready yet.
     * Wait for RDY URC (up to PROBE_RDY_TIMEOUT seconds), then retry AT.
     * RDY on ANY port means modem is ready, so immediately AT-probe the rest. */
    printf("No AT response — modem not ready, waiting for RDY URC (up to %ds)...\n",
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
                printf("  [%s] RDY URC — AT port (modem ready)\n",
                       g_bridges[idx[i]].func_name);
            } else if (strstr(accum[i], "$G")) {
                types[i] = PORT_NMEA;
                printf("  [%s] NMEA data — GPS port\n",
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
            printf("AT-probing %d remaining port(s)...\n", unknown_remain);
            for (int i = 0; i < count; i++) {
                if (types[i] != PORT_UNKNOWN) continue;
                if (!atomic_load(&g_running)) break;

                tcflush(fds[i], TCIOFLUSH);
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
                    printf("  [%s] AT port detected\n", g_bridges[idx[i]].func_name);
                } else {
                    printf("  [%s] No response\n", g_bridges[idx[i]].func_name);
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
                printf("  [%s] Remaining port assumed NMEA/GPS\n",
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

    printf("Shutting down %d bridge(s)...\n", g_bridge_count);

    /* 1. Set all bridges to STOPPING */
    for (int i = 0; i < g_bridge_count; i++) {
        atomic_store(&g_bridges[i].state, BRIDGE_STOPPING);
    }

    /* 2. Close PTY masters FIRST to unblock read() in pty_to_usb threads.
     *    Must happen before AbortPipe — if the USB interface is dead (modem
     *    disconnected), AbortPipe may not work, but closing the master fd
     *    will make read() return EBADF and break the pty_to_usb thread out. */
    for (int i = 0; i < g_bridge_count; i++) {
        if (g_bridges[i].pty_master >= 0) {
            close(g_bridges[i].pty_master);
            g_bridges[i].pty_master = -1;
        }
    }

    /* 3. Abort BOTH pipe_in AND pipe_out to unblock ReadPipe/WritePipe */
    for (int i = 0; i < g_bridge_count; i++) {
        bridge_t *b = &g_bridges[i];
        if (b->iface) {
            (*b->iface)->AbortPipe(b->iface, b->pipe_in);
            (*b->iface)->AbortPipe(b->iface, b->pipe_out);
        }
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
            fprintf(stderr, "Shutdown timeout — stuck threads:\n");
            for (int i = 0; i < g_bridge_count; i++) {
                bridge_t *b = &g_bridges[i];
                int u2p = atomic_load(&b->usb_to_pty_alive);
                int p2u = atomic_load(&b->pty_to_usb_alive);
                if (u2p || p2u)
                    fprintf(stderr, "  [%s] usb_to_pty=%d pty_to_usb=%d\n",
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
    printf("All bridges shut down\n");
}

/* ── Status file ── */

static void write_status_file(void) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", STATUS_FILE);
    FILE *f = fopen(tmp, "w");
    if (!f) return;

    fprintf(f, "pid=%d\n", getpid());
    fprintf(f, "bridges=%d\n", g_bridge_count);
    for (int i = 0; i < g_bridge_count; i++) {
        bridge_t *b = &g_bridges[i];
        int u2p = atomic_load(&b->usb_to_pty_alive);
        int p2u = atomic_load(&b->pty_to_usb_alive);
        const char *health = (u2p && p2u) ? "healthy" : "dead";
        fprintf(f, "port.%s=%s usb2pty=%d pty2usb=%d link=%s\n",
                b->func_name, health, u2p, p2u, b->link_name);
    }
    fclose(f);
    rename(tmp, STATUS_FILE);
}

/* ── Health monitor + auto-restart loop ── */

static void run_monitor_loop(void) {
    int prev_bridge_count = 0;  /* remember how many bridges we had before disconnect */

    while (atomic_load(&g_running)) {
        /* Health check — USB→PTY thread death means modem disconnected.
         * PTY→USB threads stay alive (waiting for slave data) so we only
         * check usb_to_pty_alive for disconnect detection. */
        int alive_count = 0;
        for (int i = 0; i < g_bridge_count; i++) {
            if (atomic_load(&g_bridges[i].usb_to_pty_alive))
                alive_count++;
        }

        write_status_file();

        if (g_bridge_count > 0 && alive_count == 0) {
            printf(C_YELLOW "All bridges dead — modem likely disconnected\n" C_RESET);
            if (g_bridge_count > prev_bridge_count)
                prev_bridge_count = g_bridge_count;
            shutdown_bridges();

            /* Enter rescan loop */
            printf(C_YELLOW "Waiting for modem to reconnect...\n" C_RESET);
            int retries_with_partial = 0;
            while (atomic_load(&g_running)) {
                /* Sleep interruptibly — check g_running each second */
                for (int s = 0; s < RESCAN_INTERVAL && atomic_load(&g_running); s++)
                    sleep(1);

                if (!atomic_load(&g_running)) break;

                if (setup_bridges() == 0) {
                    /* If we got fewer bridges than before, the modem may still
                     * be re-enumerating. Tear down and retry a few times. */
                    if (g_bridge_count < prev_bridge_count && retries_with_partial < 3) {
                        printf(C_YELLOW "Partial reconnect (%d/%d bridges) — retrying...\n" C_RESET,
                               g_bridge_count, prev_bridge_count);
                        shutdown_bridges();
                        retries_with_partial++;
                        continue;
                    }
                    probe_ports();
                    printf(C_GREEN "Modem reconnected — %d bridge(s) active\n" C_RESET, g_bridge_count);
                    prev_bridge_count = g_bridge_count;
                    printf("\n" C_BOLD "Active ports:" C_RESET "\n");
                    for (int i = 0; i < g_bridge_count; i++)
                        printf("  " C_GREEN "%s" C_RESET "\n", g_bridges[i].link_name);
                    break;
                }
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

/* ── cmd_start ── */

static int cmd_start(int foreground) {
    /* Check for existing instance */
    pid_t existing = pid_file_read();
    if (existing && is_process_alive(existing)) {
        fprintf(stderr, C_YELLOW "qcseriald already running (PID %d)\n" C_RESET, existing);
        fprintf(stderr, "Use '" C_GREEN "qcseriald stop" C_RESET "' first, or '" C_GREEN "qcseriald status" C_RESET "' for details.\n");
        return 1;
    }

    /* Clean up stale state from previous crash */
    if (existing) {
        printf("Cleaning up stale PID file (PID %d no longer running)\n", existing);
        pid_file_remove();
    }
    resolve_symlink_dir();
    cleanup_stale_symlinks();

    set_adb_libusb_env();

    if (foreground) {
        /* Run in foreground (for launchd or manual debugging) */
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);

        printf(C_BOLD C_GREEN "qcseriald" C_RESET " v%s — User-space USB serial bridge (foreground)\n", QCSERIALD_VERSION);
        printf("Looking for supported modem (%zu vendors)...\n", NUM_VENDORS);

        pid_file_write(getpid());

        if (setup_bridges() < 0) {
            fprintf(stderr, C_YELLOW "No modem found — entering rescan mode\n" C_RESET);
        } else {
            probe_ports();
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

    /* Redirect stdout/stderr to log file */
    int logfd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (logfd >= 0) {
        dup2(logfd, STDOUT_FILENO);
        dup2(logfd, STDERR_FILENO);
        close(logfd);
    }
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    /* Close stdin */
    int devnull = open("/dev/null", O_RDONLY);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        close(devnull);
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf(C_BOLD C_GREEN "qcseriald" C_RESET " v%s daemon starting (PID %d)\n", QCSERIALD_VERSION, getpid());
    printf("Looking for supported modem (%zu vendors)...\n", NUM_VENDORS);

    pid_file_write(getpid());

    if (setup_bridges() < 0) {
        /* No modem — report to parent and enter rescan mode */
        dprintf(pipefd[1], "+" C_BOLD C_GREEN "qcseriald" C_RESET " started (PID %d)\n" C_YELLOW "No modem found — waiting for connection...\n" C_RESET, getpid());
        close(pipefd[1]);

        printf(C_YELLOW "No modem found — entering rescan mode\n" C_RESET);
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

        printf("\n%d serial port(s) created — " C_GREEN "probing for port identification..." C_RESET "\n", g_bridge_count);

        /* Probe unknown ports (may take up to 30s for RDY timeout) */
        probe_ports();

        printf("\n" C_BOLD "Final port assignment:" C_RESET "\n");
        for (int i = 0; i < g_bridge_count; i++)
            printf("  " C_GREEN "%s" C_RESET "\n", g_bridges[i].link_name);
    }

    run_monitor_loop();

    printf("Daemon shutting down...\n");
    shutdown_bridges();
    pid_file_remove();
    unlink(STATUS_FILE);
    printf("Done\n");
    _exit(0);
}

/* ── cmd_stop ── */

static int cmd_stop(void) {
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

        if (strncmp(line, "bridges=", 8) == 0) {
            printf("  " C_BOLD "Bridges:" C_RESET " %s\n", line + 8);
        } else if (strncmp(line, "port.", 5) == 0) {
            const char *color = strstr(line, "healthy") ? C_GREEN : C_RED;
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
        if (argc >= 3 && strcmp(argv[2], "--foreground") == 0)
            foreground = 1;
        return cmd_start(foreground);
    } else if (strcmp(argv[1], "stop") == 0) {
        return cmd_stop();
    } else if (strcmp(argv[1], "restart") == 0) {
        cmd_stop();
        int foreground = 0;
        if (argc >= 3 && strcmp(argv[2], "--foreground") == 0)
            foreground = 1;
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
