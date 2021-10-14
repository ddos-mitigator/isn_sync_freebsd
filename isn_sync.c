#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/callout.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/module.h>

#include <crypto/siphash/siphash.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/ip_options.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_syncache.h>

/*
 * Imported variables.
 */
#define ISN_SECRET_LENGTH (32)
#define TS_OFFSET_SECRET_LENGTH (32)

VNET_DECLARE(int, isn_last_reseed);
#define V_isn_last_reseed VNET(isn_last_reseed)
VNET_DECLARE(u_int32_t, isn_offset);
#define V_isn_offset VNET(isn_offset)
VNET_DECLARE(u_int32_t, isn_offset_old);
#define V_isn_offset_old VNET(isn_offset_old)
VNET_DECLARE(u_char, isn_secret[ISN_SECRET_LENGTH]);
#define V_isn_secret VNET(isn_secret)
VNET_DECLARE(int, tcp_do_ecn);
#define V_tcp_do_ecn VNET(tcp_do_ecn)
VNET_DECLARE(int, tcp_do_sack);
#define V_tcp_do_sack VNET(tcp_do_sack)
VNET_DECLARE(int, tcp_isn_reseed_interval);
#define V_tcp_isn_reseed_interval VNET(tcp_isn_reseed_interval)
VNET_DECLARE(struct tcp_syncache, tcp_syncache);
#define V_tcp_syncache VNET(tcp_syncache)
VNET_DECLARE(int, tcp_ts_offset_per_conn);
#define V_tcp_ts_offset_per_conn VNET(tcp_ts_offset_per_conn)
VNET_DECLARE(u_char, ts_offset_secret[TS_OFFSET_SECRET_LENGTH]);
#define V_ts_offset_secret VNET(ts_offset_secret)

/*
 * Sysctl: isn_sync root node.
 */
SYSCTL_ROOT_NODE(OID_AUTO, isn_sync, CTLFLAG_RD | CTLFLAG_VNET, 0, "isn_sync module");

/*
 * Sysctl: isn_sync params.
 */
#define SYNCOOKIE_SECRET_STR_LEN (SYNCOOKIE_SECRET_SIZE * 2)
#define TS_OFFSET_SECRET_STR_LEN (TS_OFFSET_SECRET_LENGTH * 2)
#define ISN_SECRET_STR_LEN (ISN_SECRET_LENGTH * 2)

struct IsnSyncParams {
    char cookie_secret[SYNCOOKIE_SECRET_STR_LEN + 1];
    uint32_t hash_secret;
    uint32_t hash_size_pow2;
    uint64_t hash_base;
    uint64_t sch_size;
    char ts_offset_secret[TS_OFFSET_SECRET_STR_LEN + 1];
    char isn_secret[ISN_SECRET_STR_LEN + 1];
    uint32_t isn_seq_speed;
    uint32_t clock_hz;
    uint64_t clock_jiffies;
    uint64_t clock_uptime_ms;
    uint64_t clock_time_ms;
    bool tcp_options_ecn_enabled;
    bool tcp_options_sack_enabled;
    bool tcp_options_rfc1323_enabled;
    bool tcp_options_ts_offset_per_conn_enabled;
};
VNET_DEFINE_STATIC(struct IsnSyncParams, isn_sync_params);
#define V_isn_sync_params VNET(isn_sync_params)

SYSCTL_NODE(_isn_sync, OID_AUTO, params, CTLFLAG_RD | CTLFLAG_VNET, 0, 0);
SYSCTL_STRING(_isn_sync_params, OID_AUTO,
        cookie_secret, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.cookie_secret),
        sizeof(V_isn_sync_params.cookie_secret), 0);
SYSCTL_U32(_isn_sync_params, OID_AUTO,
        hash_secret, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.hash_secret), 0, 0);
SYSCTL_U32(_isn_sync_params, OID_AUTO,
        hash_size_pow2, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.hash_size_pow2), 0, 0);
SYSCTL_U64(_isn_sync_params, OID_AUTO,
        hash_base, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.hash_base), 0, 0);
SYSCTL_U64(_isn_sync_params, OID_AUTO,
        sch_size, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.sch_size), 0, 0);
SYSCTL_STRING(_isn_sync_params, OID_AUTO,
        ts_offset_secret, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.ts_offset_secret),
        sizeof(V_isn_sync_params.ts_offset_secret), 0);
SYSCTL_STRING(_isn_sync_params, OID_AUTO,
        isn_secret, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.isn_secret),
        sizeof(V_isn_sync_params.isn_secret), 0);
SYSCTL_U32(_isn_sync_params, OID_AUTO,
        isn_seq_speed, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.isn_seq_speed), 0, 0);

SYSCTL_NODE(_isn_sync_params, OID_AUTO, clock, CTLFLAG_RD | CTLFLAG_VNET, 0, 0);
SYSCTL_U32(_isn_sync_params_clock, OID_AUTO,
        hz, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.clock_hz), 0, 0);
SYSCTL_U64(_isn_sync_params_clock, OID_AUTO,
        jiffies, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.clock_jiffies), 0, 0);
SYSCTL_U64(_isn_sync_params_clock, OID_AUTO,
        uptime_ms, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.clock_uptime_ms), 0, 0);
SYSCTL_U64(_isn_sync_params_clock, OID_AUTO,
        time_ms, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.clock_time_ms), 0, 0);

SYSCTL_NODE(_isn_sync_params, OID_AUTO, tcp_options, CTLFLAG_RD | CTLFLAG_VNET, 0, 0);
SYSCTL_BOOL(_isn_sync_params_tcp_options, OID_AUTO,
        ecn_enabled, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.tcp_options_ecn_enabled), 0, 0);
SYSCTL_BOOL(_isn_sync_params_tcp_options, OID_AUTO,
        sack_enabled, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.tcp_options_sack_enabled), 0, 0);
SYSCTL_BOOL(_isn_sync_params_tcp_options, OID_AUTO,
        rfc1323_enabled, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.tcp_options_rfc1323_enabled), 0, 0);
SYSCTL_BOOL(_isn_sync_params_tcp_options, OID_AUTO,
        ts_offset_per_conn_enabled, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_params.tcp_options_ts_offset_per_conn_enabled), 0, 0);

/*
 * Sysctl: isn_sync debug.
 */
struct IsnSyncDebug {
    uint32_t syncookie_current_epoch;
    uint32_t isn_offset_max_runaway_ms;
};
VNET_DEFINE_STATIC(struct IsnSyncDebug, isn_sync_debug);
#define V_isn_sync_debug VNET(isn_sync_debug)

SYSCTL_NODE(_isn_sync, OID_AUTO, debug, CTLFLAG_RD | CTLFLAG_VNET, 0, 0);
SYSCTL_U32(_isn_sync_debug, OID_AUTO,
        syncookie_current_epoch, CTLFLAG_RD | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_debug.syncookie_current_epoch), 0, 0);
SYSCTL_U32(_isn_sync_debug, OID_AUTO,
        isn_offset_max_runaway_ms, CTLFLAG_RW | CTLFLAG_VNET,
        &VNET_NAME(isn_sync_debug.isn_offset_max_runaway_ms), 0, 0);

/*
 * Common.
 */
static uint64_t isn_sync_tv_to_ms(const struct timeval* tv) {
    #define MS_PER_SEC 1000
    #define US_PER_MS  1000
    return (tv->tv_sec * MS_PER_SEC) + (tv->tv_usec / US_PER_MS);
}

static uint64_t isn_sync_get_uptime_ms() {
    struct timeval tv;
    getmicrouptime(&tv);
    return isn_sync_tv_to_ms(&tv);
}

static uint64_t isn_sync_get_time_ms() {
    struct timeval tv;
    getmicrotime(&tv);
    return isn_sync_tv_to_ms(&tv);
}

/*
 * Isn.
 */
static void isn_sync_generate_isn_secret() {
    if (V_isn_last_reseed != 0) {
        return;
    }
    arc4rand(&V_isn_secret, sizeof(V_isn_secret), 0);
    V_isn_last_reseed = ticks;
}

VNET_DEFINE_STATIC(uint32_t, isn_offset_fix) = 0;
#define V_isn_offset_fix VNET(isn_offset_fix)
VNET_DEFINE_STATIC(struct callout, isn_sync_isn_timer_ref);
#define V_isn_sync_isn_timer_ref VNET(isn_sync_isn_timer_ref)

static void isn_sync_isn_timer(void* arg);

static void isn_sync_isn_timer_init() {
    V_isn_offset_fix = V_isn_offset;
    callout_init(&V_isn_sync_isn_timer_ref, 1);
    callout_reset(&V_isn_sync_isn_timer_ref, hz, isn_sync_isn_timer, curvnet);
}

static void isn_sync_isn_timer_deinit() {
    callout_drain(&V_isn_sync_isn_timer_ref);
}

static void isn_sync_isn_timer(void* arg) {
    CURVNET_SET(arg);
    V_isn_offset_fix = isn_sync_get_uptime_ms() * V_isn_sync_params.isn_seq_speed;
    uint32_t isn_offset = atomic_load_acq_int(&V_isn_offset);
    atomic_store_rel_int(&V_isn_offset_old, V_isn_offset_fix);
    atomic_store_rel_int(&V_isn_offset, V_isn_offset_fix);
    if (SEQ_GT(isn_offset, V_isn_offset_fix)) {
        uint32_t runaway_ms = (isn_offset - V_isn_offset_fix) /
                V_isn_sync_params.isn_seq_speed;
        if (V_isn_sync_debug.isn_offset_max_runaway_ms < runaway_ms) {
            V_isn_sync_debug.isn_offset_max_runaway_ms = runaway_ms;
        }
    }
    callout_schedule(&V_isn_sync_isn_timer_ref, hz);
    CURVNET_RESTORE();
}

/*
 * Syncookie.
 */
#define EPOCH_PERIOD_MS (15000)
static uint32_t isn_sync_get_epoch() {
    return isn_sync_get_uptime_ms() / EPOCH_PERIOD_MS;
}

static void isn_sync_debug_init() {
    V_isn_sync_debug.syncookie_current_epoch = 0;
    V_isn_sync_debug.isn_offset_max_runaway_ms = 0;
}

static void isn_sync_syncache_timer_stop() {
    V_tcp_isn_reseed_interval = 0;
    callout_drain(&V_tcp_syncache.secret.reseed);
}

static void isn_sync_syncache_timer_recover() {
    callout_schedule(&V_tcp_syncache.secret.reseed, SYNCOOKIE_LIFETIME * hz);
}

struct SipKey {
    union {
        uint8_t u8[16];
        uint64_t u64[2];
    };
};
VNET_DEFINE_STATIC(struct SipKey, cookie_secret);
#define V_cookie_secret VNET(cookie_secret)

static void isn_sync_generate_cookie_secret() {
    _Static_assert(sizeof(V_cookie_secret.u8) ==
            sizeof(V_tcp_syncache.secret.key[0]), "");
    uint32_t epoch = isn_sync_get_epoch();
    bcopy(V_tcp_syncache.secret.key[epoch & 0x1], V_cookie_secret.u8,
            sizeof(V_cookie_secret.u8));
    V_cookie_secret.u64[0] -= epoch;
    V_cookie_secret.u64[1] += epoch;
    V_isn_sync_debug.syncookie_current_epoch = epoch;
    atomic_store_rel_int(&V_tcp_syncache.secret.oddeven, epoch);
}

/*
 * Module.
 */
#define HEX "0123456789abcdef"
static void print_to(char* dst, uint8_t* src, size_t src_size) {
    size_t i = 0;
    for (uint8_t* it = src; it != (src + src_size); ++it) {
        dst[i++] = HEX[(*it) >> 4];
        dst[i++] = HEX[(*it) & 0xf];
    }
    dst[i] = '\0';
}

static void isn_sync_refill_periodicly() {
    V_isn_sync_params.clock_hz = hz;
    V_isn_sync_params.clock_jiffies = ticks;
    V_isn_sync_params.clock_uptime_ms = isn_sync_get_uptime_ms();
    V_isn_sync_params.clock_time_ms = isn_sync_get_time_ms();

    V_isn_sync_params.tcp_options_ecn_enabled = (V_tcp_do_ecn != 0 );
    V_isn_sync_params.tcp_options_sack_enabled = (V_tcp_do_sack != 0);
    V_isn_sync_params.tcp_options_rfc1323_enabled = (V_tcp_do_rfc1323 != 0);
    V_isn_sync_params.tcp_options_ts_offset_per_conn_enabled =
            V_tcp_ts_offset_per_conn;
}

#define ISN_SEQ_PERIOD_MS 240000
static void isn_sync_fill() {
    print_to(V_isn_sync_params.cookie_secret,
            V_cookie_secret.u8, sizeof(V_cookie_secret.u8));
    V_isn_sync_params.hash_secret = V_tcp_syncache.hash_secret;
    V_isn_sync_params.hash_size_pow2 = __builtin_ctz(V_tcp_syncache.hashsize);
    V_isn_sync_params.hash_base = (uint64_t)V_tcp_syncache.hashbase;
    V_isn_sync_params.sch_size = sizeof(struct syncache_head);
    print_to(V_isn_sync_params.ts_offset_secret,
            V_ts_offset_secret, sizeof(V_ts_offset_secret));
    print_to(V_isn_sync_params.isn_secret,
            V_isn_secret, sizeof(V_isn_secret));
    V_isn_sync_params.isn_seq_speed = UINT_MAX / ISN_SEQ_PERIOD_MS;
    isn_sync_refill_periodicly();
}

VNET_DEFINE_STATIC(struct callout, isn_sync_syncookie_timer_ref);
#define V_isn_sync_syncookie_timer_ref VNET(isn_sync_syncookie_timer_ref)

static void isn_sync_syncookie_timer(void* arg);

static void isn_sync_syncookie_timer_init() {
    callout_init(&V_isn_sync_syncookie_timer_ref, 1);
    callout_reset(&V_isn_sync_syncookie_timer_ref,
            hz, isn_sync_syncookie_timer, &V_tcp_syncache);
}

static void isn_sync_syncookie_timer_deinit() {
    callout_drain(&V_isn_sync_syncookie_timer_ref);
}

static void isn_sync_syncookie_timer(void* arg) {
    struct tcp_syncache* sc __attribute__((unused)) = arg;
    CURVNET_SET(sc->vnet);
    uint32_t epoch = isn_sync_get_epoch();
    if (epoch != sc->secret.oddeven) {
        struct SipKey next_key;
        bcopy(V_cookie_secret.u8, next_key.u8, sizeof(next_key.u8));
        next_key.u64[0] += epoch;
        next_key.u64[1] -= epoch;
        bcopy(next_key.u8, sc->secret.key[epoch & 0x1], sizeof(sc->secret.key[0]));
        atomic_store_rel_int(&V_tcp_syncache.secret.oddeven, epoch);
        V_isn_sync_debug.syncookie_current_epoch = epoch;
    }
    isn_sync_refill_periodicly();
    callout_schedule(&V_isn_sync_syncookie_timer_ref, hz);
    CURVNET_RESTORE();
}

/*
 * Module.
 */
static int isn_sync_event_handler(struct module* mod, int event_type, void* arg) {
    CURVNET_SET(vnet0);

    int retval = 0;

    switch (event_type) {
    case MOD_LOAD:
        isn_sync_debug_init();
        isn_sync_syncache_timer_stop();
        isn_sync_generate_cookie_secret();
        isn_sync_generate_isn_secret();
        isn_sync_fill();
        isn_sync_syncookie_timer_init();
        isn_sync_isn_timer_init();
        uprintf("isn_sync module loaded\n");
        break;
    case MOD_UNLOAD:
        isn_sync_isn_timer_deinit();
        isn_sync_syncookie_timer_deinit();
        isn_sync_syncache_timer_recover();
        uprintf("isn_sync module unloaded\n");
        break;
    default:
        retval = EOPNOTSUPP;
        break;
    }

    CURVNET_RESTORE();
    return retval;
}

static moduledata_t isn_sync_data = {"isn_sync", isn_sync_event_handler, NULL};
DECLARE_MODULE(isn_sync, isn_sync_data, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
