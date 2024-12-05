#ifndef __BPF_HELPERS_H__
#define __BPF_HELPERS_H__

#include <linux/bpf.h>
#include <linux/types.h>

/* Additional helper macros */
#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif

/* BPF helper functions */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) BPF_FUNC_probe_read;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *) BPF_FUNC_trace_printk;
static int (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) BPF_FUNC_perf_event_output;

/* Memory access helpers */
#define BPF_PROBE_READ(dst, sz, src) \
    do { \
        typeof(dst) _dst = (dst); \
        typeof(src) _src = (src); \
        *((__u64 *)dst) = 0; \
        bpf_probe_read(_dst, sz, _src); \
    } while (0)

#endif /* __BPF_HELPERS_H__ */
