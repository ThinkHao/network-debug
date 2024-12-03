#ifndef __BPF_HELPERS_H__
#define __BPF_HELPERS_H__

#include <stdint.h>

/* BPF helper functions */
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_map_update_elem 2
#define BPF_FUNC_map_delete_elem 3
#define BPF_FUNC_probe_read 4
#define BPF_FUNC_ktime_get_ns 5
#define BPF_FUNC_trace_printk 6
#define BPF_FUNC_get_current_pid_tgid 14
#define BPF_FUNC_get_current_task 35
#define BPF_FUNC_perf_event_output 25

/* BPF flags */
#define BPF_F_CURRENT_CPU 0xffffffffULL

/* helper macro to place programs, maps, license in specific sections */
#define SEC(name) __attribute__((section(name), used))

/* Helper macros */
#define __section(NAME) __attribute__((section(NAME), used))

/* BPF helper function prototypes */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, const void *key, const void *value, uint64_t flags) = (void *) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, uint32_t size, const void *unsafe_ptr) = (void *) BPF_FUNC_probe_read;
static uint64_t (*bpf_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;
static int (*bpf_trace_printk)(const char *fmt, uint32_t fmt_size, ...) = (void *) BPF_FUNC_trace_printk;
static uint64_t (*bpf_get_current_pid_tgid)(void) = (void *) BPF_FUNC_get_current_pid_tgid;
static uint64_t (*bpf_get_current_task)(void) = (void *) BPF_FUNC_get_current_task;
static int (*bpf_perf_event_output)(void *ctx, void *map, uint64_t flags, void *data, uint64_t size) = (void *) BPF_FUNC_perf_event_output;

#endif /* __BPF_HELPERS_H__ */
