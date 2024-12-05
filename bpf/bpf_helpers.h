#ifndef __BPF_HELPERS_H__
#define __BPF_HELPERS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

/* Additional helper macros not defined in system headers */
#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif

#endif /* __BPF_HELPERS_H__ */
