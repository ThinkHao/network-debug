#ifndef __BPF_HELPERS_H__
#define __BPF_HELPERS_H__

#include <linux/bpf.h>
#include <linux/types.h>

/* Additional helper macros */
#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif

#endif /* __BPF_HELPERS_H__ */
