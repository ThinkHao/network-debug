#ifndef __BPF_TRACING_H__
#define __BPF_TRACING_H__

#include <stdint.h>

/* Register access macros */
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)

/* BPF map definitions */
#define BPF_MAP_TYPE_HASH           1
#define BPF_MAP_TYPE_ARRAY          2
#define BPF_MAP_TYPE_PROG_ARRAY     3
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4

/* BPF map attributes */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#endif /* __BPF_TRACING_H__ */
