You are given one failing eBPF verifier case.

Constraints:
- Do not use tools.
- Do not search the internet.
- Do not run the verifier.
- Do not assume access to any file other than the source and verifier log below.

Task:
Explain the verifier failure and propose the smallest source-level fix that is
likely to make the program pass verification. If a complete patch is clear,
provide it. Otherwise describe the exact edit and why it should satisfy the
verifier.

Source:
```c
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct map_value {
	struct task_struct *task;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct map_value);
	__uint(max_entries, 1);
} map_a SEC(".maps");

static struct map_value *map_value_lookup(struct task_struct *task)
{
	s32 pid;
	long status;

	status = bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
	if (status)
		return NULL;

	return bpf_map_lookup_elem(&map_a, &pid);
}

static int map_insert(struct task_struct *task)
{
	struct task_struct *acquired, *old;
	struct map_value local, *value;
	long status;
	s32 pid;

	status = bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
	if (status)
		return status;

	local.task = NULL;
	status = bpf_map_update_elem(&map_a, &pid, &local, BPF_NOEXIST);
	if (status)
		return status;

	value = bpf_map_lookup_elem(&map_a, &pid);
	if (!value) {
		bpf_map_delete_elem(&map_a, &pid);
		return -ENOENT;
	}

	acquired = bpf_task_acquire(task);
	if (!acquired)
		return -ENOENT;

	old = bpf_kptr_xchg(&value->task, acquired);
	if (old) {
		bpf_task_release(old);
		return -EEXIST;
	}

	return 0;
}

static struct map_value *helper_a(struct task_struct *task)
{
	int status;

	status = map_insert(task);
	if (status)
		return NULL;

	return map_value_lookup(task);
}

SEC("tp_btf/task_newtask")
int BPF_PROG(entry, struct task_struct *task, u64 flags)
{
	struct task_struct *acquired;
	struct map_value *value;

	value = helper_a(task);
	if (!value)
		return 0;

	acquired = bpf_task_acquire(value->task);
	if (!acquired)
		return 0;

	bpf_task_release(acquired);
	return 0;
}
```

Verifier log:
```text
0: R1=ctx() R10=fp0
; int BPF_PROG(entry, struct task_struct *task, u64 clone_flags) @ case.c:32
0: (79) r1 = *(u64 *)(r1 +0)
func 'task_newtask' arg0 has btf_id 104158 type STRUCT 'task_struct'
1: R1=trusted_ptr_task_struct()
; v = helper_a(task); @ case.c:37
1: (85) call pc+8
caller:
 R10=fp0
callee:
 frame1: R1=trusted_ptr_task_struct() R10=fp0
10: frame1: R1=trusted_ptr_task_struct() R10=fp0
; static struct map_value *helper_a(struct task_struct *task) @ case.c:19
10: (bf) r6 = r1                      ; frame1: R1=trusted_ptr_task_struct() R6=trusted_ptr_task_struct()
11: (b7) r1 = 1528                    ; frame1: R1=1528
12: (bf) r3 = r6                      ; frame1: R3=trusted_ptr_task_struct() R6=trusted_ptr_task_struct()
13: (0f) r3 += r1                     ; frame1: R1=1528 R3=trusted_ptr_task_struct(imm=1528)
14: (bf) r1 = r10                     ; frame1: R1=fp0 R10=fp0
15: (07) r1 += -12                    ; frame1: R1=fp-12
; status = bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid); @ case.c:49
16: (b4) w2 = 4                       ; frame1: R2=4
17: (85) call bpf_probe_read_kernel#113       ; frame1: R0=scalar() fp-16=mmmmpppp
18: (bf) r1 = r0                      ; frame1: R1=scalar(id=1)
; if (status) @ case.c:50
19: (55) if r1 != 0x0 goto pc+33      ; frame1: R1=0
20: (b7) r1 = 0                       ; frame1: R1=0
; local.task = NULL; @ case.c:53
21: (7b) *(u64 *)(r10 -8) = r1        ; frame1: R1=0 R10=fp0 fp-8=0
22: (bf) r2 = r10                     ; frame1: R2=fp0 R10=fp0
23: (07) r2 += -12                    ; frame1: R2=fp-12
24: (bf) r3 = r10                     ; frame1: R3=fp0 R10=fp0
25: (07) r3 += -8                     ; frame1: R3=fp-8
; status = bpf_map_update_elem(&map_a, &pid, &local, BPF_NOEXIST); @ case.c:54
26: (18) r1 = 0xffff88810ade1000      ; frame1: R1=map_ptr(map=map_a,ks=4,vs=8)
28: (b7) r4 = 1                       ; frame1: R4=1
29: (85) call bpf_map_update_elem#2   ; frame1: R0=scalar()
30: (bf) r1 = r0                      ; frame1: R1=scalar(id=2)
; if (status) @ case.c:55
31: (55) if r1 != 0x0 goto pc+21      ; frame1: R1=0
32: (bf) r2 = r10                     ; frame1: R2=fp0 R10=fp0
33: (07) r2 += -12                    ; frame1: R2=fp-12
; v = bpf_map_lookup_elem(&map_a, &pid); @ case.c:58
34: (18) r1 = 0xffff88810ade1000      ; frame1: R1=map_ptr(map=map_a,ks=4,vs=8)
36: (85) call bpf_map_lookup_elem#1   ; frame1: R0=map_value_or_null(id=3,map=map_a,ks=4,vs=8)
37: (bf) r7 = r0                      ; frame1: R7=map_value_or_null(id=3,map=map_a,ks=4,vs=8)
; if (!v) { @ case.c:59
38: (55) if r7 != 0x0 goto pc+6 45: frame1: R6=trusted_ptr_task_struct() R7=map_value(id=3,map=map_a,ks=4,vs=8) R10=fp0
; acquired = bpf_task_acquire(task); @ case.c:64
45: (bf) r1 = r6                      ; frame1: R1=trusted_ptr_task_struct() R6=trusted_ptr_task_struct()
46: (85) call bpf_task_acquire#63762          ; frame1: R0=trusted_ptr_or_null_task_struct(id=5) refs=5
; if (!acquired) @ case.c:65
47: (15) if r0 == 0x0 goto pc+25      ; frame1: R0=trusted_ptr_task_struct(id=5) refs=5
; old = bpf_kptr_xchg(&value->task, acquired); @ case.c:68
48: (bf) r1 = r7                      ; frame1: R1=map_value(id=3,map=map_a,ks=4,vs=8) R7=map_value(id=3,map=map_a,ks=4,vs=8) refs=5
49: (bf) r2 = r0                      ; frame1: R0=trusted_ptr_task_struct(id=5) R2=trusted_ptr_task_struct(id=5) refs=5
50: (85) call bpf_kptr_xchg#194       ; frame1: R0=ptr_or_null_task_struct(id=7) refs=7
; if (old) { @ case.c:69
51: (55) if r0 != 0x0 goto pc+19      ; frame1: R0=0
; if (status) @ case.c:24
52: (05) goto pc+2
55: (b7) r1 = 1528                    ; frame1: R1=1528
56: (0f) r6 += r1                     ; frame1: R1=1528 R6=trusted_ptr_task_struct(imm=1528)
57: (bf) r1 = r10                     ; frame1: R1=fp0 R10=fp0
58: (07) r1 += -8                     ; frame1: R1=fp-8
; status = bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid); @ case.c:35
59: (b4) w2 = 4                       ; frame1: R2=4
60: (bf) r3 = r6                      ; frame1: R3=trusted_ptr_task_struct(imm=1528) R6=trusted_ptr_task_struct(imm=1528)
61: (85) call bpf_probe_read_kernel#113       ; frame1: R0=scalar() fp-8=ppppmmmm
62: (bf) r1 = r0                      ; frame1: R0=scalar(id=8) R1=scalar(id=8)
63: (b7) r0 = 0                       ; frame1: R0=0
; if (status) @ case.c:36
64: (55) if r1 != 0x0 goto pc+9       ; frame1: R1=0
65: (bf) r2 = r10                     ; frame1: R2=fp0 R10=fp0
66: (07) r2 += -8                     ; frame1: R2=fp-8
; return bpf_map_lookup_elem(&map_a, &pid); @ case.c:39
67: (18) r1 = 0xffff88810ade1000      ; frame1: R1=map_ptr(map=map_a,ks=4,vs=8)
69: (85) call bpf_map_lookup_elem#1   ; frame1: R0=map_value_or_null(id=9,map=map_a,ks=4,vs=8)
70: (05) goto pc+3
; } @ case.c:28
74: (95) exit
returning from callee:
 frame1: R0=map_value_or_null(id=9,map=map_a,ks=4,vs=8) R10=fp0
to caller at 2:
 R0=map_value_or_null(id=9,map=map_a,ks=4,vs=8) R10=fp0
; if (!v) @ case.c:38
2: (15) if r0 == 0x0 goto pc+5        ; R0=map_value(id=9,map=map_a,ks=4,vs=8)
; acquired = bpf_task_acquire(value->task); @ case.c:42
3: (79) r1 = *(u64 *)(r0 +0)          ; R0=map_value(id=9,map=map_a,ks=4,vs=8) R1=rcu_ptr_or_null_task_struct(id=10)
4: (85) call bpf_task_acquire#63762
Possibly NULL pointer passed to trusted R1
processed 66 insns (limit 1000000) max_states_per_insn 0 total_states 6 peak_states 6 mark_read 0
```
