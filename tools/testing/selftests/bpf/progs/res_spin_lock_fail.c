// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#define ARENA_SKIP_KFUNC
#include "bpf_arena_common.h"

struct arr_elem {
	struct bpf_res_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct arr_elem);
} arrmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 10); /* number of pages */
} arena SEC(".maps");

long value;

struct bpf_spin_lock lock __hidden SEC(".data.A");
struct bpf_res_spin_lock res_lock __hidden SEC(".data.B");

SEC("?tc")
__failure __msg("point to map value or allocated object")
int res_spin_lock_arg(struct __sk_buff *ctx)
{
	struct arr_elem *elem;

	elem = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem)
		return 0;
	bpf_res_spin_lock((struct bpf_res_spin_lock *)bpf_core_cast(&elem->lock, struct __sk_buff));
	bpf_res_spin_lock(&elem->lock);
	return 0;
}

SEC("tc")
__failure __msg("AA deadlock detected")
int res_spin_lock_AA(struct __sk_buff *ctx)
{
	struct arr_elem *elem;

	elem = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem)
		return 0;
	bpf_res_spin_lock(&elem->lock);
	bpf_res_spin_lock(&elem->lock);
	return 0;
}

SEC("?tc")
__failure __msg("AA deadlock detected")
int res_spin_lock_cond_AA(struct __sk_buff *ctx)
{
	struct arr_elem *elem;

	elem = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem)
		return 0;
	if (bpf_res_spin_lock(&elem->lock))
		return 0;
	bpf_res_spin_lock(&elem->lock);
	return 0;
}

SEC("?tc")
__failure __msg("unlock of different lock")
int res_spin_lock_mismatch_1(struct __sk_buff *ctx)
{
	struct arr_elem *elem;

	elem = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem)
		return 0;
	if (bpf_res_spin_lock(&elem->lock))
		return 0;
	bpf_res_spin_unlock(&res_lock);
	return 0;
}

SEC("?tc")
__failure __msg("unlock of different lock")
int res_spin_lock_mismatch_2(struct __sk_buff *ctx)
{
	struct arr_elem *elem;

	elem = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem)
		return 0;
	if (bpf_res_spin_lock(&res_lock))
		return 0;
	bpf_res_spin_unlock(&elem->lock);
	return 0;
}

SEC("?tc")
__failure __msg("unlock of different lock")
int res_spin_lock_irq_mismatch_1(struct __sk_buff *ctx)
{
	struct arr_elem *elem;
	unsigned long f1;

	elem = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem)
		return 0;
	bpf_local_irq_save(&f1);
	if (bpf_res_spin_lock(&res_lock))
		return 0;
	bpf_res_spin_unlock_irqrestore(&res_lock, &f1);
	return 0;
}

SEC("?tc")
__failure __msg("unlock of different lock")
int res_spin_lock_irq_mismatch_2(struct __sk_buff *ctx)
{
	struct arr_elem *elem;
	unsigned long f1;

	elem = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem)
		return 0;
	if (bpf_res_spin_lock_irqsave(&res_lock, &f1))
		return 0;
	bpf_res_spin_unlock(&res_lock);
	return 0;
}

SEC("?tc")
__success
int res_spin_lock_ooo(struct __sk_buff *ctx)
{
	struct arr_elem *elem;

	elem = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem)
		return 0;
	if (bpf_res_spin_lock(&res_lock))
		return 0;
	if (bpf_res_spin_lock(&elem->lock)) {
		bpf_res_spin_unlock(&res_lock);
		return 0;
	}
	bpf_res_spin_unlock(&elem->lock);
	bpf_res_spin_unlock(&res_lock);
	return 0;
}

SEC("?tc")
__success
int res_spin_lock_ooo_irq(struct __sk_buff *ctx)
{
	struct arr_elem *elem;
	unsigned long f1, f2;

	elem = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem)
		return 0;
	if (bpf_res_spin_lock_irqsave(&res_lock, &f1))
		return 0;
	if (bpf_res_spin_lock_irqsave(&elem->lock, &f2)) {
		bpf_res_spin_unlock_irqrestore(&res_lock, &f1);
		/* We won't have a unreleased IRQ flag error here. */
		return 0;
	}
	bpf_res_spin_unlock_irqrestore(&elem->lock, &f2);
	bpf_res_spin_unlock_irqrestore(&res_lock, &f1);
	return 0;
}

SEC("?tc")
__failure __msg("off 1 doesn't point to 'struct bpf_res_spin_lock' that is at 0")
int res_spin_lock_bad_off(struct __sk_buff *ctx)
{
	struct arr_elem *elem;

	elem = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem)
		return 0;
	bpf_res_spin_lock((void *)&elem->lock + 1);
	return 0;
}

SEC("?tc")
__failure __msg("R1 doesn't have constant offset. bpf_res_spin_lock has to be at the constant offset")
int res_spin_lock_var_off(struct __sk_buff *ctx)
{
	struct arr_elem *elem;
	u64 val = value;

	elem = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem) {
		// FIXME: Only inline assembly use in assert macro doesn't emit
		//	  BTF definition.
		bpf_throw(0);
		return 0;
	}
	bpf_assert_range(val, 0, 40);
	bpf_res_spin_lock((void *)&value + val);
	return 0;
}

SEC("?tc")
__failure __msg("map 'res_spin.bss' has no valid bpf_res_spin_lock")
int res_spin_lock_no_lock_map(struct __sk_buff *ctx)
{
	bpf_res_spin_lock((void *)&value + 1);
	return 0;
}

SEC("?tc")
__failure __msg("local 'kptr' has no valid bpf_res_spin_lock")
int res_spin_lock_no_lock_kptr(struct __sk_buff *ctx)
{
	struct { int i; } *p = bpf_obj_new(typeof(*p));

	if (!p)
		return 0;
	bpf_res_spin_lock((void *)p);
	return 0;
}

typedef u32 arena_idx_t;

static inline lock_result_t *bpf_res_spin_lock_arena(arena_idx_t lock)
{
	void __arena *ptr = (void __arena*)(u64)lock;
	return bpf_res_spin_lock((struct bpf_res_spin_lock *)ptr);
}

static inline void bpf_res_spin_unlock_arena(arena_idx_t lock)
{
	void __arena *ptr = (void __arena*)(u64)lock;
	bpf_res_spin_unlock((struct bpf_res_spin_lock *)ptr);
}

void *ptr;

SEC("?tc")
__success
int res_spin_lock_arena_no_cond_AA(struct __sk_buff *ctx)
{
	ptr = &arena;
	if (bpf_res_spin_lock_arena(0))
		return 0;
	if (bpf_res_spin_lock_arena(0)) {
		bpf_res_spin_unlock_arena(0);
		return 0;
	}
	bpf_res_spin_unlock_arena(0);
	bpf_res_spin_unlock_arena(0);
	return 0;
}

SEC("?tc")
__failure __msg("bpf_res_spin_unlock of different lock")
int res_spin_lock_mismatch(struct __sk_buff *ctx)
{
	struct arr_elem *elem;

	/* FIXME: Make verifier happy */
	ptr = &arena;
	elem = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem)
		return 0;
	if (ctx->mark) {
		bpf_res_spin_lock(&elem->lock);
		bpf_res_spin_unlock(&elem->lock);
	} else {
		bpf_res_spin_lock_arena(0);
		bpf_res_spin_unlock_arena(0);
	}
	return 0;
}

SEC("?tc")
__failure __msg("cannot pass arena and non-arena pointer at same insn_idx=13")
int res_spin_lock_collision(struct __sk_buff *ctx)
{
	/* We encode bpf_addr_space_cast(r0, 0, 1) by hand... */
	asm volatile ("					\
	r1 = %[arena] ll;				\
	r0 = 0;						\
	*(u32*)(r10 - 4) = r0;				\
	r2 = r10;					\
	r2 += -4;					\
	r1 = %[arrmap] ll;				\
	call %[bpf_map_lookup_elem];			\
	if r0 != 0 goto l0_%=;				\
	.byte 0xBF; .byte 0x00; .short %[off]; .long %[as]; \
l0_%=:	r6 = r0;					\
	r1 = r6;					\
	call bpf_res_spin_lock;				\
	if r0 != 0 goto l1_%=;				\
	r1 = r6;					\
	call bpf_res_spin_unlock;			\
l1_%=:							\
"	:
	: __imm_addr(arena),
	  __imm(bpf_map_lookup_elem),
	  __imm(bpf_spin_lock),
	  __imm(bpf_spin_unlock),
	  __imm_addr(arrmap),
	  [off]"i"(BPF_ADDR_SPACE_CAST),
	  [as]"i"(1)
	: __clobber_all);
	return 0;
}

char _license[] SEC("license") = "GPL";
