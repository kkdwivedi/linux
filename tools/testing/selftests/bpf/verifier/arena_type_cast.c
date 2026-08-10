#define ARENA_CAST_BTF_TYPES \
	.func_info = { { 0, 7 } }, \
	.func_info_cnt = 1, \
	.btf_strings = "\0int\0value\0arena_obj\0other_obj\0empty_obj\0ctx\0main\0", \
	.btf_types = { \
	/* 1: int */ \
	BTF_TYPE_INT_ENC(1, BTF_INT_SIGNED, 0, 32, 4), \
	/* 2: struct arena_obj { int value; } */ \
	BTF_STRUCT_ENC(11, 1, 4), \
	BTF_MEMBER_ENC(5, 1, 0), \
	/* 3: struct other_obj { int value; } */ \
	BTF_STRUCT_ENC(21, 1, 4), \
	BTF_MEMBER_ENC(5, 1, 0), \
	/* 4: struct empty_obj {}; */ \
	BTF_STRUCT_ENC(31, 0, 0), \
	/* 5: void * */ \
	BTF_PTR_ENC(0), \
	/* 6: int (void *) */ \
	BTF_FUNC_PROTO_ENC(1, 1), \
	BTF_FUNC_PROTO_ARG_ENC(41, 5), \
	/* 7: main */ \
	BTF_FUNC_ENC(45, 6), \
	BTF_END_RAW \
	}

#define ARENA_SPIN_LOCK_BTF_TYPES \
	.func_info = { { 0, 6 } }, \
	.func_info_cnt = 1, \
	.btf_strings = "\0bpf_spin_lock\0lock_obj\0lock\0int\0ctx\0main\0", \
	.btf_types = { \
	/* 1: struct bpf_spin_lock */ \
	BTF_STRUCT_ENC(1, 0, 4), \
	/* 2: struct lock_obj { struct bpf_spin_lock lock; } */ \
	BTF_STRUCT_ENC(15, 1, 4), \
	BTF_MEMBER_ENC(24, 1, 0), \
	/* 3: int */ \
	BTF_TYPE_INT_ENC(29, BTF_INT_SIGNED, 0, 32, 4), \
	/* 4: void * */ \
	BTF_PTR_ENC(0), \
	/* 5: int (void *) */ \
	BTF_FUNC_PROTO_ENC(3, 1), \
	BTF_FUNC_PROTO_ARG_ENC(33, 4), \
	/* 6: main */ \
	BTF_FUNC_ENC(37, 5), \
	BTF_END_RAW \
	}

#define ARENA_TIMER_BTF_TYPES \
	.func_info = { { 0, 6 } }, \
	.func_info_cnt = 1, \
	.btf_strings = "\0bpf_timer\0timer_obj\0timer\0int\0ctx\0main\0", \
	.btf_types = { \
	/* 1: struct bpf_timer */ \
	BTF_STRUCT_ENC(1, 0, sizeof(struct bpf_timer)), \
	/* 2: struct timer_obj { struct bpf_timer timer; } */ \
	BTF_STRUCT_ENC(11, 1, sizeof(struct bpf_timer)), \
	BTF_MEMBER_ENC(21, 1, 0), \
	/* 3: int */ \
	BTF_TYPE_INT_ENC(27, BTF_INT_SIGNED, 0, 32, 4), \
	/* 4: void * */ \
	BTF_PTR_ENC(0), \
	/* 5: int (void *) */ \
	BTF_FUNC_PROTO_ENC(3, 1), \
	BTF_FUNC_PROTO_ARG_ENC(31, 4), \
	/* 6: main */ \
	BTF_FUNC_ENC(35, 5), \
	BTF_END_RAW \
	}

#define ADDR_SPACE_CAST_INSN(REG) \
	BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X, REG, REG, \
		     BPF_ADDR_SPACE_CAST, 1)

#define ARENA_TYPE_CAST_INSN(REG, BTF_ID) \
	BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X, REG, REG, \
		     BPF_ARENA_TYPE_CAST, BTF_ID)

{
	"arena type cast: annotate and reannotate",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	ADDR_SPACE_CAST_INSN(BPF_REG_0),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 2),
	BPF_ST_MEM(BPF_W, BPF_REG_0, 0, 42),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 3),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.unexpected_insns = { ARENA_TYPE_CAST_INSN(BPF_REG_0, 2) },
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = VERBOSE_ACCEPT,
	.errstr = "arena type ID 2: size=4 slot_size=4\t"
		  "arena type ID 3: size=4 slot_size=4",
	ARENA_CAST_BTF_TYPES
},
{
	"arena type cast: collect supported special fields",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	ADDR_SPACE_CAST_INSN(BPF_REG_0),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = VERBOSE_ACCEPT,
	.errstr = "arena type ID 2: size=4 slot_size=4",
	ARENA_SPIN_LOCK_BTF_TYPES
},
{
	"arena type cast: reject zero-sized declaration",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	ADDR_SPACE_CAST_INSN(BPF_REG_0),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 4),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "arena type ID 4 has zero size",
	ARENA_CAST_BTF_TYPES
},
{
	"arena type cast: reject unsupported special fields",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	ADDR_SPACE_CAST_INSN(BPF_REG_0),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "arena type ID 2 field bpf_timer is not supported",
	ARENA_TIMER_BTF_TYPES
},
{
	"arena type cast: reject scalar input",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "expected arena or typed arena pointer",
	ARENA_CAST_BTF_TYPES
},
{
	"arena type cast: reject non-struct BTF ID",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	ADDR_SPACE_CAST_INSN(BPF_REG_0),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "arena_type_cast type ID 1 is not a struct",
	ARENA_CAST_BTF_TYPES
},
{
	"arena type cast: reject missing program BTF",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	ADDR_SPACE_CAST_INSN(BPF_REG_0),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "arena_type_cast insn requires program BTF",
},
{
	"arena type cast: reject missing arena",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "special arena cast insn requires an associated arena",
	ARENA_CAST_BTF_TYPES
},
{
	"arena type cast: reject different registers",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	ADDR_SPACE_CAST_INSN(BPF_REG_0),
	BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_0,
		     BPF_ARENA_TYPE_CAST, 2),
	BPF_EXIT_INSN(),
	},
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "arena_type_cast requires dst == src",
	ARENA_CAST_BTF_TYPES
},
{
	"arena type cast: scalar and atomic access",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 4095),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	ADDR_SPACE_CAST_INSN(BPF_REG_0),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 2),
	BPF_ST_MEM(BPF_W, BPF_REG_0, 0, 41),
	BPF_MOV64_IMM(BPF_REG_1, 1),
	BPF_ATOMIC_OP(BPF_W, BPF_ADD, BPF_REG_0, BPF_REG_1, 0),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	.retval = 42,
	ARENA_CAST_BTF_TYPES
},
{
	"arena type cast: reject out-of-object access",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	ADDR_SPACE_CAST_INSN(BPF_REG_0),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 2),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0, 4),
	BPF_EXIT_INSN(),
	},
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "access beyond struct arena_obj at off 4 size 4",
	ARENA_CAST_BTF_TYPES
},
{
	"arena type cast: reject typed pointer store",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	ADDR_SPACE_CAST_INSN(BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_0),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 2),
	BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "R0 leaks typed arena addr into mem",
	ARENA_CAST_BTF_TYPES
},
{
	"arena type cast: reject direct special-field access",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	ADDR_SPACE_CAST_INSN(BPF_REG_0),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 2),
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = REJECT,
	.errstr = "direct access to bpf_spin_lock is disallowed",
	ARENA_SPIN_LOCK_BTF_TYPES
},
{
	"arena type cast: use spin lock",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	ADDR_SPACE_CAST_INSN(BPF_REG_0),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 2),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
	BPF_EMIT_CALL(BPF_FUNC_spin_lock),
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
	BPF_EMIT_CALL(BPF_FUNC_spin_unlock),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	.result = ACCEPT,
	ARENA_SPIN_LOCK_BTF_TYPES
},

#undef ARENA_TYPE_CAST_INSN
#undef ADDR_SPACE_CAST_INSN
#undef ARENA_TIMER_BTF_TYPES
#undef ARENA_SPIN_LOCK_BTF_TYPES
#undef ARENA_CAST_BTF_TYPES
