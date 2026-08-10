#define ARENA_CAST_BTF_TYPES \
	.btf_strings = "\0int\0value\0arena_obj\0other_obj\0", \
	.btf_types = { \
	/* 1: int */ \
	BTF_TYPE_INT_ENC(1, BTF_INT_SIGNED, 0, 32, 4), \
	/* 2: struct arena_obj { int value; } */ \
	BTF_STRUCT_ENC(11, 1, 4), \
	BTF_MEMBER_ENC(5, 1, 0), \
	/* 3: struct other_obj { int value; } */ \
	BTF_STRUCT_ENC(21, 1, 4), \
	BTF_MEMBER_ENC(5, 1, 0), \
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
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 3),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.unexpected_insns = { ARENA_TYPE_CAST_INSN(BPF_REG_0, 2) },
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
	.result = ACCEPT,
	ARENA_CAST_BTF_TYPES
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
	.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
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
	.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
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
	.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
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
	.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
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
	.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
	.result = REJECT,
	.errstr = "arena_type_cast requires dst == src",
	ARENA_CAST_BTF_TYPES
},
{
	"arena type cast: reject access before typed lowering",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	ADDR_SPACE_CAST_INSN(BPF_REG_0),
	ARENA_TYPE_CAST_INSN(BPF_REG_0, 2),
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_0, 0),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_arena = { 1 },
	.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
	.result = REJECT,
	.errstr = "typed arena access is not supported yet",
	ARENA_CAST_BTF_TYPES
},

#undef ARENA_TYPE_CAST_INSN
#undef ADDR_SPACE_CAST_INSN
#undef ARENA_CAST_BTF_TYPES
