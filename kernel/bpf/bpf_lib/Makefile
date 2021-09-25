# SPDX-License-Identifier: GPL-2.0
OUTPUT := build
CLANG ?= clang
LLC ?= llc
LLVM_STRIP ?= llvm-strip
DEFAULT_BPFTOOL := $(OUTPUT)/sbin/bpftool
BPFTOOL ?= $(DEFAULT_BPFTOOL)
INCLUDES := -I$(OUTPUT) -I$(abspath ../../../tools/lib/bpf) 		\
	    -I$(abspath ../../../tools/include/uapi)
CFLAGS := -g -Wall

abs_out := $(abspath $(OUTPUT))
ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory
submake_extras := feature_display=0
endif

VMLINUX_BTF_PATHS ?= $(if $(O),$(O)/vmlinux)				\
		     $(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT)/vmlinux)	\
		     ../../../../vmlinux
VMLINUX_BTF ?= $(abspath $(firstword $(wildcard $(VMLINUX_BTF_PATHS))))

ifeq ($(VMLINUX_BTF),)
$(error Cannot find a vmlinux for VMLINUX_BTF at any of "$(VMLINUX_BTF_PATHS)")
endif

.DELETE_ON_ERROR:

.PHONY: all clean

all: foo.bpf.o bar.bpf.o

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf *.bpf.o $(OUTPUT)

$(OUTPUT)/vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL)
ifeq ($(VMLINUX_H),)
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@
else
	$(Q)cp "$(VMLINUX_H)" $@
endif

%.bpf.o: %.bpf.c $(OUTPUT)/vmlinux.h
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf $(INCLUDES)			      \
		 -c $(filter %.c,$^) -o $@ &&				      \
	$(LLVM_STRIP) -g $@

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $(OUTPUT)

$(DEFAULT_BPFTOOL): $(OUTPUT)
	$(Q)$(MAKE) $(submake_extras) -C ../../../tools/bpf/bpftool	      \
		    prefix= OUTPUT=$(abs_out)/ DESTDIR=$(abs_out) install

obj-$(CONFIG_BPF_ITER_LIB) += foo.bpf.o
obj-$(CONFIG_BPF_ITER_LIB) += bar.bpf.o
