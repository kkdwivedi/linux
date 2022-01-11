===================================
Running BPF programs from userspace
===================================

This document describes the ``BPF_PROG_RUN`` facility for running BPF programs
from userspace.

.. contents::
    :local:
    :depth: 2


Overview
--------

The ``BPF_PROG_RUN`` command can be used through the ``bpf()`` syscall to
execute a BPF program in the kernel and return the results to userspace. This
can be used to unit test BPF programs against user-supplied context objects, and
as way to explicitly execute programs in the kernel for their side effects. The
command was previously named ``BPF_PROG_TEST_RUN``, and both constants continue
to be defined in the UAPI header, aliased to the same value.

The ``BPF_PROG_RUN`` command can be used to execute BPF programs of the
following types:

- ``BPF_PROG_TYPE_SOCKET_FILTER``
- ``BPF_PROG_TYPE_SCHED_CLS``
- ``BPF_PROG_TYPE_SCHED_ACT``
- ``BPF_PROG_TYPE_XDP``
- ``BPF_PROG_TYPE_SK_LOOKUP``
- ``BPF_PROG_TYPE_CGROUP_SKB``
- ``BPF_PROG_TYPE_LWT_IN``
- ``BPF_PROG_TYPE_LWT_OUT``
- ``BPF_PROG_TYPE_LWT_XMIT``
- ``BPF_PROG_TYPE_LWT_SEG6LOCAL``
- ``BPF_PROG_TYPE_FLOW_DISSECTOR``
- ``BPF_PROG_TYPE_TRACING``
- ``BPF_PROG_TYPE_STRUCT_OPS``
- ``BPF_PROG_TYPE_RAW_TRACEPOINT``
- ``BPF_PROG_TYPE_SYSCALL``

  
