// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

SEC("tp_btf/bpf_testmod_test_raw_tp_null")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_bpf_testmod_test_raw_tp_null_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/sched_pi_setprio")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_sched_pi_setprio_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/sched_stick_numa")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_sched_stick_numa_arg_3(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +16); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/sched_swap_numa")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_sched_swap_numa_arg_3(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +16); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/afs_make_fs_call")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_afs_make_fs_call_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/afs_make_fs_calli")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_afs_make_fs_calli_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/afs_make_fs_call1")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_afs_make_fs_call1_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/afs_make_fs_call2")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_afs_make_fs_call2_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/afs_protocol_error")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_afs_protocol_error_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/afs_flock_ev")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_afs_flock_ev_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_lookup")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_lookup_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_unlink")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_unlink_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_rename")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_rename_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_prep_read")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_prep_read_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_mark_active")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_mark_active_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_mark_failed")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_mark_failed_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_mark_inactive")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_mark_inactive_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_vfs_error")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_vfs_error_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_io_error")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_io_error_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_ondemand_open")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_ondemand_open_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_ondemand_copen")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_ondemand_copen_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_ondemand_close")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_ondemand_close_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_ondemand_read")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_ondemand_read_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_ondemand_cread")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_ondemand_cread_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_ondemand_fd_write")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_ondemand_fd_write_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_ondemand_fd_release")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_cachefiles_ondemand_fd_release_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/ext4_mballoc_discard")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_ext4_mballoc_discard_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/ext4_mballoc_free")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_ext4_mballoc_free_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/fib_table_lookup")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_fib_table_lookup_arg_3(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +16); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/posix_lock_inode")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_posix_lock_inode_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/fcntl_setlk")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_fcntl_setlk_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/locks_remove_posix")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_locks_remove_posix_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/flock_lock_inode")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_flock_lock_inode_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/break_lease_noblock")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_break_lease_noblock_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/break_lease_block")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_break_lease_block_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/break_lease_unblock")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_break_lease_unblock_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/generic_delete_lease")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_generic_delete_lease_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/time_out_leases")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_time_out_leases_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

/* Disabled due to missing CONFIG
SEC("tp_btf/host1x_cdma_push_gather")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_host1x_cdma_push_gather_arg_5(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +32); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}
*/

SEC("tp_btf/mm_khugepaged_scan_pmd")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_mm_khugepaged_scan_pmd_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/mm_collapse_huge_page_isolate")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_mm_collapse_huge_page_isolate_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/mm_khugepaged_scan_file")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_mm_khugepaged_scan_file_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/mm_khugepaged_collapse_file")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_mm_khugepaged_collapse_file_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/mm_page_alloc")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_mm_page_alloc_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/mm_page_pcpu_drain")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_mm_page_pcpu_drain_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/mm_page_alloc_zone_locked")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_mm_page_alloc_zone_locked_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/netfs_failure")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_netfs_failure_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

/* Disabled due to missing CONFIG
SEC("tp_btf/device_pm_callback_start")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_device_pm_callback_start_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}
*/

SEC("tp_btf/qdisc_dequeue")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_qdisc_dequeue_arg_4(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +24); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/rxrpc_recvdata")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_rxrpc_recvdata_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/rxrpc_resend")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_rxrpc_resend_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/xs_stream_read_data")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_xs_stream_read_data_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/xprt_reserve_cong")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_xprt_reserve_cong_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/xprt_release_cong")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_xprt_release_cong_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/xprt_get_cong")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_xprt_get_cong_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/xprt_put_cong")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_xprt_put_cong_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/tcp_send_reset")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_tcp_send_reset_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/tcp_send_reset")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_tcp_send_reset_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

/* Disabled due to missing CONFIG
SEC("tp_btf/tegra_dma_tx_status")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_tegra_dma_tx_status_arg_3(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +16); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}
*/

SEC("tp_btf/tmigr_update_events")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_tmigr_update_events_arg_1(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +0); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/writeback_dirty_folio")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_writeback_dirty_folio_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/folio_wait_writeback")
__failure __msg("R1 invalid mem access 'trusted_ptr_or_null_'")
int test_raw_tp_null_folio_wait_writeback_arg_2(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +8); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}
