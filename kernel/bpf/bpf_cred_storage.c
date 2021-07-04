// SPDX-License-Identifier: GPL-2.0

#include <linux/cred.h>
#include <linux/rculist.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/spinlock.h>
#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <uapi/linux/btf.h>
#include <linux/bpf_lsm.h>
#include <linux/btf_ids.h>

DEFINE_BPF_STORAGE_CACHE(cred_cache);

static struct cred *get_cred_from_value(int pidfd)
{
	struct task_struct *task;
	const struct cred *cred;
	unsigned int f_flags;
	struct pid *pid;

	/* TODO(kkd): Make key type tagged, so that pidfd, io_uring personality
	 * etc. can be chosen in the future in backwards compatible fashion
	 *
	 * Move this code into common helper
	 */
	pid = pidfd_get_pid(pidfd, &f_flags);
	if (IS_ERR(pid))
		return ERR_CAST(pid);
	task = get_pid_task(pid, PIDTYPE_TGID);
	put_pid(pid);
	if (!task)
		return ERR_PTR(-ESRCH);
	rcu_read_lock();
	cred = get_cred_rcu(rcu_dereference(task->cred));
	rcu_read_unlock();
	put_task_struct(task);
	if (!cred)
		return ERR_PTR(-ENOENT);
	return (struct cred *)cred;
}

static struct bpf_local_storage __rcu **cred_storage_ptr(void *owner)
{
	struct bpf_storage_blob *bsb;
	struct cred *cred = owner;

	bsb = bpf_cred(cred);
	if (!bsb)
		return NULL;
	return &bsb->storage;
}

static struct bpf_local_storage_data *
cred_storage_lookup(struct cred *cred, struct bpf_map *map, bool cacheit_lockit)
{
	struct bpf_local_storage *cred_storage;
	struct bpf_local_storage_map *smap;
	struct bpf_storage_blob *bsb;

	bsb = bpf_cred(cred);
	if (!bsb)
		return NULL;

	cred_storage = rcu_dereference(bsb->storage);
	if (!cred_storage)
		return NULL;

	smap = (struct bpf_local_storage_map *)map;
	return bpf_local_storage_lookup(cred_storage, smap, cacheit_lockit);
}

void bpf_cred_storage_free(struct cred *cred)
{
	struct bpf_local_storage *local_storage;
	struct bpf_local_storage_elem *selem;
	bool free_cred_storage = false;
	struct bpf_storage_blob *bsb;
	struct hlist_node *n;

	bsb = bpf_cred(cred);
	if (!bsb)
		return;

	rcu_read_lock();

	local_storage = rcu_dereference(bsb->storage);
	if (!local_storage) {
		rcu_read_unlock();
		return;
	}

	/* Neither the bpf_prog nor the bpf-map's syscall
	 * could be modifying the local_storage->list now.
	 * Thus, no elem can be added-to or deleted-from the
	 * local_storage->list by the bpf_prog or by the bpf-map's syscall.
	 *
	 * It is racing with bpf_local_storage_map_free() alone
	 * when unlinking elem from the local_storage->list and
	 * the map's bucket->list.
	 */
	raw_spin_lock_bh(&local_storage->lock);
	hlist_for_each_entry_safe(selem, n, &local_storage->list, snode) {
		/* Always unlink from map before unlinking from
		 * local_storage.
		 */
		bpf_selem_unlink_map(selem);
		free_cred_storage = bpf_selem_unlink_storage_nolock(local_storage,
								    selem, false);
	}
	raw_spin_unlock_bh(&local_storage->lock);
	rcu_read_unlock();

	/* free_cred_storage should always be true as long as
	 * local_storage->list was non-empty.
	 */
	if (free_cred_storage)
		kfree_rcu(local_storage, rcu);
}

static void *bpf_cred_storage_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_local_storage_data *sdata;
	struct cred *cred;
	int fd;

	fd = *(int *)key;
	cred = get_cred_from_value(fd);
	if (IS_ERR(cred))
		return ERR_CAST(cred);
	sdata = cred_storage_lookup(cred, map, true);
	put_cred(cred);
	return sdata ? sdata->data : NULL;
}

static int bpf_cred_storage_update_elem(struct bpf_map *map, void *key,
					   void *value, u64 map_flags)
{
	struct bpf_local_storage_data *sdata;
	struct cred *cred;
	int fd;

	/* TODO(kkd): Make key type tagged, so that pidfd, io_uring personality
	 * etc. can be chosen in the future in backwards compatible fashion
	 *
	 * Move this code into common helper
	 */
	fd = *(int *)key;
	cred = get_cred_from_value(fd);
	if (IS_ERR(cred))
		return PTR_ERR(cred);
	if (!cred_storage_ptr(cred)) {
		put_cred(cred);
		return -EBADF;
	}
	sdata = bpf_local_storage_update((struct cred *)cred,
					 (struct bpf_local_storage_map *)map,
					 value, map_flags);
	put_cred(cred);
	return PTR_ERR_OR_ZERO(sdata);
}

static int cred_storage_delete(struct cred *cred, struct bpf_map *map)
{
	struct bpf_local_storage_data *sdata;

	sdata = cred_storage_lookup(cred, map, false);
	if (!sdata)
		return -ENOENT;

	bpf_selem_unlink(SELEM(sdata));
	return 0;
}

static int bpf_cred_storage_delete_elem(struct bpf_map *map, void *key)
{
	struct cred *cred;
	int fd, err;

	fd = *(int *)key;
	cred = get_cred_from_value(fd);
	if (IS_ERR(cred))
		return PTR_ERR(cred);
	err = cred_storage_delete(cred, map);
	put_cred(cred);
	return err;
}

BPF_CALL_4(bpf_cred_storage_get, struct bpf_map *, map, struct cred *, cred,
	   void *, value, u64, flags)
{
	struct bpf_local_storage_data *sdata;

	if (flags & ~(BPF_LOCAL_STORAGE_GET_F_CREATE))
		return (unsigned long)NULL;

	/* explicitly check that the cred_storage_ptr is not
	 * NULL as cred_storage_lookup returns NULL in this case and
	 * bpf_local_storage_update expects the owner to have a
	 * valid storage pointer.
	 */
	if (!cred || !cred_storage_ptr(cred))
		return (unsigned long)NULL;

	sdata = cred_storage_lookup(cred, map, true);
	if (sdata)
		return (unsigned long)sdata->data;

	/* Use rcu_dereference for data dependency ordering not expressed in BPF program */
	if (!get_cred_rcu(rcu_dereference(cred)))
		return (unsigned long)NULL;
	/* This helper must only called from where the cred is guaranteed
	 * to have a refcount and cannot be freed.
	 */
	if (flags & BPF_LOCAL_STORAGE_GET_F_CREATE) {
		sdata = bpf_local_storage_update(
			cred, (struct bpf_local_storage_map *)map, value,
			BPF_NOEXIST);
		put_cred(cred);
		return IS_ERR(sdata) ? (unsigned long)NULL :
					     (unsigned long)sdata->data;
	}

	put_cred(cred);
	return (unsigned long)NULL;
}

BPF_CALL_2(bpf_cred_storage_delete, struct bpf_map *, map, struct cred *, cred)
{
	int ret;

	if (!cred)
		return -EINVAL;
	/* Use rcu_dereference for data dependency ordering not expressed in BPF program */
	if (!get_cred_rcu(rcu_dereference(cred)))
		return -ENOENT;
	/* This helper must only called from where the cred is guaranteed
	 * to have a refcount and cannot be freed.
	 */
	ret = cred_storage_delete(cred, map);
	put_cred(cred);
	return ret;
}

static int notsupp_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return -ENOTSUPP;
}

static struct bpf_map *cred_storage_map_alloc(union bpf_attr *attr)
{
	struct bpf_local_storage_map *smap;

	smap = bpf_local_storage_map_alloc(attr);
	if (IS_ERR(smap))
		return ERR_CAST(smap);

	smap->cache_idx = bpf_local_storage_cache_idx_get(&cred_cache);
	return &smap->map;
}

static void cred_storage_map_free(struct bpf_map *map)
{
	struct bpf_local_storage_map *smap;

	smap = (struct bpf_local_storage_map *)map;
	bpf_local_storage_cache_idx_free(&cred_cache, smap->cache_idx);
	bpf_local_storage_map_free(smap, NULL);
}

static int cred_storage_map_btf_id;

const struct bpf_map_ops cred_storage_map_ops = {
	.map_meta_equal        = bpf_map_meta_equal,
	.map_alloc_check       = bpf_local_storage_map_alloc_check,
	.map_alloc             = cred_storage_map_alloc,
	.map_free              = cred_storage_map_free,
	.map_get_next_key      = notsupp_get_next_key,
	.map_lookup_elem       = bpf_cred_storage_lookup_elem,
	.map_update_elem       = bpf_cred_storage_update_elem,
	.map_delete_elem       = bpf_cred_storage_delete_elem,
	.map_check_btf         = bpf_local_storage_map_check_btf,
	.map_btf_name          = "bpf_local_storage_map",
	.map_btf_id            = &cred_storage_map_btf_id,
	.map_owner_storage_ptr = cred_storage_ptr,
};

BTF_ID_LIST_SINGLE(bpf_cred_storage_btf_ids, struct, cred)

const struct bpf_func_proto bpf_cred_storage_get_proto = {
	.func        = bpf_cred_storage_get,
	.gpl_only    = false,
	.ret_type    = RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type   = ARG_CONST_MAP_PTR,
	.arg2_type   = ARG_PTR_TO_BTF_ID,
	.arg2_btf_id = &bpf_cred_storage_btf_ids[0],
	.arg3_type   = ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type   = ARG_ANYTHING,
};

const struct bpf_func_proto bpf_cred_storage_delete_proto = {
	.func        = bpf_cred_storage_delete,
	.gpl_only    = false,
	.ret_type    = RET_INTEGER,
	.arg1_type   = ARG_CONST_MAP_PTR,
	.arg2_type   = ARG_PTR_TO_BTF_ID,
	.arg2_btf_id = &bpf_cred_storage_btf_ids[0],
};
