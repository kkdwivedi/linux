// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <linux/magic.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "bench_memcg_reclaim.skel.h"

#define LATENCY_BUCKETS 64
#define MAX_MODES 6
#define MAX_WORKERS 4
#define MAX_BATCH_THREADS 16
#define MISSING UINT64_MAX
#define NS_PER_SEC 1000000000ULL
#define NS_PER_MSEC 1000000ULL
#define DEFAULT_EPOCH_NS (200ULL * NS_PER_MSEC)

enum bench_mode {
	MODE_KERNEL,
	MODE_MEMORY_LOW,
	MODE_USERSPACE,
	MODE_BPF_FIXED_ONE,
	MODE_BPF,
	MODE_BPF_FIXED_MAX,
};

enum phase {
	PHASE_IDLE,
	PHASE_STEADY,
	PHASE_BURST,
	PHASE_RECOVERY,
};

struct config {
	char output[PATH_MAX];
	char work_dir[PATH_MAX];
	char service_file[PATH_MAX];
	char batch_file[PATH_MAX];
	bool keep_files;
	bool reuse_batch_file;
	bool verbose;
	bool memcached;
	int repeat;
	int pool_size;
	int service_threads;
	int batch_threads;
	int memcached_port;
	int memcached_threads;
	int memtier_threads;
	int memtier_clients;
	double duration_scale;
	char memcached_binary[PATH_MAX];
	char memtier_binary[PATH_MAX];
	uint64_t page_size;
	uint64_t host_memory;
	uint64_t parent_max;
	uint64_t parent_high;
	uint64_t parent_target;
	uint64_t service_file_size;
	uint64_t service_hot_size;
	uint64_t batch_file_size;
	uint64_t epoch_ns;
	uint64_t quantum_pages;
	uint64_t max_pending_pages;
	uint64_t minimum_capacity_pages;
	uint64_t refault_budget;
	uint32_t refault_gain;
	uint32_t recovery_epochs;
	uint32_t scalein_epochs;
	uint64_t service_rate;
	uint64_t memcached_memory;
	uint64_t memcached_data_size;
	uint64_t memcached_value_size;
	uint64_t memcached_key_count;
	uint64_t memtier_rate;
	uint64_t phase_ns[4];
	uint64_t batch_rate[4];
	enum bench_mode modes[MAX_MODES];
	int mode_count;
};

struct cgroup_paths {
	char parent[PATH_MAX];
	char service[PATH_MAX];
	char batch[PATH_MAX];
	char loadgen[PATH_MAX];
};

struct shared_state {
	uint32_t start;
	uint32_t stop;
	uint32_t service_ready;
	uint32_t batch_ready;
	uint32_t controller_ready;
	uint64_t start_ns;
	uint64_t slo_ns;
	uint64_t service_ops;
	uint64_t service_slo_violations;
	uint64_t service_max_ns;
	uint64_t service_epoch_max_ns;
	uint64_t service_hist[LATENCY_BUCKETS];
	uint64_t batch_pages;
	uint64_t authorized_pages;
	uint64_t pending_pages;
	uint64_t requested_pages;
	uint64_t failed_pages;
	uint64_t first_reclaim_ns;
	uint64_t controller_epochs;
	uint64_t controller_cpu_ns;
	uint64_t worker_wakeups;
	uint64_t worker_sleeps;
	uint64_t claim_conflicts;
	uint32_t active_workers;
	uint32_t peak_active_workers;
	uint32_t desired_workers;
	uint32_t peak_desired_workers;
};

struct cg_metrics {
	uint64_t memory_current;
	uint64_t high;
	uint64_t max;
	uint64_t oom;
	uint64_t oom_kill;
	uint64_t refault_file;
	uint64_t pgscan;
	uint64_t pgsteal;
	uint64_t pgscan_direct;
	uint64_t pgsteal_direct;
	uint64_t psi_some;
	uint64_t psi_full;
	uint64_t cpu_usage;
	uint64_t cpu_user;
	uint64_t cpu_system;
	uint64_t nr_throttled;
	uint64_t throttled_usec;
};

struct vm_metrics {
	uint64_t pgscan_kswapd;
	uint64_t pgsteal_kswapd;
	uint64_t pgscan_direct;
	uint64_t pgsteal_direct;
};

struct controller_metrics {
	uint64_t authorized;
	uint64_t pending;
	uint64_t requested;
	uint64_t reclaimed;
	uint64_t failed;
	uint64_t epochs;
	uint64_t cpu_ns;
	uint64_t wakeups;
	uint64_t sleeps;
	uint64_t conflicts;
	uint64_t first_reclaim_ns;
	uint32_t active;
	uint32_t peak_active;
	uint32_t desired;
	uint32_t peak_desired;
	uint32_t pool_started;
	uint32_t pool_stopped;
};

struct trial_result {
	enum bench_mode mode;
	int repetition;
	uint64_t calibration_p99_ns;
	uint64_t slo_ns;
	uint64_t service_ops;
	uint64_t service_p99_ns;
	uint64_t service_max_ns;
	uint64_t slo_epochs;
	uint64_t batch_pages;
	uint64_t high_events;
	uint64_t oom_kills;
	uint64_t service_refaults;
	uint64_t direct_scans;
	uint64_t kswapd_scans;
	uint64_t batch_cpu_usec;
	struct controller_metrics controller;
	bool inconclusive;
	char warning[256];
};

struct child_proc {
	pid_t pid;
	int release_fd;
};

static volatile sig_atomic_t interrupted;
static struct shared_state *signal_shared;

static uint64_t load_u64(const uint64_t *ptr)
{
	return __atomic_load_n(ptr, __ATOMIC_RELAXED);
}

static uint32_t load_u32(const uint32_t *ptr)
{
	return __atomic_load_n(ptr, __ATOMIC_ACQUIRE);
}

static void store_u64(uint64_t *ptr, uint64_t value)
{
	__atomic_store_n(ptr, value, __ATOMIC_RELAXED);
}

static void store_u32(uint32_t *ptr, uint32_t value)
{
	__atomic_store_n(ptr, value, __ATOMIC_RELEASE);
}

static uint64_t fetch_add_u64(uint64_t *ptr, uint64_t value)
{
	return __atomic_fetch_add(ptr, value, __ATOMIC_RELAXED);
}

static uint32_t fetch_add_u32(uint32_t *ptr, uint32_t value)
{
	return __atomic_fetch_add(ptr, value, __ATOMIC_RELAXED);
}

static void atomic_max_u64(uint64_t *ptr, uint64_t value)
{
	uint64_t old = load_u64(ptr);

	while (old < value && !__atomic_compare_exchange_n(ptr, &old, value, false,
							   __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		;
}

static void atomic_max_u32(uint32_t *ptr, uint32_t value)
{
	uint32_t old = load_u32(ptr);

	while (old < value && !__atomic_compare_exchange_n(ptr, &old, value, false,
							   __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		;
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * NS_PER_SEC + ts.tv_nsec;
}

static uint64_t process_cpu_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
	return (uint64_t)ts.tv_sec * NS_PER_SEC + ts.tv_nsec;
}

static void sleep_until(uint64_t deadline)
{
	struct timespec ts = {
		.tv_sec = deadline / NS_PER_SEC,
		.tv_nsec = deadline % NS_PER_SEC,
	};

	while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR &&
	       !interrupted)
		;
}

static void on_signal(int signo)
{
	interrupted = signo;
	if (signal_shared)
		store_u32(&signal_shared->stop, 1);
}

static const char *mode_name(enum bench_mode mode)
{
	switch (mode) {
	case MODE_KERNEL:
		return "kernel";
	case MODE_MEMORY_LOW:
		return "memory-low";
	case MODE_USERSPACE:
		return "userspace";
	case MODE_BPF_FIXED_ONE:
		return "bpf-fixed-1";
	case MODE_BPF:
		return "bpf";
	case MODE_BPF_FIXED_MAX:
		return "bpf-fixed-max";
	}
	return "unknown";
}

static bool mode_uses_bpf(enum bench_mode mode)
{
	return mode == MODE_BPF_FIXED_ONE || mode == MODE_BPF ||
	       mode == MODE_BPF_FIXED_MAX;
}

static const char *phase_name(enum phase phase)
{
	static const char * const names[] = { "idle", "steady", "burst", "recovery" };

	return phase < ARRAY_SIZE(names) ? names[phase] : "done";
}

static enum phase phase_at(const struct config *cfg, uint64_t elapsed, uint64_t *offset)
{
	uint64_t boundary = 0;
	int i;

	for (i = 0; i < 4; i++) {
		if (elapsed < boundary + cfg->phase_ns[i]) {
			if (offset)
				*offset = elapsed - boundary;
			return i;
		}
		boundary += cfg->phase_ns[i];
	}
	if (offset)
		*offset = 0;
	return 4;
}

static uint64_t total_duration(const struct config *cfg)
{
	return cfg->phase_ns[0] + cfg->phase_ns[1] + cfg->phase_ns[2] +
	       cfg->phase_ns[3];
}

static int path_join(char *dst, size_t size, const char *dir, const char *name)
{
	int len = snprintf(dst, size, "%s/%s", dir, name);

	return len < 0 || (size_t)len >= size ? -ENAMETOOLONG : 0;
}

static int mkdir_one(const char *path)
{
	if (!mkdir(path, 0755) || errno == EEXIST)
		return 0;
	return -errno;
}

static int write_text(const char *path, const char *text)
{
	int fd, err = 0;
	ssize_t len = strlen(text);

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (write(fd, text, len) != len)
		err = errno ? -errno : -EIO;
	close(fd);
	return err;
}

static int write_number(const char *dir, const char *file, uint64_t value)
{
	char path[PATH_MAX], buf[64];

	if (path_join(path, sizeof(path), dir, file))
		return -ENAMETOOLONG;
	snprintf(buf, sizeof(buf), "%" PRIu64, value);
	return write_text(path, buf);
}

static int read_file(const char *path, char *buf, size_t size)
{
	ssize_t len;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	len = read(fd, buf, size - 1);
	if (len < 0) {
		int err = -errno;

		close(fd);
		return err;
	}
	buf[len] = '\0';
	close(fd);
	return 0;
}

static int copy_file(const char *src, const char *dst)
{
	char buf[16384];
	ssize_t len;
	int in, out, err = 0;

	in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0)
		return -errno;
	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out < 0) {
		err = -errno;
		goto out_in;
	}
	while ((len = read(in, buf, sizeof(buf))) > 0) {
		if (write(out, buf, len) != len) {
			err = errno ? -errno : -EIO;
			break;
		}
	}
	if (len < 0 && !err)
		err = -errno;
	close(out);
out_in:
	close(in);
	return err;
}

static uint64_t parse_size(const char *arg)
{
	char *end;
	uint64_t value;

	errno = 0;
	value = strtoull(arg, &end, 0);
	if (errno || end == arg)
		return 0;
	if (*end == 'K' || *end == 'k') {
		value <<= 10;
		end++;
	} else if (*end == 'M' || *end == 'm') {
		value <<= 20;
		end++;
	} else if (*end == 'G' || *end == 'g') {
		value <<= 30;
		end++;
	}
	return *end ? 0 : value;
}

static int parse_modes(struct config *cfg, const char *arg)
{
	char *copy, *cursor, *token;
	int count = 0;

	copy = strdup(arg);
	if (!copy)
		return -ENOMEM;
	cursor = copy;
	while ((token = strsep(&cursor, ","))) {
		enum bench_mode mode;
		int i;

		if (!strcmp(token, "kernel"))
			mode = MODE_KERNEL;
		else if (!strcmp(token, "memory-low"))
			mode = MODE_MEMORY_LOW;
		else if (!strcmp(token, "userspace"))
			mode = MODE_USERSPACE;
		else if (!strcmp(token, "bpf-fixed-1"))
			mode = MODE_BPF_FIXED_ONE;
		else if (!strcmp(token, "bpf"))
			mode = MODE_BPF;
		else if (!strcmp(token, "bpf-fixed-max"))
			mode = MODE_BPF_FIXED_MAX;
		else {
			free(copy);
			return -EINVAL;
		}
		for (i = 0; i < count; i++) {
			if (cfg->modes[i] == mode) {
				free(copy);
				return -EINVAL;
			}
		}
		if (count == MAX_MODES) {
			free(copy);
			return -E2BIG;
		}
		cfg->modes[count++] = mode;
	}
	free(copy);
	cfg->mode_count = count;
	return count ? 0 : -EINVAL;
}

static void usage(FILE *out, const char *prog)
{
	fprintf(out,
		"Usage: %s [OPTIONS]\n"
		"  --modes LIST          kernel,memory-low,userspace,bpf-fixed-1,bpf,"
		"bpf-fixed-max\n"
		"  --repeat N            repetitions (default 1)\n"
		"  --duration-scale N    scale all phase durations\n"
		"  --pool-size N         fixed controller worker count (1-4)\n"
		"  --parent-max BYTES    override derived parent memory.max\n"
		"  --batch-rate BYTES    steady-phase batch fault rate per second\n"
		"  --batch-threads N     parallel batch file scanners (default 1 or 4)\n"
		"  --batch-file PATH     reuse a preallocated batch file\n"
		"  --workload NAME       synthetic or memcached\n"
		"  --memcached-bin PATH  memcached executable\n"
		"  --memtier-bin PATH    memtier_benchmark executable\n"
		"  --memcached-memory N  memcached item-cache limit\n"
		"  --memcached-data N    payload bytes populated before each trial\n"
		"  --memcached-value N   value size in bytes (default 1024)\n"
		"  --memcached-port N    loopback TCP port (default 11213)\n"
		"  --memcached-threads N server worker threads (default 8)\n"
		"  --memtier-threads N   load-generator threads (default 4)\n"
		"  --memtier-clients N   clients per load-generator thread (default 4)\n"
		"  --memtier-rate N      total open-loop operations per second\n"
		"  --output DIR          result directory\n"
		"  --work-dir DIR        regular-filesystem scratch directory\n"
		"  --seed N              deterministic workload seed\n"
		"  --keep-files          retain prepared workload files\n"
		"  --verbose             print trial progress\n",
		prog);
}

static int parse_options(struct config *cfg, int argc, char **argv, uint64_t *seed)
{
	enum {
		OPT_BATCH_RATE = 256,
		OPT_BATCH_FILE,
		OPT_BATCH_THREADS,
		OPT_WORKLOAD,
		OPT_MEMCACHED_BIN,
		OPT_MEMTIER_BIN,
		OPT_MEMCACHED_MEMORY,
		OPT_MEMCACHED_DATA,
		OPT_MEMCACHED_VALUE,
		OPT_MEMCACHED_PORT,
		OPT_MEMCACHED_THREADS,
		OPT_MEMTIER_THREADS,
		OPT_MEMTIER_CLIENTS,
		OPT_MEMTIER_RATE,
	};
	static const struct option options[] = {
		{ "modes", required_argument, NULL, 'm' },
		{ "repeat", required_argument, NULL, 'r' },
		{ "duration-scale", required_argument, NULL, 'd' },
		{ "pool-size", required_argument, NULL, 'p' },
		{ "parent-max", required_argument, NULL, 'M' },
		{ "batch-rate", required_argument, NULL, OPT_BATCH_RATE },
		{ "batch-file", required_argument, NULL, OPT_BATCH_FILE },
		{ "batch-threads", required_argument, NULL, OPT_BATCH_THREADS },
		{ "workload", required_argument, NULL, OPT_WORKLOAD },
		{ "memcached-bin", required_argument, NULL, OPT_MEMCACHED_BIN },
		{ "memtier-bin", required_argument, NULL, OPT_MEMTIER_BIN },
		{ "memcached-memory", required_argument, NULL, OPT_MEMCACHED_MEMORY },
		{ "memcached-data", required_argument, NULL, OPT_MEMCACHED_DATA },
		{ "memcached-value", required_argument, NULL, OPT_MEMCACHED_VALUE },
		{ "memcached-port", required_argument, NULL, OPT_MEMCACHED_PORT },
		{ "memcached-threads", required_argument, NULL, OPT_MEMCACHED_THREADS },
		{ "memtier-threads", required_argument, NULL, OPT_MEMTIER_THREADS },
		{ "memtier-clients", required_argument, NULL, OPT_MEMTIER_CLIENTS },
		{ "memtier-rate", required_argument, NULL, OPT_MEMTIER_RATE },
		{ "output", required_argument, NULL, 'o' },
		{ "work-dir", required_argument, NULL, 'w' },
		{ "seed", required_argument, NULL, 's' },
		{ "keep-files", no_argument, NULL, 'k' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{},
	};
	int opt;

	while ((opt = getopt_long(argc, argv, "m:r:d:p:M:o:w:s:kvh", options, NULL)) != -1) {
		switch (opt) {
		case 'm':
			if (parse_modes(cfg, optarg))
				return -EINVAL;
			break;
		case 'r':
			cfg->repeat = atoi(optarg);
			break;
		case 'd':
			cfg->duration_scale = strtod(optarg, NULL);
			break;
		case 'p':
			cfg->pool_size = atoi(optarg);
			break;
		case 'M':
			cfg->parent_max = parse_size(optarg);
			if (!cfg->parent_max)
				return -EINVAL;
			break;
		case OPT_BATCH_RATE:
			cfg->batch_rate[PHASE_STEADY] = parse_size(optarg);
			if (!cfg->batch_rate[PHASE_STEADY])
				return -EINVAL;
			break;
		case OPT_BATCH_FILE:
			if (snprintf(cfg->batch_file, sizeof(cfg->batch_file), "%s", optarg) >=
			    sizeof(cfg->batch_file))
				return -ENAMETOOLONG;
			cfg->reuse_batch_file = true;
			break;
		case OPT_BATCH_THREADS:
			cfg->batch_threads = atoi(optarg);
			if (cfg->batch_threads < 1 || cfg->batch_threads > MAX_BATCH_THREADS)
				return -EINVAL;
			break;
		case OPT_WORKLOAD:
			if (!strcmp(optarg, "memcached"))
				cfg->memcached = true;
			else if (!strcmp(optarg, "synthetic"))
				cfg->memcached = false;
			else
				return -EINVAL;
			break;
		case OPT_MEMCACHED_BIN:
			if (snprintf(cfg->memcached_binary, sizeof(cfg->memcached_binary),
				     "%s", optarg) >= sizeof(cfg->memcached_binary))
				return -ENAMETOOLONG;
			break;
		case OPT_MEMTIER_BIN:
			if (snprintf(cfg->memtier_binary, sizeof(cfg->memtier_binary),
				     "%s", optarg) >= sizeof(cfg->memtier_binary))
				return -ENAMETOOLONG;
			break;
		case OPT_MEMCACHED_MEMORY:
			cfg->memcached_memory = parse_size(optarg);
			if (!cfg->memcached_memory)
				return -EINVAL;
			break;
		case OPT_MEMCACHED_DATA:
			cfg->memcached_data_size = parse_size(optarg);
			if (!cfg->memcached_data_size)
				return -EINVAL;
			break;
		case OPT_MEMCACHED_VALUE:
			cfg->memcached_value_size = parse_size(optarg);
			if (!cfg->memcached_value_size)
				return -EINVAL;
			break;
		case OPT_MEMCACHED_PORT:
			cfg->memcached_port = atoi(optarg);
			break;
		case OPT_MEMCACHED_THREADS:
			cfg->memcached_threads = atoi(optarg);
			break;
		case OPT_MEMTIER_THREADS:
			cfg->memtier_threads = atoi(optarg);
			break;
		case OPT_MEMTIER_CLIENTS:
			cfg->memtier_clients = atoi(optarg);
			break;
		case OPT_MEMTIER_RATE:
			cfg->memtier_rate = strtoull(optarg, NULL, 0);
			if (!cfg->memtier_rate)
				return -EINVAL;
			break;
		case 'o':
			if (snprintf(cfg->output, sizeof(cfg->output), "%s", optarg) >=
			    sizeof(cfg->output))
				return -ENAMETOOLONG;
			break;
		case 'w':
			if (snprintf(cfg->work_dir, sizeof(cfg->work_dir), "%s", optarg) >=
			    sizeof(cfg->work_dir))
				return -ENAMETOOLONG;
			break;
		case 's':
			*seed = strtoull(optarg, NULL, 0);
			break;
		case 'k':
			cfg->keep_files = true;
			break;
		case 'v':
			cfg->verbose = true;
			break;
		case 'h':
			usage(stdout, argv[0]);
			exit(0);
		default:
			return -EINVAL;
		}
	}
	if (optind != argc || cfg->repeat < 1 || cfg->duration_scale <= 0 ||
	    cfg->pool_size < 1 || cfg->pool_size > MAX_WORKERS ||
	    cfg->memcached_port < 1 || cfg->memcached_port > 65535 ||
	    cfg->memcached_threads < 1 || cfg->memtier_threads < 1 ||
	    cfg->memtier_clients < 1)
		return -EINVAL;
	return 0;
}

static uint64_t clamp_u64(uint64_t value, uint64_t minimum, uint64_t maximum)
{
	if (value < minimum)
		return minimum;
	if (value > maximum)
		return maximum;
	return value;
}

static int resolve_config(struct config *cfg)
{
	struct statfs fs;
	uint64_t batch_rate_bytes = cfg->batch_rate[PHASE_STEADY];
	long cpus;
	int i;

	cfg->page_size = sysconf(_SC_PAGESIZE);
	cfg->host_memory = (uint64_t)sysconf(_SC_PHYS_PAGES) * cfg->page_size;
	if (!cfg->page_size || !cfg->host_memory)
		return -EINVAL;
	if (!cfg->parent_max)
		cfg->parent_max = clamp_u64(cfg->host_memory * 40 / 100,
					    256ULL << 20, 1ULL << 30);
	if (cfg->parent_max >= cfg->host_memory * 3 / 4)
		return -EINVAL;
	cfg->parent_max -= cfg->parent_max % cfg->page_size;
	cfg->parent_high = cfg->parent_max * 70 / 100;
	cfg->parent_target = cfg->parent_max * 65 / 100;
	if (cfg->memcached) {
		if (!cfg->memcached_memory)
			cfg->memcached_memory = cfg->parent_max * 40 / 100;
		if (!cfg->memcached_data_size)
			cfg->memcached_data_size = cfg->memcached_memory * 75 / 100;
		cfg->memcached_memory -= cfg->memcached_memory % cfg->page_size;
		cfg->memcached_data_size -= cfg->memcached_data_size %
			cfg->memcached_value_size;
		if (!cfg->memcached_data_size ||
		    cfg->memcached_data_size > cfg->memcached_memory * 85 / 100)
			return -EINVAL;
		cfg->memcached_key_count = cfg->memcached_data_size /
			cfg->memcached_value_size;
		cfg->service_file_size = 0;
		cfg->service_hot_size = cfg->parent_max * 45 / 100;
		cfg->batch_file_size = cfg->parent_max * 125 / 100;
		if (access(cfg->memcached_binary, X_OK) || access(cfg->memtier_binary, X_OK))
			return -ENOENT;
	} else {
		cfg->service_file_size = cfg->parent_max * 60 / 100;
		cfg->service_hot_size = cfg->parent_max * 45 / 100;
		cfg->batch_file_size = cfg->parent_max * 150 / 100;
	}
	cfg->epoch_ns = DEFAULT_EPOCH_NS;
	cfg->quantum_pages = (16ULL << 20) / cfg->page_size;
	cfg->max_pending_pages = cfg->parent_max / cfg->page_size;
	cfg->minimum_capacity_pages = (4ULL << 20) / cfg->page_size;
	cfg->refault_budget = 32;
	cfg->refault_gain = 4;
	cfg->recovery_epochs = 4;
	cfg->scalein_epochs = 3;
	cfg->service_rate = 20000;
	cfg->service_threads = 2;
	cfg->phase_ns[PHASE_IDLE] = 2 * NS_PER_SEC * cfg->duration_scale;
	cfg->phase_ns[PHASE_STEADY] = 4 * NS_PER_SEC * cfg->duration_scale;
	cfg->phase_ns[PHASE_BURST] = 4 * NS_PER_SEC * cfg->duration_scale;
	cfg->phase_ns[PHASE_RECOVERY] = 6 * NS_PER_SEC * cfg->duration_scale;
	cfg->batch_rate[PHASE_IDLE] = 0;
	if (batch_rate_bytes)
		cfg->batch_rate[PHASE_STEADY] = batch_rate_bytes / cfg->page_size;
	else if (cfg->memcached)
		cfg->batch_rate[PHASE_STEADY] = cfg->parent_max / cfg->page_size / 40;
	else
		cfg->batch_rate[PHASE_STEADY] = cfg->parent_max / cfg->page_size / 20;
	cfg->batch_rate[PHASE_BURST] = cfg->batch_rate[PHASE_STEADY] *
		(cfg->memcached ? 4 : 6);
	cfg->batch_rate[PHASE_RECOVERY] = cfg->batch_rate[PHASE_STEADY] / 2;
	cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (cfg->pool_size > cpus - 1 && cpus > 1)
		cfg->pool_size = cpus - 1;
	if (cfg->pool_size < 1)
		cfg->pool_size = 1;
	if (!cfg->batch_threads)
		cfg->batch_threads = cfg->memcached ? 4 : 1;
	if (statfs(cfg->work_dir, &fs))
		return -errno;
	if (fs.f_type == TMPFS_MAGIC || fs.f_type == RAMFS_MAGIC)
		return -EOPNOTSUPP;
	for (i = 0; i < 4; i++) {
		if (cfg->phase_ns[i] < cfg->epoch_ns)
			cfg->phase_ns[i] = cfg->epoch_ns;
	}
	return 0;
}

static int enable_controllers(const char *dir)
{
	char path[PATH_MAX];

	if (path_join(path, sizeof(path), dir, "cgroup.subtree_control"))
		return -ENAMETOOLONG;
	return write_text(path, "+memory +cpu");
}

static int setup_cgroups(struct cgroup_paths *cgs, const struct config *cfg)
{
	int err;

	snprintf(cgs->parent, sizeof(cgs->parent), "/sys/fs/cgroup/memcg_reclaim_bench.%d",
		 getpid());
	if (path_join(cgs->service, sizeof(cgs->service), cgs->parent, "service") ||
	    path_join(cgs->batch, sizeof(cgs->batch), cgs->parent, "batch") ||
	    path_join(cgs->loadgen, sizeof(cgs->loadgen), cgs->parent, "loadgen"))
		return -ENAMETOOLONG;
	err = enable_controllers("/sys/fs/cgroup");
	if (err && err != -EBUSY)
		return err;
	err = mkdir_one(cgs->parent);
	if (err)
		return err;
	err = write_number(cgs->parent, "memory.max", cfg->parent_max);
	if (err)
		return err;
	err = write_number(cgs->parent, "memory.high", cfg->parent_high);
	if (err)
		return err;
	write_number(cgs->parent, "memory.swap.max", 0);
	err = enable_controllers(cgs->parent);
	if (err)
		return err;
	err = mkdir_one(cgs->service);
	if (err)
		return err;
	err = mkdir_one(cgs->batch);
	if (err)
		return err;
	err = mkdir_one(cgs->loadgen);
	if (err)
		return err;
	err = write_number(cgs->service, "cpu.weight", 800);
	if (err)
		return err;
	err = write_number(cgs->batch, "cpu.weight", 200);
	if (err)
		return err;
	err = write_number(cgs->loadgen, "cpu.weight", 800);
	if (err)
		return err;
	err = write_number(cgs->service, "memory.low", 0);
	if (err)
		return err;
	return 0;
}

static void cleanup_cgroups(const struct cgroup_paths *cgs)
{
	rmdir(cgs->service);
	rmdir(cgs->batch);
	rmdir(cgs->loadgen);
	rmdir(cgs->parent);
}

static int attach_pid(const char *cgroup, pid_t pid)
{
	char path[PATH_MAX], text[32];

	if (path_join(path, sizeof(path), cgroup, "cgroup.procs"))
		return -ENAMETOOLONG;
	snprintf(text, sizeof(text), "%d", pid);
	return write_text(path, text);
}

static uint64_t cgroup_id(const char *path)
{
	struct file_handle *handle;
	uint64_t id = 0;
	int mount_id;

	handle = calloc(1, sizeof(*handle) + 8);
	if (!handle)
		return 0;
	handle->handle_bytes = 8;
	if (!name_to_handle_at(AT_FDCWD, path, handle, &mount_id, 0))
		memcpy(&id, handle->f_handle, sizeof(id));
	free(handle);
	return id;
}

static int prepare_file(const char *path, uint64_t size, uint64_t seed)
{
	const size_t chunk_size = 1 << 20;
	unsigned char *buf;
	uint64_t offset;
	int fd, err = 0;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return -errno;
	err = posix_fallocate(fd, 0, size);
	if (err) {
		err = -err;
		goto out;
	}
	buf = malloc(chunk_size);
	if (!buf) {
		err = -ENOMEM;
		goto out;
	}
	for (offset = 0; offset < chunk_size; offset++)
		buf[offset] = (seed + offset * 131) & 0xff;
	for (offset = 0; offset < size; offset += chunk_size) {
		size_t len = size - offset < chunk_size ? size - offset : chunk_size;

		if (pwrite(fd, buf, len, offset) != len) {
			err = -errno;
			break;
		}
	}
	free(buf);
	if (!err && fsync(fd))
		err = -errno;
	if (!err)
		posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
out:
	close(fd);
	return err;
}

static int validate_prepared_file(const char *path, uint64_t size)
{
	struct stat stat;
	int fd;

	if (lstat(path, &stat))
		return -errno;
	if (!S_ISREG(stat.st_mode) || stat.st_size < size)
		return -EINVAL;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	posix_fadvise(fd, 0, size, POSIX_FADV_DONTNEED);
	close(fd);
	return 0;
}

static void reset_file_cache(const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd >= 0) {
		posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
		close(fd);
	}
}

typedef int (*child_fn_t)(void *arg);

static int spawn_child(struct child_proc *child, const char *cgroup, child_fn_t fn, void *arg)
{
	int pipefd[2], err;
	char byte;
	pid_t pid;

	if (pipe2(pipefd, O_CLOEXEC))
		return -errno;
	pid = fork();
	if (pid < 0) {
		err = -errno;
		close(pipefd[0]);
		close(pipefd[1]);
		return err;
	}
	if (!pid) {
		close(pipefd[1]);
		if (read(pipefd[0], &byte, 1) != 1)
			_exit(125);
		close(pipefd[0]);
		_exit(fn(arg) ? 1 : 0);
	}

	close(pipefd[0]);
	err = attach_pid(cgroup, pid);
	if (err) {
		close(pipefd[1]);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		return err;
	}
	child->pid = pid;
	child->release_fd = pipefd[1];
	return 0;
}

static int release_child(struct child_proc *child)
{
	if (write(child->release_fd, "x", 1) != 1) {
		int err = -errno;

		close(child->release_fd);
		child->release_fd = -1;
		return err;
	}
	close(child->release_fd);
	child->release_fd = -1;
	return 0;
}

static int reap_child(struct child_proc *child, int timeout_ms)
{
	int status, elapsed = 0;
	pid_t ret;

	if (child->pid <= 0)
		return 0;
	while (elapsed < timeout_ms) {
		ret = waitpid(child->pid, &status, WNOHANG);
		if (ret == child->pid) {
			child->pid = 0;
			if (WIFEXITED(status) && !WEXITSTATUS(status))
				return 0;
			return -ECHILD;
		}
		if (ret < 0) {
			int err = -errno;

			child->pid = 0;
			return err;
		}
		usleep(10000);
		elapsed += 10;
	}
	kill(child->pid, SIGTERM);
	usleep(100000);
	if (waitpid(child->pid, &status, WNOHANG) != child->pid) {
		kill(child->pid, SIGKILL);
		waitpid(child->pid, &status, 0);
	}
	child->pid = 0;
	return -ETIMEDOUT;
}

struct memcached_args {
	const struct config *cfg;
	const char *log_path;
};

struct memtier_args {
	const struct config *cfg;
	const char *json_path;
	const char *log_path;
	uint64_t duration_seconds;
	bool prefill;
};

static int redirect_child_log(const char *path)
{
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return -errno;
	if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) {
		int err = -errno;

		close(fd);
		return err;
	}
	close(fd);
	return 0;
}

static int memcached_main(void *data)
{
	struct memcached_args *args = data;
	const struct config *cfg = args->cfg;
	char memory[32], port[16], threads[16];
	char *const argv[] = {
		(char *)cfg->memcached_binary,
		"-l", "127.0.0.1",
		"-p", port,
		"-U", "0",
		"-m", memory,
		"-t", threads,
		"-u", "root",
		NULL,
	};
	int err;

	snprintf(memory, sizeof(memory), "%" PRIu64, cfg->memcached_memory >> 20);
	snprintf(port, sizeof(port), "%d", cfg->memcached_port);
	snprintf(threads, sizeof(threads), "%d", cfg->memcached_threads);
	err = redirect_child_log(args->log_path);
	if (err)
		return err;
	execv(cfg->memcached_binary, argv);
	return -errno;
}

static int memtier_main(void *data)
{
	struct memtier_args *args = data;
	const struct config *cfg = args->cfg;
	uint64_t connections = cfg->memtier_threads * cfg->memtier_clients;
	uint64_t rate = (cfg->memtier_rate + connections - 1) / connections;
	char port[16], threads[16], clients[16], value_size[32], keys[32];
	char duration[32], rate_arg[64];
	char *argv[40];
	int argc = 0, err;

	snprintf(port, sizeof(port), "%d", cfg->memcached_port);
	snprintf(threads, sizeof(threads), "%d", cfg->memtier_threads);
	snprintf(clients, sizeof(clients), "%d", cfg->memtier_clients);
	snprintf(value_size, sizeof(value_size), "%" PRIu64, cfg->memcached_value_size);
	snprintf(keys, sizeof(keys), "%" PRIu64, cfg->memcached_key_count);
	snprintf(duration, sizeof(duration), "%" PRIu64, args->duration_seconds);
	snprintf(rate_arg, sizeof(rate_arg), "--rate-limiting=%" PRIu64, rate);

	argv[argc++] = (char *)cfg->memtier_binary;
	argv[argc++] = "--server=127.0.0.1";
	argv[argc++] = "--port";
	argv[argc++] = port;
	argv[argc++] = "--protocol=memcache_binary";
	argv[argc++] = "--threads";
	argv[argc++] = threads;
	argv[argc++] = "--clients";
	argv[argc++] = clients;
	argv[argc++] = "--data-size";
	argv[argc++] = value_size;
	argv[argc++] = "--key-minimum=1";
	argv[argc++] = "--key-maximum";
	argv[argc++] = keys;
	argv[argc++] = "--key-prefix=bpf-reclaim-";
	argv[argc++] = "--hide-histogram";
	if (args->prefill) {
		argv[argc++] = "--ratio=1:0";
		argv[argc++] = "--key-pattern=P:P";
		argv[argc++] = "--requests=allkeys";
		argv[argc++] = "--pipeline=8";
	} else {
		argv[argc++] = "--ratio=1:499";
		argv[argc++] = "--key-pattern=R:R";
		argv[argc++] = "--key-zipf-exp=0.99";
		argv[argc++] = "--pipeline=1";
		argv[argc++] = "--distinct-client-seed";
		argv[argc++] = "--test-time";
		argv[argc++] = duration;
		argv[argc++] = rate_arg;
		argv[argc++] = "--print-percentiles=50,95,99,99.9,99.99";
	}
	argv[argc++] = "--json-out-file";
	argv[argc++] = (char *)args->json_path;
	argv[argc] = NULL;

	err = redirect_child_log(args->log_path);
	if (err)
		return err;
	execv(cfg->memtier_binary, argv);
	return -errno;
}

static int wait_for_memcached(const struct config *cfg)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_port = htons(cfg->memcached_port),
	};
	uint64_t deadline = now_ns() + 30 * NS_PER_SEC;

	inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
	while (now_ns() < deadline) {
		int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

		if (fd >= 0) {
			if (!connect(fd, (struct sockaddr *)&address, sizeof(address))) {
				close(fd);
				return 0;
			}
			close(fd);
		}
		usleep(50000);
	}
	return -ETIMEDOUT;
}

static int stop_external_child(struct child_proc *child, int timeout_ms)
{
	if (child->pid > 0)
		kill(child->pid, SIGTERM);
	return reap_child(child, timeout_ms);
}

static uint64_t xorshift64(uint64_t *state)
{
	uint64_t value = *state;

	value ^= value << 13;
	value ^= value >> 7;
	value ^= value << 17;
	*state = value;
	return value;
}

static unsigned int latency_bucket(uint64_t latency)
{
	if (latency <= 1)
		return 0;
	return 64 - __builtin_clzll(latency - 1);
}

static uint64_t histogram_percentile(const uint64_t *hist, unsigned int percentile)
{
	uint64_t total = 0, target, seen = 0;
	int i;

	for (i = 0; i < LATENCY_BUCKETS; i++)
		total += hist[i];
	if (!total)
		return 0;
	target = (total * percentile + 99) / 100;
	for (i = 0; i < LATENCY_BUCKETS; i++) {
		seen += hist[i];
		if (seen >= target)
			return i == 63 ? UINT64_MAX : 1ULL << i;
	}
	return UINT64_MAX;
}

struct service_args {
	const struct config *cfg;
	struct shared_state *shared;
	uint64_t seed;
};

struct service_worker_args {
	const struct config *cfg;
	struct shared_state *shared;
	const unsigned char *mapping;
	uint64_t seed;
};

static void *service_worker(void *data)
{
	struct service_worker_args *arg = data;
	const struct config *cfg = arg->cfg;
	struct shared_state *shared = arg->shared;
	uint64_t file_pages = cfg->service_file_size / cfg->page_size;
	uint64_t hot_pages = cfg->service_hot_size / cfg->page_size;
	uint64_t period = NS_PER_SEC * cfg->service_threads / cfg->service_rate;
	uint64_t next, state = arg->seed;
	unsigned int sink = 0;

	while (!load_u32(&shared->start) && !load_u32(&shared->stop))
		sched_yield();
	next = load_u64(&shared->start_ns);
	if (next > now_ns())
		sleep_until(next);
	while (!load_u32(&shared->stop)) {
		uint64_t begin, end, latency, page;
		unsigned int bucket, i;

		begin = now_ns();
		for (i = 0; i < 4; i++) {
			uint64_t random = xorshift64(&state);

			if ((random & 7) && hot_pages)
				page = random % hot_pages;
			else
				page = random % file_pages;
			sink += arg->mapping[page * cfg->page_size];
		}
		end = now_ns();
		latency = end - begin;
		bucket = latency_bucket(latency);
		fetch_add_u64(&shared->service_hist[bucket], 1);
		fetch_add_u64(&shared->service_ops, 1);
		atomic_max_u64(&shared->service_max_ns, latency);
		atomic_max_u64(&shared->service_epoch_max_ns, latency);
		if (latency > load_u64(&shared->slo_ns))
			fetch_add_u64(&shared->service_slo_violations, 1);
		next += period;
		if (next > now_ns())
			sleep_until(next);
		else
			next = now_ns();
	}
	if (sink == UINT_MAX)
		fprintf(stderr, "service sink: %u\n", sink);
	return NULL;
}

static int service_main(void *data)
{
	struct service_args *arg = data;
	const struct config *cfg = arg->cfg;
	struct service_worker_args *worker_args;
	struct shared_state *shared = arg->shared;
	pthread_t *threads;
	unsigned char *mapping;
	unsigned int sink = 0;
	uint64_t offset;
	int fd, err = 0, i;

	fd = open(cfg->service_file, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	mapping = mmap(NULL, cfg->service_file_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (mapping == MAP_FAILED)
		return -errno;
	madvise(mapping, cfg->service_file_size, MADV_RANDOM);
	for (offset = 0; offset < cfg->service_hot_size; offset += cfg->page_size)
		sink += mapping[offset];

	threads = calloc(cfg->service_threads, sizeof(*threads));
	worker_args = calloc(cfg->service_threads, sizeof(*worker_args));
	if (!threads || !worker_args) {
		err = -ENOMEM;
		goto out;
	}
	for (i = 0; i < cfg->service_threads; i++) {
		worker_args[i] = (struct service_worker_args) {
			.cfg = cfg,
			.shared = shared,
			.mapping = mapping,
			.seed = arg->seed + 0x9e3779b97f4a7c15ULL * (i + 1),
		};
		err = pthread_create(&threads[i], NULL, service_worker, &worker_args[i]);
		if (err) {
			store_u32(&shared->stop, 1);
			break;
		}
	}
	store_u32(&shared->service_ready, 1);
	while (i-- > 0)
		pthread_join(threads[i], NULL);
out:
	free(worker_args);
	free(threads);
	munmap(mapping, cfg->service_file_size);
	if (sink == UINT_MAX)
		fprintf(stderr, "prewarm sink: %u\n", sink);
	return err;
}

struct batch_args {
	const struct config *cfg;
	struct shared_state *shared;
	unsigned int worker;
};

static uint64_t phase_target(const struct config *cfg, enum phase phase, uint64_t offset)
{
	uint64_t active = offset;

	if (phase == PHASE_RECOVERY && active > cfg->phase_ns[phase] / 2)
		active = cfg->phase_ns[phase] / 2;
	return active * cfg->batch_rate[phase] / NS_PER_SEC;
}

static int batch_main(void *data)
{
	struct batch_args *arg = data;
	const struct config *cfg = arg->cfg;
	struct shared_state *shared = arg->shared;
	unsigned char *mapping;
	unsigned int sink = 0;
	uint64_t done[4] = {}, file_pages, first_page, last_page, page;
	int fd;

	fd = open(cfg->batch_file, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	mapping = mmap(NULL, cfg->batch_file_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (mapping == MAP_FAILED)
		return -errno;
	madvise(mapping, cfg->batch_file_size, MADV_NORMAL);
	file_pages = cfg->batch_file_size / cfg->page_size;
	first_page = file_pages * arg->worker / cfg->batch_threads;
	last_page = file_pages * (arg->worker + 1) / cfg->batch_threads;
	page = first_page;
	fetch_add_u32(&shared->batch_ready, 1);
	while (!load_u32(&shared->start) && !load_u32(&shared->stop))
		sched_yield();
	if (load_u64(&shared->start_ns) > now_ns())
		sleep_until(load_u64(&shared->start_ns));

	while (!load_u32(&shared->stop)) {
		uint64_t elapsed = now_ns() - load_u64(&shared->start_ns);
		uint64_t offset, target;
		enum phase phase = phase_at(cfg, elapsed, &offset);
		unsigned int chunk = 0;

		if (phase >= 4)
			break;
		target = phase_target(cfg, phase, offset) / cfg->batch_threads;
		if (arg->worker < phase_target(cfg, phase, offset) % cfg->batch_threads)
			target++;
		while (done[phase] < target && chunk++ < 4096 && !load_u32(&shared->stop)) {
			sink += mapping[page * cfg->page_size];
			if (++page == last_page)
				page = first_page;
			done[phase]++;
			fetch_add_u64(&shared->batch_pages, 1);
		}
		if (done[phase] >= target)
			usleep(1000);
	}
	munmap(mapping, cfg->batch_file_size);
	if (sink == UINT_MAX)
		fprintf(stderr, "batch sink: %u\n", sink);
	return 0;
}

static int wait_ready(const uint32_t *word, unsigned int timeout_sec)
{
	uint64_t deadline = now_ns() + timeout_sec * NS_PER_SEC;

	while (!load_u32(word)) {
		if (now_ns() >= deadline)
			return -ETIMEDOUT;
		usleep(1000);
	}
	return 0;
}

static int wait_ready_count(const uint32_t *word, uint32_t count, unsigned int timeout_sec)
{
	uint64_t deadline = now_ns() + timeout_sec * NS_PER_SEC;

	while (load_u32(word) < count) {
		if (now_ns() >= deadline)
			return -ETIMEDOUT;
		usleep(1000);
	}
	return 0;
}

static uint64_t key_value(const char *buf, const char *key)
{
	size_t key_len = strlen(key);
	const char *line = buf;

	while (*line) {
		const char *end = strchr(line, '\n');
		const char *value;

		if (!end)
			end = line + strlen(line);
		if ((size_t)(end - line) > key_len && !strncmp(line, key, key_len) &&
		    (line[key_len] == ' ' || line[key_len] == '\t')) {
			value = line + key_len;
			while (*value == ' ' || *value == '\t')
				value++;
			return strtoull(value, NULL, 10);
		}
		line = *end ? end + 1 : end;
	}
	return MISSING;
}

static uint64_t pressure_total(const char *buf, const char *kind)
{
	const char *line = buf;
	size_t kind_len = strlen(kind);

	while (*line) {
		const char *end = strchr(line, '\n');
		const char *total;

		if (!end)
			end = line + strlen(line);
		if (!strncmp(line, kind, kind_len) && line[kind_len] == ' ') {
			total = strstr(line, "total=");
			if (total && total < end)
				return strtoull(total + strlen("total="), NULL, 10);
		}
		line = *end ? end + 1 : end;
	}
	return MISSING;
}

static int read_cgroup_file(const char *dir, const char *name, char *buf, size_t size)
{
	char path[PATH_MAX];

	if (path_join(path, sizeof(path), dir, name))
		return -ENAMETOOLONG;
	return read_file(path, buf, size);
}

static int read_cg_metrics(const char *dir, struct cg_metrics *metrics)
{
	char buf[16384];
	int err;

	memset(metrics, 0xff, sizeof(*metrics));
	err = read_cgroup_file(dir, "memory.current", buf, sizeof(buf));
	if (err)
		return err;
	metrics->memory_current = strtoull(buf, NULL, 10);

	err = read_cgroup_file(dir, "memory.events", buf, sizeof(buf));
	if (err)
		return err;
	metrics->high = key_value(buf, "high");
	metrics->max = key_value(buf, "max");
	metrics->oom = key_value(buf, "oom");
	metrics->oom_kill = key_value(buf, "oom_kill");

	err = read_cgroup_file(dir, "memory.stat", buf, sizeof(buf));
	if (err)
		return err;
	metrics->refault_file = key_value(buf, "workingset_refault_file");
	metrics->pgscan = key_value(buf, "pgscan");
	metrics->pgsteal = key_value(buf, "pgsteal");
	metrics->pgscan_direct = key_value(buf, "pgscan_direct");
	metrics->pgsteal_direct = key_value(buf, "pgsteal_direct");

	err = read_cgroup_file(dir, "memory.pressure", buf, sizeof(buf));
	if (err && err != -ENOENT && err != -EOPNOTSUPP)
		return err;
	if (!err) {
		metrics->psi_some = pressure_total(buf, "some");
		metrics->psi_full = pressure_total(buf, "full");
	}

	err = read_cgroup_file(dir, "cpu.stat", buf, sizeof(buf));
	if (err)
		return err;
	metrics->cpu_usage = key_value(buf, "usage_usec");
	metrics->cpu_user = key_value(buf, "user_usec");
	metrics->cpu_system = key_value(buf, "system_usec");
	metrics->nr_throttled = key_value(buf, "nr_throttled");
	metrics->throttled_usec = key_value(buf, "throttled_usec");
	return 0;
}

static int read_vm_metrics(struct vm_metrics *metrics)
{
	char buf[65536];
	int err;

	memset(metrics, 0xff, sizeof(*metrics));
	err = read_file("/proc/vmstat", buf, sizeof(buf));
	if (err)
		return err;
	metrics->pgscan_kswapd = key_value(buf, "pgscan_kswapd");
	metrics->pgsteal_kswapd = key_value(buf, "pgsteal_kswapd");
	metrics->pgscan_direct = key_value(buf, "pgscan_direct");
	metrics->pgsteal_direct = key_value(buf, "pgsteal_direct");
	return 0;
}

static uint64_t metric_delta(uint64_t current, uint64_t previous)
{
	if (current == MISSING || previous == MISSING || current < previous)
		return MISSING;
	return current - previous;
}

static void csv_value(FILE *file, uint64_t value)
{
	if (value != MISSING)
		fprintf(file, "%" PRIu64, value);
}

static int snapshot_raw_metrics(const char *raw_dir, const char *prefix,
				const struct cgroup_paths *cgs)
{
	static const char * const files[] = {
		"memory.events", "memory.stat", "memory.pressure", "cpu.stat",
	};
	const char * const dirs[] = {
		cgs->parent, cgs->service, cgs->batch, cgs->loadgen,
	};
	const char * const names[] = { "parent", "service", "batch", "loadgen" };
	char src[PATH_MAX], dst[PATH_MAX], leaf[128];
	int i, j, err;

	for (i = 0; i < ARRAY_SIZE(dirs); i++) {
		for (j = 0; j < ARRAY_SIZE(files); j++) {
			if (path_join(src, sizeof(src), dirs[i], files[j]))
				return -ENAMETOOLONG;
			snprintf(leaf, sizeof(leaf), "%s-%s-%s", prefix, names[i], files[j]);
			if (path_join(dst, sizeof(dst), raw_dir, leaf))
				return -ENAMETOOLONG;
			err = copy_file(src, dst);
			if (err == -ENOENT || err == -EOPNOTSUPP)
				continue;
			if (err)
				return err;
		}
	}
	return 0;
}

static void read_shared_controller(const struct shared_state *shared,
				   struct controller_metrics *metrics)
{
	memset(metrics, 0, sizeof(*metrics));
	metrics->authorized = load_u64(&shared->authorized_pages);
	metrics->pending = load_u64(&shared->pending_pages);
	metrics->requested = load_u64(&shared->requested_pages);
	metrics->reclaimed = MISSING;
	metrics->failed = load_u64(&shared->failed_pages);
	metrics->first_reclaim_ns = load_u64(&shared->first_reclaim_ns);
	metrics->epochs = load_u64(&shared->controller_epochs);
	metrics->cpu_ns = load_u64(&shared->controller_cpu_ns);
	metrics->wakeups = load_u64(&shared->worker_wakeups);
	metrics->sleeps = load_u64(&shared->worker_sleeps);
	metrics->conflicts = load_u64(&shared->claim_conflicts);
	metrics->active = load_u32(&shared->active_workers);
	metrics->peak_active = load_u32(&shared->peak_active_workers);
	metrics->desired = load_u32(&shared->desired_workers);
	metrics->peak_desired = load_u32(&shared->peak_desired_workers);
}

static void read_bpf_controller(const struct bench_memcg_reclaim *skel,
				struct controller_metrics *metrics)
{
	memset(metrics, 0, sizeof(*metrics));
	metrics->authorized = skel->bss->authorized_pages;
	metrics->pending = skel->bss->pending_pages_snapshot;
	metrics->requested = skel->bss->requested_pages;
	metrics->reclaimed = skel->bss->reclaimed_pages;
	metrics->failed = skel->bss->failed_pages;
	metrics->epochs = skel->bss->controller_epochs;
	metrics->wakeups = skel->bss->worker_wakeups;
	metrics->sleeps = skel->bss->worker_sleeps;
	metrics->conflicts = skel->bss->claim_conflicts;
	metrics->first_reclaim_ns = skel->bss->first_reclaim_ns;
	metrics->active = skel->bss->active_workers;
	metrics->peak_active = skel->bss->peak_active_workers;
	metrics->desired = skel->bss->desired_workers;
	metrics->peak_desired = skel->bss->peak_desired_workers;
	metrics->pool_started = skel->bss->pool_started;
	metrics->pool_stopped = skel->bss->pool_stopped;
}

struct userspace_controller;

struct userspace_worker {
	struct userspace_controller *controller;
	uint32_t slot;
};

struct userspace_controller {
	const struct config *cfg;
	const struct cgroup_paths *cgs;
	struct shared_state *shared;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	pthread_t threads[MAX_WORKERS];
	struct userspace_worker workers[MAX_WORKERS];
	uint32_t stop;
	uint32_t healthy_epochs;
	uint64_t capacity_pages;
	uint64_t last_batch_pages;
	uint64_t last_service_refaults;
	uint64_t last_requested_pages;
	int parent_current_fd;
	int batch_current_fd;
	int service_stat_fd;
};

static int open_cgroup_file(const char *dir, const char *name, int flags)
{
	char path[PATH_MAX];

	if (path_join(path, sizeof(path), dir, name))
		return -ENAMETOOLONG;
	return open(path, flags | O_CLOEXEC);
}

static int pread_text(int fd, char *buf, size_t size)
{
	ssize_t len = pread(fd, buf, size - 1, 0);

	if (len < 0)
		return -errno;
	buf[len] = '\0';
	return 0;
}

static int read_current_pages(int fd, uint64_t page_size, uint64_t *pages)
{
	char buf[64];
	int err;

	err = pread_text(fd, buf, sizeof(buf));
	if (err)
		return err;
	*pages = strtoull(buf, NULL, 10) / page_size;
	return 0;
}

static uint64_t saturating_add(uint64_t value, uint64_t add, uint64_t maximum)
{
	if (add >= maximum || value >= maximum - add)
		return maximum;
	return value + add;
}

static uint64_t saturating_mul(uint64_t value, uint32_t factor, uint64_t maximum)
{
	if (!factor)
		return 0;
	if (value >= maximum / factor)
		return maximum;
	return value * factor;
}

static uint64_t userspace_enqueue(struct userspace_controller *controller, uint64_t work,
				  uint64_t *old_pending)
{
	struct shared_state *shared = controller->shared;
	uint64_t old, pending;

	for (;;) {
		old = load_u64(&shared->pending_pages);
		pending = saturating_add(old, work, controller->cfg->max_pending_pages);
		if (__atomic_compare_exchange_n(&shared->pending_pages, &old, pending, false,
						__ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
			fetch_add_u64(&shared->authorized_pages, pending - old);
			*old_pending = old;
			return pending;
		}
		fetch_add_u64(&shared->claim_conflicts, 1);
	}
}

static uint64_t userspace_claim(struct userspace_controller *controller)
{
	struct shared_state *shared = controller->shared;
	uint64_t claim, old;

	for (;;) {
		old = load_u64(&shared->pending_pages);
		if (!old)
			return 0;
		claim = old < controller->cfg->quantum_pages ?
			old : controller->cfg->quantum_pages;
		if (__atomic_compare_exchange_n(&shared->pending_pages, &old, old - claim, false,
						__ATOMIC_RELAXED, __ATOMIC_RELAXED))
			return claim;
		fetch_add_u64(&shared->claim_conflicts, 1);
	}
}

static void *userspace_worker_main(void *data)
{
	struct userspace_worker *worker = data;
	struct userspace_controller *controller = worker->controller;
	struct shared_state *shared = controller->shared;
	char command[96];

	for (;;) {
		uint64_t claim;
		uint32_t active;
		int fd, len;

		pthread_mutex_lock(&controller->lock);
		while (!controller->stop &&
		       (worker->slot >= load_u32(&shared->desired_workers) ||
			!load_u64(&shared->pending_pages))) {
			fetch_add_u64(&shared->worker_sleeps, 1);
			pthread_cond_wait(&controller->cond, &controller->lock);
		}
		if (controller->stop) {
			pthread_mutex_unlock(&controller->lock);
			break;
		}
		pthread_mutex_unlock(&controller->lock);

		claim = userspace_claim(controller);
		if (!claim)
			continue;
		active = fetch_add_u32(&shared->active_workers, 1) + 1;
		atomic_max_u32(&shared->peak_active_workers, active);
		fetch_add_u64(&shared->requested_pages, claim);
		len = snprintf(command, sizeof(command), "%" PRIu64 " swappiness=0",
			       claim * controller->cfg->page_size);
		fd = open_cgroup_file(controller->cgs->batch, "memory.reclaim", O_WRONLY);
		if (fd < 0 || write(fd, command, len) != len) {
			fetch_add_u64(&shared->failed_pages, claim);
		} else {
			uint64_t now = now_ns(), zero = 0;

			__atomic_compare_exchange_n(&shared->first_reclaim_ns, &zero, now, false,
							    __ATOMIC_RELAXED, __ATOMIC_RELAXED);
		}
		if (fd >= 0)
			close(fd);
		fetch_add_u32(&shared->active_workers, -1U);
	}
	return NULL;
}

static int userspace_control_step(struct userspace_controller *controller)
{
	const struct config *cfg = controller->cfg;
	struct shared_state *shared = controller->shared;
	uint64_t batch_pages, parent_pages, service_refaults;
	uint64_t completed, new_work, parent_error;
	uint64_t old_pending, pending, refault_delta, refault_error, desired;
	char stat_buf[16384];
	uint32_t current;
	int err;

	err = read_current_pages(controller->parent_current_fd, cfg->page_size,
				 &parent_pages);
	if (err)
		return err;
	err = read_current_pages(controller->batch_current_fd, cfg->page_size,
				 &batch_pages);
	if (err)
		return err;
	err = pread_text(controller->service_stat_fd, stat_buf, sizeof(stat_buf));
	if (err)
		return err;
	service_refaults = key_value(stat_buf, "workingset_refault_file");
	if (service_refaults == MISSING)
		return -EINVAL;

	completed = load_u64(&shared->requested_pages) - controller->last_requested_pages;
	controller->last_requested_pages = load_u64(&shared->requested_pages);
	if (!controller->capacity_pages)
		controller->capacity_pages = cfg->minimum_capacity_pages;
	controller->capacity_pages = (controller->capacity_pages * 3 + completed) / 4;
	if (controller->capacity_pages < cfg->minimum_capacity_pages)
		controller->capacity_pages = cfg->minimum_capacity_pages;

	parent_error = parent_pages > cfg->parent_target / cfg->page_size +
				     cfg->minimum_capacity_pages ?
		parent_pages - cfg->parent_target / cfg->page_size : 0;
	refault_delta = load_u64(&shared->controller_epochs) &&
		service_refaults > controller->last_service_refaults ?
		service_refaults - controller->last_service_refaults : 0;
	refault_error = refault_delta > cfg->refault_budget ?
		refault_delta - cfg->refault_budget : 0;
	new_work = parent_error / (cfg->recovery_epochs ? cfg->recovery_epochs : 1);
	new_work = saturating_add(new_work, saturating_mul(refault_error, cfg->refault_gain,
							  cfg->max_pending_pages),
				  cfg->max_pending_pages);
	pending = userspace_enqueue(controller, new_work, &old_pending);
	desired = pending ?
		(pending + controller->capacity_pages - 1) / controller->capacity_pages : 0;
	if (desired > cfg->pool_size)
		desired = cfg->pool_size;

	current = load_u32(&shared->desired_workers);
	if (desired > current) {
		current = desired;
		controller->healthy_epochs = 0;
	} else if (desired < current) {
		if (!parent_error && refault_delta <= cfg->refault_budget &&
		    pending <= old_pending)
			controller->healthy_epochs++;
		else
			controller->healthy_epochs = 0;
		if (controller->healthy_epochs >=
		    (cfg->scalein_epochs ? cfg->scalein_epochs : 1)) {
			current--;
			controller->healthy_epochs = 0;
		}
	} else {
		controller->healthy_epochs = 0;
	}
	store_u32(&shared->desired_workers, current);
	atomic_max_u32(&shared->peak_desired_workers, current);
	if (pending && current) {
		fetch_add_u64(&shared->worker_wakeups, 1);
		pthread_mutex_lock(&controller->lock);
		pthread_cond_broadcast(&controller->cond);
		pthread_mutex_unlock(&controller->lock);
	}
	controller->last_batch_pages = batch_pages;
	controller->last_service_refaults = service_refaults;
	fetch_add_u64(&shared->controller_epochs, 1);
	return 0;
}

struct controller_args {
	const struct config *cfg;
	const struct cgroup_paths *cgs;
	struct shared_state *shared;
};

static void userspace_controller_close(struct userspace_controller *controller)
{
	if (controller->parent_current_fd >= 0)
		close(controller->parent_current_fd);
	if (controller->batch_current_fd >= 0)
		close(controller->batch_current_fd);
	if (controller->service_stat_fd >= 0)
		close(controller->service_stat_fd);
	pthread_cond_destroy(&controller->cond);
	pthread_mutex_destroy(&controller->lock);
}

static int userspace_controller_main(void *data)
{
	struct controller_args *arg = data;
	struct userspace_controller controller = {
		.cfg = arg->cfg,
		.cgs = arg->cgs,
		.shared = arg->shared,
		.parent_current_fd = -1,
		.batch_current_fd = -1,
		.service_stat_fd = -1,
	};
	uint64_t next, cpu_start;
	int err = 0, i;

	pthread_mutex_init(&controller.lock, NULL);
	pthread_cond_init(&controller.cond, NULL);
	controller.parent_current_fd = open_cgroup_file(arg->cgs->parent, "memory.current",
						       O_RDONLY);
	controller.batch_current_fd = open_cgroup_file(arg->cgs->batch, "memory.current",
						      O_RDONLY);
	controller.service_stat_fd = open_cgroup_file(arg->cgs->service, "memory.stat",
						     O_RDONLY);
	if (controller.parent_current_fd < 0 || controller.batch_current_fd < 0 ||
	    controller.service_stat_fd < 0) {
		err = -errno;
		goto out;
	}
	for (i = 0; i < arg->cfg->pool_size; i++) {
		controller.workers[i].controller = &controller;
		controller.workers[i].slot = i;
		err = pthread_create(&controller.threads[i], NULL, userspace_worker_main,
				     &controller.workers[i]);
		if (err) {
			err = -err;
			goto stop_workers;
		}
	}
	store_u32(&arg->shared->controller_ready, 1);
	while (!load_u32(&arg->shared->start) && !load_u32(&arg->shared->stop))
		sched_yield();
	cpu_start = process_cpu_ns();
	next = load_u64(&arg->shared->start_ns);
	if (next > now_ns())
		sleep_until(next);
	while (!load_u32(&arg->shared->stop)) {
		err = userspace_control_step(&controller);
		if (err)
			break;
		next += arg->cfg->epoch_ns;
		sleep_until(next);
	}
	store_u64(&arg->shared->controller_cpu_ns, process_cpu_ns() - cpu_start);

stop_workers:
	controller.stop = 1;
	pthread_mutex_lock(&controller.lock);
	pthread_cond_broadcast(&controller.cond);
	pthread_mutex_unlock(&controller.lock);
	while (i-- > 0)
		pthread_join(controller.threads[i], NULL);
out:
	userspace_controller_close(&controller);
	return err;
}

static int run_bpf_syscall(struct bpf_program *program)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(program), &opts);
	if (err)
		return -errno;
	return (int32_t)opts.retval;
}

static int start_bpf_controller(struct bench_memcg_reclaim **skel_out,
				const struct config *cfg, const struct cgroup_paths *cgs,
				enum bench_mode mode)
{
	struct bench_memcg_reclaim *skel;
	uint64_t parent_id, service_id, batch_id;
	int err;

	parent_id = cgroup_id(cgs->parent);
	service_id = cgroup_id(cgs->service);
	batch_id = cgroup_id(cgs->batch);
	if (!parent_id || !service_id || !batch_id)
		return -ENOENT;

	skel = bench_memcg_reclaim__open();
	if (!skel)
		return -errno;
	skel->bss->parent_cgroup_id = parent_id;
	skel->bss->service_cgroup_id = service_id;
	skel->bss->batch_cgroup_id = batch_id;
	skel->bss->parent_target_pages = cfg->parent_target / cfg->page_size;
	skel->bss->page_size = cfg->page_size;
	skel->bss->epoch_ns = cfg->epoch_ns;
	skel->bss->reclaim_quantum_pages = cfg->quantum_pages;
	skel->bss->max_pending_pages = cfg->max_pending_pages;
	skel->bss->minimum_capacity_pages = cfg->minimum_capacity_pages;
	skel->bss->refault_budget = cfg->refault_budget;
	skel->bss->refault_gain = cfg->refault_gain;
	skel->bss->recovery_epochs = cfg->recovery_epochs;
	skel->bss->scalein_epochs = cfg->scalein_epochs;
	skel->bss->pool_size = cfg->pool_size;
	if (mode == MODE_BPF_FIXED_ONE)
		skel->bss->fixed_concurrency = 1;
	else if (mode == MODE_BPF_FIXED_MAX)
		skel->bss->fixed_concurrency = cfg->pool_size;
	err = bench_memcg_reclaim__load(skel);
	if (err)
		goto out;
	err = run_bpf_syscall(skel->progs.start_pool);
	if (err) {
		run_bpf_syscall(skel->progs.stop_pool);
		goto out;
	}
	if (skel->bss->pool_started != cfg->pool_size) {
		err = -EINVAL;
		run_bpf_syscall(skel->progs.stop_pool);
		goto out;
	}
	*skel_out = skel;
	return 0;
out:
	bench_memcg_reclaim__destroy(skel);
	return err;
}

static int stop_bpf_controller(struct bench_memcg_reclaim *skel)
{
	skel->bss->control_enabled = 0;
	return run_bpf_syscall(skel->progs.stop_pool);
}

static struct shared_state *alloc_shared(void)
{
	struct shared_state *shared;

	shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared == MAP_FAILED)
		return NULL;
	memset(shared, 0, sizeof(*shared));
	return shared;
}

static int calibrate_service(const struct config *cfg, const struct cgroup_paths *cgs,
			     uint64_t seed, uint64_t *p99)
{
	struct shared_state *shared;
	struct service_args args;
	struct child_proc service = { .release_fd = -1 };
	uint64_t duration = 2 * NS_PER_SEC * cfg->duration_scale;
	int err;

	shared = alloc_shared();
	if (!shared)
		return -errno;
	signal_shared = shared;
	store_u64(&shared->slo_ns, UINT64_MAX);
	args = (struct service_args) {
		.cfg = cfg,
		.shared = shared,
		.seed = seed,
	};
	err = spawn_child(&service, cgs->service, service_main, &args);
	if (err)
		goto out;
	err = release_child(&service);
	if (err)
		goto stop;
	err = wait_ready(&shared->service_ready, 120);
	if (err)
		goto stop;
	store_u64(&shared->start_ns, now_ns() + 100 * NS_PER_MSEC);
	store_u32(&shared->start, 1);
	sleep_until(load_u64(&shared->start_ns) + duration);
stop:
	store_u32(&shared->stop, 1);
	if (service.release_fd >= 0)
		close(service.release_fd);
	if (reap_child(&service, 10000) && !err)
		err = -ECHILD;
	if (!err) {
		*p99 = histogram_percentile(shared->service_hist, 99);
		if (!*p99)
			err = -ENODATA;
	}
out:
	signal_shared = NULL;
	munmap(shared, sizeof(*shared));
	reset_file_cache(cfg->service_file);
	return err;
}

static int wait_memory_drain(const struct cgroup_paths *cgs, uint64_t threshold)
{
	char path[PATH_MAX], buf[64];
	uint64_t deadline = now_ns() + 10 * NS_PER_SEC;

	if (path_join(path, sizeof(path), cgs->parent, "memory.current"))
		return -ENAMETOOLONG;
	while (now_ns() < deadline) {
		if (!read_file(path, buf, sizeof(buf)) &&
		    strtoull(buf, NULL, 10) <= threshold)
			return 0;
		usleep(100000);
	}
	return -ETIMEDOUT;
}

struct system_metrics {
	struct cg_metrics parent;
	struct cg_metrics service;
	struct cg_metrics batch;
	struct vm_metrics vm;
};

static int read_system_metrics(const struct cgroup_paths *cgs, struct system_metrics *metrics)
{
	int err;

	err = read_cg_metrics(cgs->parent, &metrics->parent);
	if (err)
		return err;
	err = read_cg_metrics(cgs->service, &metrics->service);
	if (err)
		return err;
	err = read_cg_metrics(cgs->batch, &metrics->batch);
	if (err)
		return err;
	err = read_vm_metrics(&metrics->vm);
	if (err)
		return err;
	return 0;
}

static void write_csv_header(FILE *samples)
{
	fprintf(samples,
		"repetition,mode,elapsed_ms,phase,service_ops,service_ops_per_sec,"
		"service_p50_ns,service_p95_ns,service_p99_ns,service_max_ns,"
		"service_slo_violations,parent_memory_current,service_memory_current,"
		"batch_memory_current,parent_high_events,parent_max_events,"
		"parent_oom_events,parent_oom_kills,service_refault_file,"
		"batch_refault_file,parent_pgscan_direct,parent_pgsteal_direct,"
		"service_psi_some_usec,service_psi_full_usec,batch_psi_some_usec,"
		"batch_psi_full_usec,service_cpu_usec,batch_cpu_usec,batch_pages,"
		"controller_authorized_pages,controller_pending_pages,"
		"controller_requested_pages,controller_reclaimed_pages,"
		"controller_failed_pages,controller_active_workers,"
		"controller_desired_workers,controller_wakeups,controller_sleeps,"
		"controller_claim_conflicts,pgscan_kswapd,pgsteal_kswapd,"
		"pgscan_direct,pgsteal_direct\n");
}

static void write_sample(FILE *samples, int repetition, enum bench_mode mode,
			 uint64_t elapsed, enum phase phase, uint64_t epoch_ns,
			 const uint64_t *hist, uint64_t operations, uint64_t maximum,
			 uint64_t slo_violations, uint64_t batch_pages,
			 const struct system_metrics *current,
			 const struct system_metrics *previous,
			 const struct controller_metrics *controller,
			 const struct controller_metrics *previous_controller)
{
	uint64_t p50 = histogram_percentile(hist, 50);
	uint64_t p95 = histogram_percentile(hist, 95);
	uint64_t p99 = histogram_percentile(hist, 99);
	uint64_t rate = epoch_ns ? operations * NS_PER_SEC / epoch_ns : 0;

	fprintf(samples, "%d,%s,%" PRIu64 ",%s,%" PRIu64 ",%" PRIu64 ",%" PRIu64
		",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
		",%" PRIu64 ",%" PRIu64 ",",
		repetition, mode_name(mode), (uint64_t)(elapsed / NS_PER_MSEC),
		phase_name(phase),
		operations, rate, p50, p95, p99, maximum, slo_violations,
		current->parent.memory_current, current->service.memory_current,
		current->batch.memory_current);
	csv_value(samples, metric_delta(current->parent.high, previous->parent.high));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->parent.max, previous->parent.max));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->parent.oom, previous->parent.oom));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->parent.oom_kill, previous->parent.oom_kill));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->service.refault_file,
					previous->service.refault_file));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->batch.refault_file,
					previous->batch.refault_file));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->parent.pgscan_direct,
					previous->parent.pgscan_direct));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->parent.pgsteal_direct,
					previous->parent.pgsteal_direct));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->service.psi_some, previous->service.psi_some));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->service.psi_full, previous->service.psi_full));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->batch.psi_some, previous->batch.psi_some));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->batch.psi_full, previous->batch.psi_full));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->service.cpu_usage,
					previous->service.cpu_usage));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->batch.cpu_usage, previous->batch.cpu_usage));
	fprintf(samples, ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",",
		batch_pages, controller->authorized - previous_controller->authorized,
		controller->pending, controller->requested - previous_controller->requested);
	if (controller->reclaimed != MISSING && previous_controller->reclaimed != MISSING)
		fprintf(samples, "%" PRIu64,
			controller->reclaimed - previous_controller->reclaimed);
	fprintf(samples, ",%" PRIu64 ",%u,%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",",
		controller->failed - previous_controller->failed, controller->active,
		controller->desired, controller->wakeups - previous_controller->wakeups,
		controller->sleeps - previous_controller->sleeps,
		controller->conflicts - previous_controller->conflicts);
	csv_value(samples, metric_delta(current->vm.pgscan_kswapd,
					previous->vm.pgscan_kswapd));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->vm.pgsteal_kswapd,
					previous->vm.pgsteal_kswapd));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->vm.pgscan_direct,
					previous->vm.pgscan_direct));
	fputc(',', samples);
	csv_value(samples, metric_delta(current->vm.pgsteal_direct,
					previous->vm.pgsteal_direct));
	fputc('\n', samples);
	fflush(samples);
}

static int run_trial(const struct config *cfg, const struct cgroup_paths *cgs,
		     enum bench_mode mode, int repetition, uint64_t seed,
		     uint64_t calibration_p99_ns, uint64_t slo_ns,
		     FILE *samples, const char *raw_dir, struct trial_result *result)
{
	struct controller_metrics controller = {}, previous_controller = {};
	struct bench_memcg_reclaim *skel = NULL;
	struct child_proc service = { .release_fd = -1 };
	struct child_proc batch[MAX_BATCH_THREADS] = {};
	struct child_proc userspace = { .release_fd = -1 };
	struct child_proc prefill = { .release_fd = -1 };
	struct child_proc memtier = { .release_fd = -1 };
	struct system_metrics initial, previous, current, final;
	struct shared_state *shared = NULL;
	struct controller_args controller_args;
	struct service_args service_args;
	struct batch_args batch_args[MAX_BATCH_THREADS];
	struct memcached_args memcached_args;
	struct memtier_args prefill_args, memtier_args;
	uint64_t previous_hist[LATENCY_BUCKETS] = {};
	uint64_t histogram[LATENCY_BUCKETS], previous_ops = 0, previous_batch = 0;
	uint64_t previous_slo = 0, start, deadline, duration;
	char raw_prefix[64], memcached_log[PATH_MAX], prefill_log[PATH_MAX];
	char prefill_json[PATH_MAX], memtier_log[PATH_MAX], memtier_json[PATH_MAX];
	int err = 0, child_err, i;
	bool workloads_started = false;
	bool have_initial_metrics = false;

	for (i = 0; i < MAX_BATCH_THREADS; i++)
		batch[i].release_fd = -1;
	memset(result, 0, sizeof(*result));
	result->mode = mode;
	result->repetition = repetition;
	result->calibration_p99_ns = calibration_p99_ns;
	result->slo_ns = slo_ns;
	write_number(cgs->service, "memory.low",
		     mode == MODE_MEMORY_LOW ? cfg->service_hot_size : 0);
	if (!cfg->memcached)
		reset_file_cache(cfg->service_file);
	reset_file_cache(cfg->batch_file);
	wait_memory_drain(cgs, 64ULL << 20);

	shared = alloc_shared();
	if (!shared)
		return -errno;
	signal_shared = shared;
	store_u64(&shared->slo_ns, slo_ns);
	service_args = (struct service_args) {
		.cfg = cfg,
		.shared = shared,
		.seed = seed,
	};
	controller_args = (struct controller_args) {
		.cfg = cfg,
		.cgs = cgs,
		.shared = shared,
	};

	if (mode_uses_bpf(mode)) {
		err = start_bpf_controller(&skel, cfg, cgs, mode);
		if (err)
			goto out;
	}
	if (cfg->memcached) {
		snprintf(memcached_log, sizeof(memcached_log), "%s/logs/rep%d-%s-memcached.log",
			 cfg->output, repetition, mode_name(mode));
		snprintf(prefill_log, sizeof(prefill_log), "%s/logs/rep%d-%s-prefill.log",
			 cfg->output, repetition, mode_name(mode));
		snprintf(prefill_json, sizeof(prefill_json),
			 "%s/memtier/rep%d-%s-prefill.json", cfg->output, repetition,
			 mode_name(mode));
		snprintf(memtier_log, sizeof(memtier_log), "%s/logs/rep%d-%s-memtier.log",
			 cfg->output, repetition, mode_name(mode));
		snprintf(memtier_json, sizeof(memtier_json), "%s/memtier/rep%d-%s.json",
			 cfg->output, repetition, mode_name(mode));
		memcached_args = (struct memcached_args) {
			.cfg = cfg,
			.log_path = memcached_log,
		};
		prefill_args = (struct memtier_args) {
			.cfg = cfg,
			.json_path = prefill_json,
			.log_path = prefill_log,
			.prefill = true,
		};
		memtier_args = (struct memtier_args) {
			.cfg = cfg,
			.json_path = memtier_json,
			.log_path = memtier_log,
			.duration_seconds = (total_duration(cfg) + NS_PER_SEC - 1) /
				NS_PER_SEC,
		};
		err = spawn_child(&service, cgs->service, memcached_main, &memcached_args);
		if (err)
			goto stop;
		err = release_child(&service);
		if (err)
			goto stop;
		err = wait_for_memcached(cfg);
		if (err)
			goto stop;
		err = spawn_child(&prefill, cgs->loadgen, memtier_main, &prefill_args);
		if (err)
			goto stop;
		err = release_child(&prefill);
		if (err)
			goto stop;
		err = reap_child(&prefill, 20 * 60 * 1000);
		if (err)
			goto stop;
		store_u32(&shared->service_ready, 1);
	} else {
		err = spawn_child(&service, cgs->service, service_main, &service_args);
		if (err)
			goto stop;
		err = release_child(&service);
		if (err)
			goto stop;
	}
	for (i = 0; i < cfg->batch_threads; i++) {
		batch_args[i] = (struct batch_args) {
			.cfg = cfg,
			.shared = shared,
			.worker = i,
		};
		err = spawn_child(&batch[i], cgs->batch, batch_main, &batch_args[i]);
		if (err)
			goto stop;
		err = release_child(&batch[i]);
		if (err)
			goto stop;
	}
	if (mode == MODE_USERSPACE) {
		err = spawn_child(&userspace, cgs->batch, userspace_controller_main,
				  &controller_args);
		if (err)
			goto stop;
		err = release_child(&userspace);
		if (err)
			goto stop;
	}
	if (cfg->memcached) {
		err = spawn_child(&memtier, cgs->loadgen, memtier_main, &memtier_args);
		if (err)
			goto stop;
	}
	err = wait_ready(&shared->service_ready, 120);
	if (err)
		goto stop;
	err = wait_ready_count(&shared->batch_ready, cfg->batch_threads, 30);
	if (err)
		goto stop;
	if (mode == MODE_USERSPACE) {
		err = wait_ready(&shared->controller_ready, 30);
		if (err)
			goto stop;
	}
	err = read_system_metrics(cgs, &initial);
	if (err)
		goto stop;
	have_initial_metrics = true;
	previous = initial;
	if (mode_uses_bpf(mode))
		read_bpf_controller(skel, &previous_controller);
	else if (mode == MODE_USERSPACE)
		read_shared_controller(shared, &previous_controller);
	else
		previous_controller.reclaimed = MISSING;

	start = now_ns() + (cfg->memcached ? 500 : 100) * NS_PER_MSEC;
	store_u64(&shared->start_ns, start);
	store_u32(&shared->start, 1);
	if (cfg->memcached) {
		err = release_child(&memtier);
		if (err)
			goto stop;
	}
	if (skel) {
		sleep_until(start);
		err = run_bpf_syscall(skel->progs.enable_pool);
		if (err)
			goto stop;
	}
	workloads_started = true;
	duration = total_duration(cfg);
	deadline = start + cfg->epoch_ns;
	while (!interrupted && deadline <= start + duration) {
		uint64_t operations, batch_delta, slo_delta, maximum;
		uint64_t elapsed = deadline - start;
		enum phase phase = phase_at(cfg, elapsed ? elapsed - 1 : 0, NULL);

		sleep_until(deadline);
		err = read_system_metrics(cgs, &current);
		if (err)
			break;
		for (i = 0; i < LATENCY_BUCKETS; i++) {
			uint64_t value = load_u64(&shared->service_hist[i]);

			histogram[i] = value - previous_hist[i];
			previous_hist[i] = value;
		}
		operations = load_u64(&shared->service_ops) - previous_ops;
		previous_ops = load_u64(&shared->service_ops);
		batch_delta = load_u64(&shared->batch_pages) - previous_batch;
		previous_batch = load_u64(&shared->batch_pages);
		slo_delta = load_u64(&shared->service_slo_violations) - previous_slo;
		previous_slo = load_u64(&shared->service_slo_violations);
		maximum = __atomic_exchange_n(&shared->service_epoch_max_ns, 0,
					      __ATOMIC_RELAXED);
		if (mode_uses_bpf(mode))
			read_bpf_controller(skel, &controller);
		else if (mode == MODE_USERSPACE)
			read_shared_controller(shared, &controller);
		else {
			memset(&controller, 0, sizeof(controller));
			controller.reclaimed = MISSING;
		}
		write_sample(samples, repetition, mode, elapsed, phase, cfg->epoch_ns,
			     histogram, operations, maximum, slo_delta, batch_delta,
			     &current, &previous, &controller, &previous_controller);
		if (histogram_percentile(histogram, 99) > slo_ns)
			result->slo_epochs++;
		previous = current;
		previous_controller = controller;
		deadline += cfg->epoch_ns;
	}

stop:
	store_u32(&shared->stop, 1);
	if (skel)
		skel->bss->control_enabled = 0;
	if (userspace.release_fd >= 0)
		close(userspace.release_fd);
	if (prefill.release_fd >= 0)
		close(prefill.release_fd);
	if (memtier.release_fd >= 0)
		close(memtier.release_fd);
	if (service.release_fd >= 0)
		close(service.release_fd);
	for (i = 0; i < cfg->batch_threads; i++) {
		if (batch[i].release_fd >= 0)
			close(batch[i].release_fd);
	}
	child_err = reap_child(&userspace, 10000);
	if (child_err && !err && mode == MODE_USERSPACE)
		err = child_err;
	for (i = 0; i < cfg->batch_threads; i++) {
		child_err = reap_child(&batch[i], 10000);
		if (child_err && !err)
			err = child_err;
	}
	child_err = reap_child(&prefill, 10000);
	if (child_err && !err)
		err = child_err;
	child_err = reap_child(&memtier, 60000);
	if (child_err && !err)
		err = child_err;
	if (cfg->memcached)
		child_err = stop_external_child(&service, 10000);
	else
		child_err = reap_child(&service, 10000);
	if (child_err && !err)
		err = child_err;
	if (skel) {
		child_err = stop_bpf_controller(skel);
		if (child_err && !err)
			err = child_err;
		read_bpf_controller(skel, &controller);
	} else if (mode == MODE_USERSPACE) {
		read_shared_controller(shared, &controller);
	}
	if (have_initial_metrics && !read_system_metrics(cgs, &final)) {
		result->high_events = metric_delta(final.parent.high, initial.parent.high);
		result->oom_kills = metric_delta(final.parent.oom_kill, initial.parent.oom_kill);
		result->service_refaults =
			metric_delta(final.service.refault_file, initial.service.refault_file);
		result->direct_scans =
			metric_delta(final.parent.pgscan_direct, initial.parent.pgscan_direct);
		result->kswapd_scans =
			metric_delta(final.vm.pgscan_kswapd, initial.vm.pgscan_kswapd);
		result->batch_cpu_usec =
			metric_delta(final.batch.cpu_usage, initial.batch.cpu_usage);
	}
	result->service_ops = load_u64(&shared->service_ops);
	result->service_p99_ns = histogram_percentile(shared->service_hist, 99);
	result->service_max_ns = load_u64(&shared->service_max_ns);
	result->batch_pages = load_u64(&shared->batch_pages);
	result->controller = controller;

	if (result->oom_kills && result->oom_kills != MISSING) {
		result->inconclusive = true;
		snprintf(result->warning, sizeof(result->warning), "OOM kill occurred");
	} else if (mode == MODE_KERNEL && !result->high_events) {
		result->inconclusive = true;
		snprintf(result->warning, sizeof(result->warning),
			 "kernel baseline never crossed memory.high");
	} else if ((mode == MODE_USERSPACE || mode_uses_bpf(mode)) &&
		   controller.authorized != controller.requested + controller.pending) {
		result->inconclusive = true;
		snprintf(result->warning, sizeof(result->warning),
			 "controller debt accounting mismatch");
	} else if (mode == MODE_BPF &&
		   (controller.peak_desired < 2 || controller.desired != 0)) {
		result->inconclusive = true;
		snprintf(result->warning, sizeof(result->warning),
			 "BPF pool did not scale out and back in");
	}
	if (skel && !result->inconclusive) {
		uint64_t batch_id = cgroup_id(cgs->batch);

		if (controller.pool_started != cfg->pool_size ||
		    controller.pool_stopped != cfg->pool_size) {
			result->inconclusive = true;
			snprintf(result->warning, sizeof(result->warning),
				 "BPF fixed-pool lifecycle counters are inconsistent");
		}
		for (i = 0; i < cfg->pool_size && !result->inconclusive; i++) {
			if (skel->bss->worker_cgroup_ids[i] != batch_id) {
				result->inconclusive = true;
				snprintf(result->warning, sizeof(result->warning),
					 "BPF worker %d ran outside the batch cgroup", i);
			}
		}
	}
	snprintf(raw_prefix, sizeof(raw_prefix), "rep%d-%s-final", repetition,
		 mode_name(mode));
	snapshot_raw_metrics(raw_dir, raw_prefix, cgs);

out:
	if (skel)
		bench_memcg_reclaim__destroy(skel);
	signal_shared = NULL;
	if (shared)
		munmap(shared, sizeof(*shared));
	if (!cfg->memcached)
		reset_file_cache(cfg->service_file);
	reset_file_cache(cfg->batch_file);
	wait_memory_drain(cgs, 64ULL << 20);
	if (err && workloads_started && cfg->verbose)
		fprintf(stderr, "%s trial stopped with error: %s\n", mode_name(mode),
			strerror(-err));
	return err;
}

static int write_config_json(const struct config *cfg, uint64_t seed)
{
	char path[PATH_MAX];
	FILE *file;
	int i;

	if (path_join(path, sizeof(path), cfg->output, "config.json"))
		return -ENAMETOOLONG;
	file = fopen(path, "w");
	if (!file)
		return -errno;
	fprintf(file,
		"{\n"
		"  \"seed\": %" PRIu64 ",\n"
		"  \"repeat\": %d,\n"
		"  \"duration_scale\": %.3f,\n"
		"  \"batch_threads\": %d,\n"
		"  \"batch_file\": \"%s\",\n"
		"  \"reuse_batch_file\": %s,\n"
		"  \"workload\": \"%s\",\n"
		"  \"memcached_binary\": \"%s\",\n"
		"  \"memtier_binary\": \"%s\",\n"
		"  \"memcached_port\": %d,\n"
		"  \"memcached_threads\": %d,\n"
		"  \"memtier_threads\": %d,\n"
		"  \"memtier_clients\": %d,\n"
		"  \"memtier_rate\": %" PRIu64 ",\n"
		"  \"memcached_memory\": %" PRIu64 ",\n"
		"  \"memcached_data_size\": %" PRIu64 ",\n"
		"  \"memcached_value_size\": %" PRIu64 ",\n"
		"  \"memcached_key_count\": %" PRIu64 ",\n"
		"  \"page_size\": %" PRIu64 ",\n"
		"  \"host_memory\": %" PRIu64 ",\n"
		"  \"parent_max\": %" PRIu64 ",\n"
		"  \"parent_high\": %" PRIu64 ",\n"
		"  \"parent_target\": %" PRIu64 ",\n"
		"  \"service_file_size\": %" PRIu64 ",\n"
		"  \"service_hot_size\": %" PRIu64 ",\n"
		"  \"batch_file_size\": %" PRIu64 ",\n"
		"  \"epoch_ns\": %" PRIu64 ",\n"
		"  \"pool_size\": %d,\n"
		"  \"quantum_pages\": %" PRIu64 ",\n"
		"  \"maximum_pending_pages\": %" PRIu64 ",\n"
		"  \"minimum_capacity_pages\": %" PRIu64 ",\n"
		"  \"refault_budget\": %" PRIu64 ",\n"
		"  \"refault_gain\": %u,\n"
		"  \"recovery_epochs\": %u,\n"
		"  \"scalein_epochs\": %u,\n"
		"  \"service_rate\": %" PRIu64 ",\n"
		"  \"phase_duration_ns\": [%" PRIu64 ", %" PRIu64 ", %" PRIu64
		", %" PRIu64 "],\n"
		"  \"batch_rate_pages_per_sec\": [%" PRIu64 ", %" PRIu64 ", %" PRIu64
		", %" PRIu64 "],\n"
		"  \"modes\": [",
		seed, cfg->repeat, cfg->duration_scale, cfg->batch_threads, cfg->batch_file,
		cfg->reuse_batch_file ? "true" : "false",
		cfg->memcached ? "memcached" : "synthetic",
		cfg->memcached_binary, cfg->memtier_binary, cfg->memcached_port,
		cfg->memcached_threads, cfg->memtier_threads, cfg->memtier_clients,
		cfg->memtier_rate, cfg->memcached_memory, cfg->memcached_data_size,
		cfg->memcached_value_size, cfg->memcached_key_count,
		cfg->page_size, cfg->host_memory,
		cfg->parent_max, cfg->parent_high, cfg->parent_target,
		cfg->service_file_size, cfg->service_hot_size, cfg->batch_file_size,
		cfg->epoch_ns, cfg->pool_size, cfg->quantum_pages, cfg->max_pending_pages,
		cfg->minimum_capacity_pages, cfg->refault_budget, cfg->refault_gain,
		cfg->recovery_epochs, cfg->scalein_epochs, cfg->service_rate,
		cfg->phase_ns[0], cfg->phase_ns[1], cfg->phase_ns[2], cfg->phase_ns[3],
		cfg->batch_rate[0], cfg->batch_rate[1], cfg->batch_rate[2],
		cfg->batch_rate[3]);
	for (i = 0; i < cfg->mode_count; i++)
		fprintf(file, "%s\"%s\"", i ? ", " : "", mode_name(cfg->modes[i]));
	fprintf(file, "]\n}\n");
	fclose(file);
	return 0;
}

static int write_environment(const struct config *cfg)
{
	struct utsname uts;
	struct statfs fs;
	char path[PATH_MAX], buf[4096];
	FILE *file;
	long cpus = sysconf(_SC_NPROCESSORS_ONLN);

	if (path_join(path, sizeof(path), cfg->output, "environment.txt"))
		return -ENAMETOOLONG;
	file = fopen(path, "w");
	if (!file)
		return -errno;
	uname(&uts);
	statfs(cfg->work_dir, &fs);
	fprintf(file, "kernel_release=%s\nmachine=%s\nonline_cpus=%ld\npage_size=%" PRIu64
		"\nhost_memory=%" PRIu64 "\nfilesystem_magic=0x%lx\ncgroup_mount=/sys/fs/cgroup\n",
		uts.release, uts.machine, cpus, cfg->page_size, cfg->host_memory,
		(unsigned long)fs.f_type);
	if (!read_file("/sys/kernel/mm/lru_gen/enabled", buf, sizeof(buf)))
		fprintf(file, "mglru_enabled=%s", buf);
	if (!read_file("/proc/cmdline", buf, sizeof(buf)))
		fprintf(file, "cmdline=%s", buf);
	fclose(file);
	return 0;
}

static const struct trial_result *find_result(const struct trial_result *results, int count,
					      int repetition, enum bench_mode mode)
{
	int i;

	for (i = 0; i < count; i++) {
		if (results[i].repetition == repetition && results[i].mode == mode)
			return &results[i];
	}
	return NULL;
}

static int64_t signed_difference(uint64_t value, uint64_t baseline)
{
	if (value >= baseline) {
		uint64_t difference = value - baseline;

		return difference > INT64_MAX ? INT64_MAX : difference;
	}
	if (baseline - value > INT64_MAX)
		return INT64_MIN;
	return -(int64_t)(baseline - value);
}

static int write_summaries(const struct config *cfg, const struct trial_result *results,
			   int count)
{
	char json_path[PATH_MAX], text_path[PATH_MAX];
	FILE *json, *text;
	int i;

	if (path_join(json_path, sizeof(json_path), cfg->output, "summary.json") ||
	    path_join(text_path, sizeof(text_path), cfg->output, "summary.txt"))
		return -ENAMETOOLONG;
	json = fopen(json_path, "w");
	text = fopen(text_path, "w");
	if (!json || !text) {
		if (json)
			fclose(json);
		if (text)
			fclose(text);
		return -errno;
	}

	fprintf(json, "{\n  \"trials\": [\n");
	fprintf(text,
		"Adaptive memcg reclaim benchmark\n\n"
		"rep mode         status        p99-us max-us svc-ops batch-pages high "
		"refault direct-scan kswapd-scan peak-slots reclaim-pages\n");
	for (i = 0; i < count; i++) {
		const struct trial_result *result = &results[i];
		const struct trial_result *kernel =
			find_result(results, count, result->repetition, MODE_KERNEL);
		const struct trial_result *userspace =
			find_result(results, count, result->repetition, MODE_USERSPACE);
		int64_t kernel_delta = kernel ?
			signed_difference(result->service_p99_ns, kernel->service_p99_ns) : 0;
		int64_t userspace_delta = userspace ?
			signed_difference(result->service_p99_ns, userspace->service_p99_ns) : 0;

		fprintf(json,
			"    %s{\n"
			"      \"repetition\": %d,\n"
			"      \"mode\": \"%s\",\n"
			"      \"status\": \"%s\",\n"
			"      \"warning\": \"%s\",\n"
			"      \"calibration_p99_ns\": %" PRIu64 ",\n"
			"      \"slo_ns\": %" PRIu64 ",\n"
			"      \"service_ops\": %" PRIu64 ",\n"
			"      \"service_p99_ns\": %" PRIu64 ",\n"
			"      \"service_max_ns\": %" PRIu64 ",\n"
			"      \"slo_violating_epochs\": %" PRIu64 ",\n"
			"      \"batch_pages\": %" PRIu64 ",\n"
			"      \"memory_high_events\": %" PRIu64 ",\n"
			"      \"oom_kills\": %" PRIu64 ",\n"
			"      \"service_refaults\": %" PRIu64 ",\n"
			"      \"direct_scans\": %" PRIu64 ",\n"
			"      \"kswapd_scans\": %" PRIu64 ",\n"
			"      \"batch_cpu_usec\": %" PRIu64 ",\n"
			"      \"authorized_pages\": %" PRIu64 ",\n"
			"      \"pending_pages\": %" PRIu64 ",\n"
			"      \"requested_pages\": %" PRIu64 ",\n",
			i ? ",\n" : "", result->repetition, mode_name(result->mode),
			result->inconclusive ? "inconclusive" : "complete", result->warning,
			result->calibration_p99_ns, result->slo_ns, result->service_ops,
			result->service_p99_ns,
			result->service_max_ns, result->slo_epochs, result->batch_pages,
			result->high_events, result->oom_kills, result->service_refaults,
			result->direct_scans, result->kswapd_scans, result->batch_cpu_usec,
			result->controller.authorized, result->controller.pending,
			result->controller.requested);
		if (result->controller.reclaimed == MISSING)
			fprintf(json, "      \"reclaimed_pages\": null,\n");
		else
			fprintf(json, "      \"reclaimed_pages\": %" PRIu64 ",\n",
				result->controller.reclaimed);
		fprintf(json,
			"      \"failed_pages\": %" PRIu64 ",\n"
			"      \"peak_active_workers\": %u,\n"
			"      \"peak_desired_workers\": %u,\n",
			result->controller.failed, result->controller.peak_active,
			result->controller.peak_desired);
		if (kernel)
			fprintf(json, "      \"p99_delta_vs_kernel_ns\": %" PRId64 ",\n",
				kernel_delta);
		else
			fprintf(json, "      \"p99_delta_vs_kernel_ns\": null,\n");
		if (userspace)
			fprintf(json, "      \"p99_delta_vs_userspace_ns\": %" PRId64 "\n",
				userspace_delta);
		else
			fprintf(json, "      \"p99_delta_vs_userspace_ns\": null\n");
		fprintf(json, "    }");
		fprintf(text, "%3d %-12s %-13s %6" PRIu64 " %6" PRIu64 " %7" PRIu64
			" %11" PRIu64 " %4" PRIu64 " %7" PRIu64 " %11" PRIu64
			" %11" PRIu64 " %12u ",
			result->repetition, mode_name(result->mode),
			result->inconclusive ? "inconclusive" : "complete",
			result->service_p99_ns / 1000, result->service_max_ns / 1000,
			result->service_ops, result->batch_pages, result->high_events,
			result->service_refaults, result->direct_scans, result->kswapd_scans,
			result->controller.peak_desired);
		if (result->controller.reclaimed == MISSING)
			fprintf(text, "n/a");
		else
			fprintf(text, "%" PRIu64, result->controller.reclaimed);
		if (result->warning[0])
			fprintf(text, "  # %s", result->warning);
		fputc('\n', text);
	}
	fprintf(json, "\n  ]\n}\n");
	fclose(json);
	fclose(text);
	return 0;
}

static int write_status(const struct config *cfg, const char *status, const char *detail)
{
	char path[PATH_MAX];
	FILE *file;

	if (path_join(path, sizeof(path), cfg->output, "status"))
		return -ENAMETOOLONG;
	file = fopen(path, "w");
	if (!file)
		return -errno;
	fprintf(file, "%s\n%s\n", status, detail ? detail : "");
	fclose(file);
	return 0;
}

int main(int argc, char **argv)
{
	struct config cfg = {
		.repeat = 1,
		.pool_size = MAX_WORKERS,
		.duration_scale = 1.0,
		.memcached_port = 11213,
		.memcached_threads = 8,
		.memtier_threads = 4,
		.memtier_clients = 4,
		.memcached_value_size = 1024,
		.memtier_rate = 600000,
		.modes = { MODE_KERNEL, MODE_MEMORY_LOW, MODE_USERSPACE, MODE_BPF },
		.mode_count = 4,
	};
	struct cgroup_paths cgs = {};
	struct trial_result *results = NULL;
	char raw_dir[PATH_MAX], samples_path[PATH_MAX], status_detail[256] = {};
	char logs_dir[PATH_MAX], memtier_dir[PATH_MAX];
	char service_leaf[64], batch_leaf[64];
	uint64_t seed = 1, calibration_p99, slo_ns;
	FILE *samples = NULL;
	int result_count = 0, trial_count, failures = 0, inconclusive = 0;
	int err, repetition, mode_index;
	bool cgroups_created = false;

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	if (geteuid()) {
		fprintf(stderr, "bench_memcg_reclaim must run as root\n");
		return 1;
	}
	snprintf(cfg.work_dir, sizeof(cfg.work_dir), "/var/tmp");
	snprintf(cfg.memcached_binary, sizeof(cfg.memcached_binary), "/usr/bin/memcached");
	snprintf(cfg.memtier_binary, sizeof(cfg.memtier_binary),
		 "/usr/local/bin/memtier_benchmark");
	err = parse_options(&cfg, argc, argv, &seed);
	if (err) {
		usage(stderr, argv[0]);
		return 1;
	}
	if (!cfg.output[0])
		snprintf(cfg.output, sizeof(cfg.output), "%s/memcg-reclaim-%d",
			 cfg.work_dir, getpid());
	err = resolve_config(&cfg);
	if (err) {
		if (err == -EOPNOTSUPP)
			fprintf(stderr, "work directory must be on a non-tmpfs filesystem\n");
		else
			fprintf(stderr, "invalid benchmark configuration: %s\n", strerror(-err));
		return err == -EOPNOTSUPP ? 4 : 1;
	}
	snprintf(service_leaf, sizeof(service_leaf), "memcg-reclaim-service.%d.dat", getpid());
	snprintf(batch_leaf, sizeof(batch_leaf), "memcg-reclaim-batch.%d.dat", getpid());
	err = mkdir_one(cfg.output);
	if (!err)
		err = path_join(raw_dir, sizeof(raw_dir), cfg.output, "raw");
	if (!err)
		err = mkdir_one(raw_dir);
	if (!err)
		err = path_join(logs_dir, sizeof(logs_dir), cfg.output, "logs");
	if (!err)
		err = mkdir_one(logs_dir);
	if (!err)
		err = path_join(memtier_dir, sizeof(memtier_dir), cfg.output, "memtier");
	if (!err)
		err = mkdir_one(memtier_dir);
	if (!err)
		err = path_join(cfg.service_file, sizeof(cfg.service_file), cfg.work_dir,
				service_leaf);
	if (!err && !cfg.reuse_batch_file)
		err = path_join(cfg.batch_file, sizeof(cfg.batch_file), cfg.work_dir,
				batch_leaf);
	if (err) {
		fprintf(stderr, "cannot create result paths: %s\n", strerror(-err));
		return 1;
	}
	err = setup_cgroups(&cgs, &cfg);
	if (err) {
		fprintf(stderr, "cannot create cgroup hierarchy: %s\n", strerror(-err));
		write_status(&cfg, "failure", "cgroup setup failed");
		goto out;
	}
	cgroups_created = true;
	err = write_config_json(&cfg, seed);
	if (!err)
		err = write_environment(&cfg);
	if (err) {
		fprintf(stderr, "cannot write benchmark provenance: %s\n", strerror(-err));
		goto out;
	}
	if (cfg.verbose)
		fprintf(stderr, "preparing %" PRIu64 " MiB service and %" PRIu64
			" MiB batch files\n", cfg.service_file_size >> 20,
			cfg.batch_file_size >> 20);
	err = cfg.memcached ? 0 :
		prepare_file(cfg.service_file, cfg.service_file_size, seed);
	if (!err && cfg.reuse_batch_file)
		err = validate_prepared_file(cfg.batch_file, cfg.batch_file_size);
	else if (!err)
		err = prepare_file(cfg.batch_file, cfg.batch_file_size, seed ^ 0x5bd1e995);
	if (err) {
		fprintf(stderr, "cannot prepare workload files: %s\n", strerror(-err));
		write_status(&cfg, "failure", "workload file preparation failed");
		goto out;
	}
	if (path_join(samples_path, sizeof(samples_path), cfg.output, "samples.csv")) {
		err = -ENAMETOOLONG;
		goto out;
	}
	samples = fopen(samples_path, "w");
	if (!samples) {
		err = -errno;
		goto out;
	}
	write_csv_header(samples);

	trial_count = cfg.repeat * cfg.mode_count;
	results = calloc(trial_count, sizeof(*results));
	if (!results) {
		err = -ENOMEM;
		goto out;
	}
	for (repetition = 0; repetition < cfg.repeat && !interrupted; repetition++) {
		write_number(cgs.service, "memory.low", 0);
		if (cfg.verbose)
			fprintf(stderr, "repetition %d: calibrating service latency\n",
				repetition);
		if (cfg.memcached) {
			calibration_p99 = 0;
			slo_ns = 0;
		} else {
			err = calibrate_service(&cfg, &cgs, seed + repetition,
						&calibration_p99);
			if (err) {
				fprintf(stderr, "service calibration failed: %s\n",
					strerror(-err));
				failures++;
				break;
			}
			slo_ns = calibration_p99 * 3;
			if (slo_ns < 100000)
				slo_ns = 100000;
		}
		for (mode_index = 0; mode_index < cfg.mode_count && !interrupted;
		     mode_index++) {
			enum bench_mode mode =
				cfg.modes[(mode_index + repetition) % cfg.mode_count];
			struct trial_result *result = &results[result_count++];

			if (cfg.verbose)
				fprintf(stderr, "repetition %d: running %s (SLO %" PRIu64
					" us)\n", repetition, mode_name(mode), slo_ns / 1000);
			err = run_trial(&cfg, &cgs, mode, repetition, seed + repetition,
					calibration_p99, slo_ns, samples, raw_dir, result);
			if (err) {
				result->inconclusive = true;
				snprintf(result->warning, sizeof(result->warning),
					 "trial failed: %s", strerror(-err));
				failures++;
			}
			if (result->inconclusive)
				inconclusive++;
		}
	}
	if (samples) {
		fclose(samples);
		samples = NULL;
	}
	write_summaries(&cfg, results, result_count);
	if (interrupted) {
		snprintf(status_detail, sizeof(status_detail), "interrupted by signal %d",
			 interrupted);
		write_status(&cfg, "failure", status_detail);
		err = -EINTR;
	} else if (failures) {
		snprintf(status_detail, sizeof(status_detail), "%d trial failures", failures);
		write_status(&cfg, "failure", status_detail);
		err = -EIO;
	} else if (inconclusive) {
		snprintf(status_detail, sizeof(status_detail), "%d inconclusive trials",
			 inconclusive);
		write_status(&cfg, "inconclusive", status_detail);
		err = 0;
	} else {
		write_status(&cfg, "complete", "all scenario validity checks passed");
		err = 0;
	}
	fprintf(stdout, "results: %s\n", cfg.output);
	if (!path_join(samples_path, sizeof(samples_path), cfg.output, "summary.txt")) {
		char summary[32768];

		if (!read_file(samples_path, summary, sizeof(summary)))
			fputs(summary, stdout);
	}

out:
	if (samples)
		fclose(samples);
	free(results);
	if (!cfg.keep_files) {
		if (!cfg.memcached)
			unlink(cfg.service_file);
		if (!cfg.reuse_batch_file)
			unlink(cfg.batch_file);
	}
	if (cgroups_created)
		cleanup_cgroups(&cgs);
	if (err && cfg.output[0] && !failures)
		write_status(&cfg, "failure", strerror(-err));
	return err ? 1 : 0;
}
