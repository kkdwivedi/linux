#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct Item {
	int x;
};

__noinline int helper_a(const struct Item *s)
{
	return bpf_get_prandom_u32() < s->x;
}

SEC("cgroup_skb/ingress")
int entry(struct __sk_buff *skb)
{
	const struct Item s = {.x = skb->len};

	helper_a(&s);

	return 1;
}
