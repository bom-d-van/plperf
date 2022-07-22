
// #include <linux/version.h>
#include <linux/ptrace.h>
// #include <uapi/linux/bpf.h>
// #include <uapi/linux/bpf_perf_event.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

// sudo bpftrace -p `pidof -s uwsgi` -e '
//   usdt:/usr/lib64/uwsgi/perl_plugin.so:sub__entry {
//     if (@my_arg0[arg0] <= 0) {
//       @my_arg0[arg0] = 1;
//       @my_arg0_str[pid, arg0] = str(arg0);
//     }
//   }
//
//   interval:s:1 {
//     print(@my_arg0_str);
//     exit();
//   }
// '

struct stack_entry {
	void *file;
	void *func;
	u32 line;
};

struct bpf_map_def SEC("maps") stack = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct stack_entry),
	.max_entries = 4096,
};

SEC("uprobe/sub_entry")
int sub_entry(struct pt_regs *ctx)
{
	u32 index = 0;
	struct stack_entry *depth = bpf_map_lookup_elem(&stack, &index);

	if (depth) {
		depth->line++;
	} else {
		depth = &(struct stack_entry){.line = 1};
	}

	struct stack_entry stack;
	stack.func = (void *)PT_REGS_PARM1(ctx);
	stack.file = (void *)PT_REGS_PARM2(ctx);
	stack.line = (u32)PT_REGS_PARM3(ctx);

	bpf_map_update_elem(&stack, &(depth->line), &stack, BPF_ANY);

	return 0;
}

SEC("uprobe/sub_return")
int sub_return(struct pt_regs *ctx) {
	u32 index = 0;
	struct stack_entry *depth = bpf_map_lookup_elem(&stack, &index);

	if (depth) {
		depth->line--;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
