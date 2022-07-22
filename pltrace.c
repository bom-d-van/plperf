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

char _license[] SEC("license") = "GPL";
__u32 _version  SEC("version") = 0xFFFFFFFE;

#define BUF_SIZE_MAP_NS 256

struct gobpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int pinning;
	char namespace[BUF_SIZE_MAP_NS];
};

enum bpf_pin_type {
	PIN_NONE = 0,
	PIN_OBJECT_NS,
	PIN_GLOBAL_NS,
	PIN_CUSTOM_NS,
};


#define ENTRY_SIZE0 (12288)
#define ENTRY_SIZE1 (128)

struct _stack_entry {
	u64 timestamp;
	u64 file;
	u64 func;
	u32 line;
	u8  etype;
	u64 pid;
	u32 cpu;
	u32 depth;
};

struct stack_entry {
	struct _stack_entry entries[ENTRY_SIZE1];
	// u64 timestamp;
	// u64 file;
	// u64 func;
	// u32 line;
	// u64 stash;
	// u64 pid;
	// u64 cpu;
};

enum etype {
	SUB_ENTRY = 0,
	SUB_EXIT  = 1,
};

// struct gobpf_map_def SEC("maps/stack") stack = {
// 	.type = BPF_MAP_TYPE_ARRAY,
// 	.key_size = sizeof(u32),
// 	.value_size = sizeof(struct stack_entry),
// 	.max_entries = 4096,
// };

struct gobpf_map_def SEC("maps/depths") depths = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 1024,
};

// struct gobpf_map_def SEC("maps/depths_by_pid") stack_depths = {
// 	.type = BPF_MAP_TYPE_ARRAY,
// 	.key_size = sizeof(u16),
// 	.value_size = sizeof(u32),
// 	.max_entries = 65536,
// };

struct gobpf_map_def SEC("maps/stacks") stacks = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct stack_entry),
	// .value_size = sizeof(struct stack_entry[ENTRY_SIZE1]),
	.max_entries = ENTRY_SIZE0,
};

// struct gobpf_map_def SEC("maps/stack") stack = {
// 	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
// 	// .key_size = sizeof(int),
// 	// .value_size = sizeof(struct stack_entry),
// 	.key_size = sizeof(int),
// 	.value_size = sizeof(__u32),
// 	.max_entries = 1024*1024*128,
// };

SEC("uprobe/sub_entry")
int sub_entry(struct pt_regs *ctx)
{
	{
		// u32 index = 0;
		// struct stack_entry *depth = bpf_map_lookup_elem(&stack, &index);

		// u64 pid = 0;
		// pid = bpf_get_current_pid_tgid();
		// if (depth) {
		// 	index = (depth->line + 1) % 4096;
		// 	if (index == 0) {
		// 		index += 1;
		// 	}
		// 	// depth->line = 2;
		// 	depth->line++;
		// 	depth->pid = pid;
		// }

		// else {
		// 	// depth = &(struct stack_entry){.line = 1};
		// 	// depth.pid
		// }

		// bpf_trace_printk("uprobe__sub_entry: depth = %d\n", 30, depth->line);

		// index = depth->line;
		// struct stack_entry *entry = bpf_map_lookup_elem(&stack, &index);
		// if (entry) {
		// 	// func, file, line, stash
		// 	entry->func = (u64)ctx->r8;
		// 	entry->file = (u64)ctx->cx;
		// 	entry->line = (u32)ctx->di;
		// 	entry->pid  = pid;
		// }

		// bpf_map_update_elem(&stack, &(depth->line), &entry, BPF_ANY);
	}

	u32 index0 = 0;
	u32 *depth = bpf_map_lookup_elem(&depths, &index0);
	if (!depth) {
		return 0;
	}
	// u16 pid = bpf_get_current_pid_tgid() &((1<<16)-1);
	// u32 *depth_by_pid = bpf_map_lookup_elem(&depths_by_pid, &pid);
	// if (!depth) {
	// 	return 0;
	// }

	index0 = ((*depth) / ENTRY_SIZE1) % ENTRY_SIZE0;

	struct stack_entry *entries = bpf_map_lookup_elem(&stacks, &index0);

	if (entries) {
		u32 index2 = (*depth) % ENTRY_SIZE1;

		entries->entries[index2].timestamp = bpf_ktime_get_ns();
		entries->entries[index2].func = (u64)ctx->r8;
		entries->entries[index2].file = (u64)ctx->cx;
		entries->entries[index2].line = (u32)ctx->di;
		entries->entries[index2].etype = SUB_ENTRY;
		entries->entries[index2].pid = bpf_get_current_pid_tgid();
		entries->entries[index2].cpu = bpf_get_smp_processor_id();
		entries->entries[index2].depth = *depth;

		// *depth_by_pid += *depth;
		*depth += 1;
	}

	{
		// struct stack_entry entry = {};
		// entry.timestamp = bpf_ktime_get_ns();
		// entry.func = (u64)ctx->r8;
		// entry.file = (u64)ctx->cx;
		// entry.line = (u32)ctx->di;
		// entry.stash = (u64)ctx->dx;
		// entry.pid = bpf_get_current_pid_tgid();

		// u32 cpu = bpf_get_smp_processor_id();
		// bpf_perf_event_output(ctx, &stack, cpu, &entry, sizeof(entry));
	}

	return 0;
}

SEC("uprobe/uwsgi_response")
int uwsgi_response(struct pt_regs *ctx) {
	//
}


SEC("uprobe/sub_return")
int sub_return(struct pt_regs *ctx) {
	u32 index0 = 0;
	u32 *depth = bpf_map_lookup_elem(&depths, &index0);
	if (!depth) {
		return 0;
	}

	index0 = ((*depth) / ENTRY_SIZE1) % ENTRY_SIZE0;

	struct stack_entry *entries = bpf_map_lookup_elem(&stacks, &index0);

	if (entries) {
		u32 index2 = (*depth) % ENTRY_SIZE1;

		entries->entries[index2].timestamp = bpf_ktime_get_ns();
		entries->entries[index2].func = (u64)ctx->r8;
		entries->entries[index2].file = (u64)ctx->cx;
		entries->entries[index2].line = (u32)ctx->di;
		entries->entries[index2].etype = SUB_EXIT;
		entries->entries[index2].pid = bpf_get_current_pid_tgid();
		entries->entries[index2].cpu = bpf_get_smp_processor_id();
		entries->entries[index2].depth = *depth;

		*depth += 1;
	}

	return 0;
}
