
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

static int (*bpf_probe_read_str)(void *dst, uint32_t size, void *unsafe_ptr) = (void *) BPF_FUNC_probe_read_str;

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
	// unsigned int inner_map_idx;
	char namespace[BUF_SIZE_MAP_NS];
};

enum bpf_pin_type {
	PIN_NONE = 0,
	PIN_OBJECT_NS,
	PIN_GLOBAL_NS,
	PIN_CUSTOM_NS,
};

#define STACK_OUTER_LEN (4096)
#define STACK_INNER_LEN (1024)

struct stack_entry {
	struct {
		u64 timestamp;
		u64 file;
		u64 func;
		u32 line;
		u8  etype;
		u64 pid;
		u32 cpu;
		u32 req_idx;
	} entries[STACK_INNER_LEN];
};

#define MAX_SYMBOL_LEN 512

#define TEXTSTACK_INNER_LEN 256

struct stack_entry_text {
	struct {
		u64 timestamp;
		u64 pid;
		u32 cpu;
		u32 req_idx;

		u32 line;
		char file[MAX_SYMBOL_LEN];
		char func[MAX_SYMBOL_LEN];
	} entries[TEXTSTACK_INNER_LEN];
};

enum etype {
	SUB_ENTRY = 0,
	SUB_EXIT  = 1,
};

struct gobpf_map_def SEC("maps/stacks") stacks = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct stack_entry),
	.max_entries = STACK_OUTER_LEN,
};

struct gobpf_map_def SEC("maps/text_stacks") text_stacks = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct stack_entry_text),
	.max_entries = STACK_OUTER_LEN,
};

#define MAX_URI_LEN 2048
struct stack_meta {
	u8 enabled;

	u32 outer_len;
	u32 outer_offset;
	u32 outer_idx;
	u32 inner_idx;

	u32 step;

	u32 req_idx;
	u32 req_buffer_size;
	u32 req_buffer_offset;

	u8 reset_outer_idx_on_new_request;
	// char req_uri[MAX_URI_LEN];
	// u16 req_uri_len;
};

struct uwsgi_request {
	u32 id;
	u16 uri_len;
	char uri[MAX_URI_LEN];
	char method[16];
	uint16_t method_len;
};

struct gobpf_map_def SEC("maps/metas") metas = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct stack_meta),
	.max_entries = 65536,
};

struct gobpf_map_def SEC("maps/requests") requests = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct uwsgi_request),
	.max_entries = 65536,
};

int __attribute__((always_inline)) store_stack_frame(struct pt_regs *ctx, enum etype et) {
	u64 pid = bpf_get_current_pid_tgid() & ((1<<16)-1);
	struct stack_meta *meta = bpf_map_lookup_elem(&metas, &pid);
	if (!meta || !meta->enabled) {
		return 0;
	}
	// meta->step = 1;
	if (meta->outer_len == 0) {
		return 0;
	}

	// meta->step = 2;
	if (meta->inner_idx >= STACK_INNER_LEN) {
		// meta->step = 3;
		meta->inner_idx = 0;
		meta->outer_idx = meta->outer_offset + ((meta->outer_idx + 1) % meta->outer_len);
	}

	u32 outter = meta->outer_idx;
	struct stack_entry *stack = bpf_map_lookup_elem(&stacks, &outter);
	if (!stack) {
		// meta->step = 4;
		return 0;
	}

	// meta->step = 5;
	u32 index = meta->inner_idx;
	if (index >= STACK_INNER_LEN) {
		// meta->step = 6;
		return 0;
	}
	// meta->step = 7;

	meta->inner_idx += 1;
	stack->entries[index].timestamp = bpf_ktime_get_ns();
	stack->entries[index].func = (u64)ctx->r8;
	stack->entries[index].file = (u64)ctx->cx;
	stack->entries[index].line = (u32)ctx->di;
	stack->entries[index].etype = et;
	stack->entries[index].pid = pid;
	stack->entries[index].cpu = bpf_get_smp_processor_id();
	stack->entries[index].req_idx = meta->req_idx-1;

	return 0;
}

SEC("uprobe/sub_entry")
int sub_entry(struct pt_regs *ctx) { return store_stack_frame(ctx, SUB_ENTRY); }

SEC("uprobe/sub_return")
int sub_return(struct pt_regs *ctx) { return store_stack_frame(ctx, SUB_EXIT); }

int __attribute__((always_inline)) store_stack_frame_text(struct pt_regs *ctx, enum etype et) {
	u64 pid = bpf_get_current_pid_tgid() & ((1<<16)-1);
	struct stack_meta *meta = bpf_map_lookup_elem(&metas, &pid);
	if (!meta || !meta->enabled) {
		return 0;
	}
	meta->step = 1;
	if (meta->outer_len == 0) {
		return 0;
	}

	if (et == SUB_EXIT) {
		if (meta->inner_idx > 0) {
			meta->inner_idx -= 1;
			return 0;
		}

		if (meta->outer_idx <= 0) {
			return 0;
		}

		meta->outer_idx -= 1;
		meta->inner_idx = TEXTSTACK_INNER_LEN - 1;

		return 0;
	}

	meta->step = 2;
	if (meta->inner_idx >= TEXTSTACK_INNER_LEN) {
		meta->step = 3;
		if (meta->outer_idx >= meta->outer_len - 1) {
			meta->inner_idx += 1;

			// TODO: report overflown?
			return 0;
		}

		meta->outer_idx += 1;
		meta->inner_idx = 0;
	}

	u32 outter = meta->outer_idx + meta->outer_offset;
	struct stack_entry_text *stack = bpf_map_lookup_elem(&text_stacks, &outter);
	if (!stack) {
		meta->step = 4;
		return 0;
	}

	meta->step = 5;
	u32 index = meta->inner_idx;
	if (index >= TEXTSTACK_INNER_LEN) {
		meta->step = 6;
		return 0;
	}
	meta->step = 7;

	meta->inner_idx += 1;
	stack->entries[index].timestamp = bpf_ktime_get_ns();
	stack->entries[index].line = (u32)ctx->di;
	stack->entries[index].pid = pid;
	stack->entries[index].cpu = bpf_get_smp_processor_id();
	stack->entries[index].req_idx = meta->req_idx-1;

	bpf_probe_read_str(&stack->entries[index].file, MAX_SYMBOL_LEN, (void *)ctx->cx);
	bpf_probe_read_str(&stack->entries[index].func, MAX_SYMBOL_LEN, (void *)ctx->r8);

	return 0;
}

SEC("uprobe/sub_entry_text")
int sub_entry_text(struct pt_regs *ctx) { return store_stack_frame_text(ctx, SUB_ENTRY); }

SEC("uprobe/sub_return_text")
int sub_return_text(struct pt_regs *ctx) { return store_stack_frame_text(ctx, SUB_EXIT); }

SEC("uprobe/new_uwsgi_request_no_uri")
int new_uwsgi_request_no_uri(struct pt_regs *ctx) {
	// struct uwsgi_request *req = (struct uwsgi_request*)PT_REGS_PARM1(ctx);

	u64 pid = bpf_get_current_pid_tgid() & ((1<<16)-1);
	struct stack_meta *meta = bpf_map_lookup_elem(&metas, &pid);
	if (!meta || !meta->enabled) {
		return 0;
	}

	meta->req_idx += 1;

	return 0;
}

// struct uwsgi_request {
//     char padding[192];
//     char *uri;
//     uint16_t uri_len;
// };

// struct gobpf_map_def SEC("maps/metas") metas = {
// 	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
// 	.key_size = sizeof(int),
// 	.value_size = sizeof(u32),
// 	.max_entries = 2,
// };

SEC("uprobe/new_uwsgi_request_with_uri")
int new_uwsgi_request_with_uri(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid() & ((1<<16)-1);
	struct stack_meta *meta = bpf_map_lookup_elem(&metas, &pid);
	if (!meta || !meta->enabled) {
		return 0;
	}

	u32 rid = (meta->req_idx % meta->req_buffer_size) + meta->req_buffer_offset;
	struct uwsgi_request *req = bpf_map_lookup_elem(&requests, &rid);
	if (!req) {
		return 0;
	}
	req->id = meta->req_idx;

	meta->req_idx += 1;

	if (meta->reset_outer_idx_on_new_request) {
		meta->outer_idx = 0;
		meta->inner_idx = 0;
	}

	struct uri {
		char *str;
		uint16_t len;

		char *remote_addr;
		uint16_t remote_addr_len;
		char *remote_user;
		uint16_t remote_user_len;
		char *query_string;
		uint16_t query_string_len;
		char *protocol;
		uint16_t protocol_len;

		char *method;
		uint16_t method_len;
	} uri;
	const int uri_offset = 192;
	bpf_probe_read(&uri, sizeof(struct uri), (void*)PT_REGS_PARM1(ctx) + uri_offset);

	bpf_probe_read_str(&req->uri, MAX_URI_LEN, uri.str);
	req->uri_len = uri.len;

	bpf_probe_read_str(&req->method, 16, uri.method);
	req->method_len = uri.method_len;

	return 0;
}
