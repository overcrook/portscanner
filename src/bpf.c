#include <linux/bpf.h>
#include <sys/syscall.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "bpf.h"
#include "log.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define BPF_RETURN(x) \
	{.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = (x)}, \
	{.code = BPF_JMP | BPF_EXIT}

#define BPF_MOV_REG(dst, src) \
	{.code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = (dst), .src_reg = (src)}

#define BPF_MOV_VALUE(dst, value) \
	{.code = BPF_ALU   | BPF_MOV | BPF_K, .dst_reg = (dst), .imm = (value)}

#define BPF_PKT_LOAD_ABS(size, offset) \
	{.code = BPF_LD    | BPF_ABS | (size), .imm = (offset)}

#define BPF_PKT_LOAD_IND(size, base, offset) \
	{.code = BPF_LD    | BPF_IND | (size), .src_reg = (base), .imm = (offset)}

#define BPF_JEQ_REG(dst, src, goto_num) \
	{.code = BPF_JMP   | BPF_JEQ | BPF_X, .dst_reg = (dst), .src_reg = (src), .off = (goto_num)}

#define BPF_JEQ_VALUE(dst, value, goto_num) \
	{.code = BPF_JMP   | BPF_JEQ | BPF_K, .dst_reg = (dst), .off = (goto_num), .imm = (value)}

#define BPF_JGE_VALUE(dst, value, goto_num) \
	{.code = BPF_JMP   | BPF_JGE | BPF_K, .dst_reg = (dst), .off = (goto_num), .imm = (value)}

#define BPF_JLE_VALUE(dst, value, goto_num) \
	{.code = BPF_JMP   | BPF_JLE | BPF_K, .dst_reg = (dst), .off = (goto_num), .imm = (value)}

#define BPF_ALU_VALUE(op, dst, value) \
	{.code = BPF_ALU   | (op) | BPF_K, .dst_reg = (dst), .imm = (value)}

static int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	int ret = (int) syscall(__NR_bpf, cmd, attr, size);

	return ret;
}


static int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn *insns, int insn_cnt, const char *license)
{
#define LOG_BUF_SIZE 65536
	char bpf_log_buf[LOG_BUF_SIZE];

	union bpf_attr attr = {
		.prog_type = type,
		.insns     = (intptr_t) insns,
		.insn_cnt  = insn_cnt,
		.license   = (intptr_t) license,
		.log_buf   = (intptr_t) bpf_log_buf,
		.log_size  = LOG_BUF_SIZE,
		.log_level = 2,
	};

	int ret = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));

	log_notice("Kernel message: \n%s", bpf_log_buf);
	if (ret < 0) {
		plog_err("Error loading eBPF(BPF_PROG_LOAD)");
		log_notice("Kernel message: \n%s", bpf_log_buf);
		return -1;
	}

	return ret;
}

int bpf_attach_filter(int sock, const struct portscan_context *ctx)
{
	const struct bpf_insn ipv4_filter[] = {
		/* r6 = r1 */
		BPF_MOV_REG(BPF_REG_6, BPF_REG_1),
		/* r0 = ip->protocol */
		BPF_PKT_LOAD_ABS(BPF_B, offsetof(struct iphdr, protocol)),
		/* if (r0 != IPPROTO_TCP) return 0 */
		BPF_JEQ_VALUE(BPF_REG_0, IPPROTO_TCP, 2),
		BPF_RETURN(0),

		/* r0 = ip->saddr */
		BPF_PKT_LOAD_ABS(BPF_W, offsetof(struct iphdr, saddr)),
		/* r2 = route->dst */
		BPF_MOV_VALUE(BPF_REG_2, ntohl(ctx->route.dst.v4.s_addr)),
		/* if (r0 != r2) goto fail */
		BPF_JEQ_REG(BPF_REG_0, BPF_REG_2, 2),
		BPF_RETURN(0),

		/* r0 = ip->daddr */
		BPF_PKT_LOAD_ABS(BPF_W, offsetof(struct iphdr, daddr)),
		/* r2 = route->src */
		BPF_MOV_VALUE(BPF_REG_2, ntohl(ctx->route.src.v4.s_addr)),
		/* if (r0 != r2) goto fail */
		BPF_JEQ_REG(BPF_REG_0, BPF_REG_2, 2),
		BPF_RETURN(0),

		/* r0 = ip->ihl */
		BPF_PKT_LOAD_ABS(BPF_B, 0),
		/* r0 = r0 & 0xF0 */
		BPF_ALU_VALUE(BPF_AND, BPF_REG_0, 0x0F),
		/* r0 = r0 * 4 */
		BPF_ALU_VALUE(BPF_MUL, BPF_REG_0, 4),
		/* r7 = r0 */
		BPF_MOV_REG(BPF_REG_7, BPF_REG_0),
	};

	const struct bpf_insn ipv6_filter[] = {
		/* r6 = r1 */
		BPF_MOV_REG(BPF_REG_6, BPF_REG_1),

		/* r7 = 0 (IPv6 header is excluded from the received payload, so no need to shift */
		BPF_MOV_VALUE(BPF_REG_7, 0),
	};

	const struct bpf_insn tcp_filter[] = {

		/* r0 = tcp->th_dport */
		BPF_PKT_LOAD_IND(BPF_H, BPF_REG_7, offsetof(struct tcphdr, th_dport)),
		/* if (r0 != ctx->sport) goto fail */
		BPF_JEQ_VALUE(BPF_REG_0, ctx->sport, 2),
		BPF_RETURN(0),

		/* r0 = tcp->th_sport */
		BPF_PKT_LOAD_IND(BPF_H, BPF_REG_7, offsetof(struct tcphdr, th_sport)),
		/* if (r0 < ctx->dport_start) goto fail */
		BPF_JGE_VALUE(BPF_REG_0, ctx->dport_start, 2),
		BPF_RETURN(0),
		/* if (r0 > ctx->dport_end) goto fail */
		BPF_JLE_VALUE(BPF_REG_0, ctx->dport_end, 2),
		BPF_RETURN(0),

		/* r0 = tcp->th_ack */
		BPF_PKT_LOAD_IND(BPF_W, BPF_REG_7, offsetof(struct tcphdr, th_ack)),
		/* if (r0  != ctx->tcp_sn + 1) goto fail */
		BPF_JEQ_VALUE(BPF_REG_0, (ctx->tcp_sn + 1) % UINT32_MAX, 2),
		BPF_RETURN(0),

		// OK
		BPF_RETURN(0xFFFFFFFF),
	};

	int ret = -1;
	struct bpf_insn *filter = NULL;
	size_t filter_insn_count = 0;

	if (ctx->route.af == AF_INET) {
		filter_insn_count = ARRAY_SIZE(ipv4_filter) + ARRAY_SIZE(tcp_filter);
		filter = malloc(filter_insn_count * sizeof(struct bpf_insn));
		memcpy(filter, ipv4_filter, sizeof(ipv4_filter));
		memcpy(filter + ARRAY_SIZE(ipv4_filter), tcp_filter, sizeof(tcp_filter));
	} else {
		filter_insn_count = ARRAY_SIZE(ipv6_filter) + ARRAY_SIZE(tcp_filter);
		filter = malloc(filter_insn_count * sizeof(struct bpf_insn));
		memcpy(filter, ipv6_filter, sizeof(ipv6_filter));
		memcpy(filter + ARRAY_SIZE(ipv6_filter), tcp_filter, sizeof(tcp_filter));
	}

	int bpf_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, filter, filter_insn_count, "GPL");

	if (bpf_fd < 0)
		goto out;

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &bpf_fd, sizeof(bpf_fd))) {
		plog_err("Cannot attach eBPF filter to socket");
		goto out;
	}

	ret = 0;

out:
	free(filter);
	close(bpf_fd);
	return ret;
}
