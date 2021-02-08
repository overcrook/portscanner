#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <portscan.h>
#include "log.h"


union in46_addr {
	struct in_addr v4;
	struct in6_addr v6;
};

struct route_info {
	int af;
	unsigned int ifindex;

	union in46_addr src;
	union in46_addr dst;
};

static int parse_ip(const char *str_address, union in46_addr *addr)
{
	if (inet_pton(AF_INET, str_address, &addr->v4) == 1) {
		return AF_INET;
	}

	if (inet_pton(AF_INET6, str_address, &addr->v6) == 1) {
		return AF_INET6;
	}

	return AF_UNSPEC;
}


int portscan_execute(struct portscan_req *req, struct portscan_result *results)
{
	struct route_info route_info;

	memset(&route_info, 0, sizeof(route_info));

	// TODO: вынести весь код валидации в отдельную функцию (и возможно, возвращать EINVAL в общем случае)
	if (req->port_start == 0 || req->port_start > 65535 || req->port_end > 65535) {
		log_err("Port must be in range [1:65535]");
		return -1;
	}

	if (req->port_end && req->port_end < req->port_start) {
		log_err("End port must be greater than start port");
		return -1;
	}

	if (!req->dst_ip) {
		log_err("Destination address is not specified");
		return -1;
	}

	route_info.af = parse_ip(req->dst_ip, &route_info.dst);

	if (route_info.af == AF_UNSPEC) {
		log_err("Destination address '%s' is not a valid IP address", req->dst_ip);
		return -1;
	}

	if (req->src_ip) {
		int src_af = parse_ip(req->src_ip, &route_info.src);

		if (src_af == AF_UNSPEC) {
			log_err("Source address '%s' is not a valid IP address", req->src_ip);
			return -1;
		}

		if (src_af != route_info.af) {
			log_err("Source address '%s' and destination address '%s' belong to different IP stacks",
			        req->src_ip, req->dst_ip);
			return -1;
		}
	}

	if (req->interface) {
		route_info.ifindex = if_nametoindex(req->interface);

		if (route_info.ifindex == 0) {
			plog_err("Cannot find interface '%s'", req->interface);
			return -1;
		}
	}



	// TODO: actual port scan
	return 0;
}



const char *portscan_version(void)
{
	return PORTSCAN_VERSION;
}
