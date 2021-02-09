#ifndef PORTSCANNER_ROUTE_H
#define PORTSCANNER_ROUTE_H
#include <netinet/in.h>

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

int fetch_route_info(struct route_info *info);

#endif //PORTSCANNER_ROUTE_H
