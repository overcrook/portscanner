#ifndef PORTSCANNER_PROBE_RECV_H
#define PORTSCANNER_PROBE_RECV_H
#include <netinet/in.h>
#include <stdint.h>

#include "portscan.h"


int probe_recv_one(int sock, struct route_info *route, in_port_t sport, in_port_t dport_start,
                   in_port_t dport_end, uint32_t tcp_sn, struct portscan_result *result);

int probe_recv(int sock, struct route_info *route, in_port_t sport, in_port_t dport_start, in_port_t dport_end,
               uint32_t tcp_sn, int timeo, struct portscan_result *results, int ports_to_scan);

#endif //PORTSCANNER_PROBE_RECV_H
