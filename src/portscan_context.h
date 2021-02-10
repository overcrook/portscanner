#ifndef PORTSCANNER_PORTSCAN_CONTEXT_H
#define PORTSCANNER_PORTSCAN_CONTEXT_H
#include <portscan.h>
#include <netinet/in.h>
#include "route.h"

struct portscan_context {
	/// Информация об адресах источника и назначения
	struct route_info *route;

	/// raw-сокет, с которого происходить отправка и получение данных
	int sock;

	/// Порт источника (один для всех пакетов, выбирается автоматически)
	in_port_t sport;

	/// Начало диапазона портов для сканирования портов
	in_port_t dport_start;

	/// Конец диапазона портов для сканирования портов
	in_port_t dport_end;

	/// TCP sequence number (один для всех, выбирается автоматически)
	uint32_t tcp_sn;

	/// Массив для заполнения результатов сканирования
	struct portscan_result *results;
};

#endif //PORTSCANNER_PORTSCAN_CONTEXT_H
