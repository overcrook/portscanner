#ifndef PORTSCANNER_PACKET_H
#define PORTSCANNER_PACKET_H
#include <stdint.h>
#include <netinet/in.h>

#include "route.h"

struct tcp_setup {
	/// Информация о данных L3-уровня (выбор IPv4/IPv6, IP-адрес отправителя (это мы) и получателя, исходящий интерфейс)
	struct route_info *route;

	/// Порт источника (если 0, то будет выбран произвольный из диапазона динамических портов)
	in_port_t src_port;

	/// Порт назначения
	in_port_t dst_port;

	/// Sequence Number (если 0, то будет сгенерирован)
	uint32_t sn;
};


/**
 * Заполняет пакет с TCP-заголовком для сканирования TCP-SYN
 *
 * @param setup_info  - информация для заполнения пакета (адреса, порты, TCP.SN, ...).
 * @param packet      - указатель на буфер, заполняемый заголовком TCP
 * @param packet_size - размер буфера packet
 * @retval >0 размер собранного пакета
 * @retval -1 некорректные аргументы
 */
int packet_craft(const struct tcp_setup *setup_info, uint8_t *packet, size_t packet_size);

#endif //PORTSCANNER_PACKET_H
