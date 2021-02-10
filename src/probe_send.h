#ifndef PORTSCANNER_PROBE_SEND_H
#define PORTSCANNER_PROBE_SEND_H
#include <netinet/in.h>


/**
 * Отправляет запрос TCP-SYN по указанному адресу и порту с указанного исходящего порта
 *
 * @param sock         - raw-сокет для отправки запроса;
 * @param route        - информация об адресах источника и назначения;
 * @param sport        - порт источника;
 * @param dport        - порт назначения;
 * @param tcp_sn       - начальное значение для TCP sequence number;
 * @retval 0  - успешно отправлен хотя бы один запрос;
 * @retval -1 - ошибка отправки всех запросов.
 */
int probe_send_one(int sock, struct route_info *route, in_port_t sport, in_port_t dport, uint32_t tcp_sn);

#endif //PORTSCANNER_PROBE_SEND_H
