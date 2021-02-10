#ifndef PORTSCANNER_PROBE_SEND_H
#define PORTSCANNER_PROBE_SEND_H
#include <netinet/in.h>


int probe_send_one(int sock, struct route_info *route, in_port_t sport, in_port_t dport, uint32_t tcp_sn);

/**
 * Отправляет запрос TCP-SYN по указанному адресу и диапазону портов с указанного исходящего порта
 *
 * Для каждого порта заново генерирует пакет.
 *
 * Если хотя бы одна попытка отправки удалась, то весь вызов считается успешным.
 *
 * @param sock         - raw-сокет для отправки запроса;
 * @param route        - информация об адресах источника и назначения;
 * @param sport        - порт источника;
 * @param dport_start  - начало диапазона портов назначения;
 * @param dport_end    - конец диапазона портов назначения;
 * @param tcp_sn       - начальное значение для TCP sequence number;
 * @retval 0  - успешно отправлен хотя бы один запрос;
 * @retval -1 - ошибка отправки всех запросов.
 */
int probe_send(int sock, struct route_info *route, in_port_t sport, in_port_t dport_start, in_port_t dport_end,
               uint32_t tcp_sn);

#endif //PORTSCANNER_PROBE_SEND_H
