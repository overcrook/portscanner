#ifndef PORTSCANNER_PROBE_SEND_H
#define PORTSCANNER_PROBE_SEND_H
#include <netinet/in.h>


/**
 * Отправляет запрос TCP-SYN по указанному адресу и диапазону портов с указанного исходящего порта
 *
 * Для каждого порта заново генерирует пакет, кодируя в TCP sequence number номер попытки отправки.
 *
 * Если хотя бы одна попытка отправки удалась, то весь вызов считается успешным.
 *
 * @param sock         - raw-сокет для отправки запроса;
 * @param route        - информация об адресах источника и назначения;
 * @param sport        - порт источника;
 * @param dport_start  - начало диапазона портов назначения;
 * @param dport_end    - конец диапазона портов назначения;
 * @param tcp_sn       - начальное значение для TCP sequence number;
 * @param retry_index  - номер попытки отправки.
 * @retval 0  - успешно отправлен хотя бы один запрос;
 * @retval -1 - ошибка отправки всех запросов.
 */
int probe_send(int sock, struct route_info *route, in_port_t sport, in_port_t dport_start, in_port_t dport_end,
               uint32_t tcp_sn, int retry_index);

#endif //PORTSCANNER_PROBE_SEND_H
