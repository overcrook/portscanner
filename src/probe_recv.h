#ifndef PORTSCANNER_PROBE_RECV_H
#define PORTSCANNER_PROBE_RECV_H
#include <netinet/in.h>
#include <stdint.h>

#include "portscan.h"


/**
 * Пробует прочитать данные из raw-сокета и соотнести их с ожидаемыми данными.
 *
 * Читает данные из сокета, проверяет их корректность. Разбирает заголовок IPv4/IPv6, проверяет на корректность и
 * на совпадение адресов. Затем проверяет заголовок TCP, порты src/dst и tcp ack num.
 *
 * При успехе отдает 0. При ошибке отдает -1, которую стоит игнорировать.
 *
 * @param sock         - raw-сокет, готовый для чтения;
 * @param route        - информация о маршруте до целевой машины;
 * @param sport        - порт источника на момент отправки пакета (должен быть равен dport в ответе);
 * @param dport_start  - начало диапазона портов назначения на момент отправки пакета (sport в ответе должен быть не меньше);
 * @param dport_end    - конец диапазона портов назначения на момент отправки пакета (sport в ответе должен быть не больше);
 * @param tcp_sn       - TCP syn id на момент отправки ответа (должен быть равен `TCP ack id - 1` в ответе);
 * @param result       - массив для заполнения результата: порт - статус (open при SYN-ACK, closed при RST);
 * @retval 0 - успех чтения данных и успешное соответствие исходному запросу;
 * @retval -1 - ошибка чтения данных, либо данные от другой, не связанной сессии.
 */
int probe_recv_one(int sock, struct route_info *route, in_port_t sport, in_port_t dport_start,
                   in_port_t dport_end, uint32_t tcp_sn, struct portscan_result *result);


#endif //PORTSCANNER_PROBE_RECV_H
