#ifndef PORTSCANNER_PORTSCAN_CONTEXT_H
#define PORTSCANNER_PORTSCAN_CONTEXT_H
#include <portscan.h>
#include <netinet/in.h>
#include "route.h"

/**
 * Runtime-данные сканера портов, необходимые для реентерабельных вызовов.
 *
 * Перед началом сканирования обязательно требуется создать новый контекст функцией portscan_prepare(), который
 * автоматически готов к отправке пакетов.
 *
 * Затем требуется отслеживать состояние поля *events* - оно показывает, какие события в данный момент нужно
 * отслеживать. Для обработки событий нужно вызывать соответствующие функции portscan_pollin() и portscan_pollout().
 *
 *
 */
struct portscan_context {
	/// Информация об адресах источника и назначения
	struct route_info route;

	/// raw-сокет, с которого происходит отправка и получение данных
	int sock;

	/// таймер для ожидания ответа
	int timerfd;

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

	/// Текущая позиция для учета числа отправленных запросов
	int cursor;

	/// Общее число опрашиваемых портов
	int total_ports;

	/// Число портов, с которых были получены ответы
	int answered_ports;

	/// Число пакетов, которые мы можем отправить заранее, прежде чем будем вынуждены ждать ответы
	int send_quota;

	/// Число оставшихся попыток отправки пакетов
	int retry_counter;

	/// Ожидаемые события на сокете
	short events;
};

#endif //PORTSCANNER_PORTSCAN_CONTEXT_H
