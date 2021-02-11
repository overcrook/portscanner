#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <portscan.h>
#include <unistd.h>
#include <stdlib.h>
#include <poll.h>
#include <assert.h>
#include <stdbool.h>

#include "portscan_context.h"
#include "packet.h"
#include "route.h"
#include "log.h"
#include "probe_send.h"
#include "probe_recv.h"
#include "bpf.h"


#define RETRY_LIMIT 2

/// Число пакетов, которые мы можем отправить заранее, прежде чем перейдем к чтению ответов.
/// Чем это число больше, тем больше send подряд будет выполнено, что теоретически будет быстрее.
/// Но на практике есть ограничения SO_SNDBUF с нашей стороны и SO_RCVBUF с принимающей стороны, из-за чего
/// пакеты будут теряться.
#define SEND_QUOTA_MAX 100

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

static int validate_request(struct portscan_req *req, struct route_info *route_info)
{
	if (req->port_start == 0 || req->port_start > 65535 || req->port_end > 65535) {
		log_err("Port must be in range [1:65535]");
		return -ERANGE;
	}

	if (req->port_end < req->port_start) {
		log_err("End port must be greater than start port");
		return -ERANGE;
	}

	if (!req->dst_ip) {
		log_err("Destination address is not specified");
		return -EDESTADDRREQ;
	}

	route_info->af = parse_ip(req->dst_ip, &route_info->dst);

	if (route_info->af == AF_UNSPEC) {
		log_err("Destination address '%s' is not a valid IPv4/IPv6 address", req->dst_ip);
		return -EAFNOSUPPORT;
	}

	if (req->src_ip) {
		int src_af = parse_ip(req->src_ip, &route_info->src);

		if (src_af == AF_UNSPEC) {
			log_err("Source address '%s' is not a valid IP address", req->src_ip);
			return -EAFNOSUPPORT;
		}

		if (src_af != route_info->af) {
			log_err("Source address '%s' and destination address '%s' belong to different IP stacks",
			        req->src_ip, req->dst_ip);
			return -EAFNOSUPPORT;
		}
	}

	return 0;
}

static inline void log_route(struct route_info *route_info, const char *dst)
{
	char src_ip[INET6_ADDRSTRLEN] = "";
	char ifname[IF_NAMESIZE] = "";

	inet_ntop(route_info->af, &route_info->src, src_ip, sizeof(src_ip));
	if_indextoname(route_info->ifindex, ifname);

	log_debug("Host %s is available from dev %s with src %s", dst, ifname, src_ip);
}


/**
 * Инициализирует *ctx* данными, которые нужно проинициализировать один раз
 *
 * @param ctx - контекст для portscan
 * @retval 0  - успех
 * @retval -1 - ошибка создания сокета
 */
static int portscan_prepare(struct portscan_context *ctx)
{
	for (int i = 0; i <= ctx->dport_end - ctx->dport_start; i++) {
		ctx->results[i].port   = ctx->dport_start + i;
		ctx->results[i].status = PORT_STATUS_FILTERED;
	}

	ctx->sock = socket(ctx->route->af, SOCK_RAW, IPPROTO_TCP);

	if (ctx->sock < 0) {
		plog_err("Cannot open socket(%s, SOCK_RAW, IPPROTO_TCP)", ctx->route->af == AF_INET6 ? "AF_INET6" : "AF_INET");
		return -1;
	}

	// Генерируем рандомный порт в диапазоне 32768-61000
	ctx->sport = rand() % (61000 - 32768) + 32768;

	// Генерируем рандомный sequence number
	ctx->tcp_sn = rand();

	if (bpf_attach_filter(ctx->sock, ctx))
		return -1;

	return 0;
}


/**
 * Сдвигает курсор на следующую позицию с учетом возможного завершения диапазона
 *
 * Если курсор вышел за пределы диапазона, то он устанавливается обратно в 0.
 * Число попыток при этом уменьшается, и дополнительно выставляется признак ожидания всех ответов
 * перед началом работы с новой попыткой.
 */
#define cursor_advance(cursor, retry_counter, wait_all_before_pollout) do { \
	if (++cursor >= total_ports) {                                          \
	    retry_counter--;                                                    \
	    wait_all_before_pollout = true;                                     \
	    cursor = 0;                                                         \
	}                                                                       \
} while (0)


/**
 * Выполняет основной цикл отправки TCP-SYN пакетов и ожидания их ответов
 *
 * Функция одновременно пытается отправлять пакеты по указанным портам и в то же время
 * успевать обрабатывать ответы. Более приоритетно получение ответов - таким образом мы
 * дополнительно даем ядру время на отправку того, что уже лежит в tx буфере сокета
 * (то, что мы отправили в сокет на предыдущих итерациях), и в то же время даем время
 * целевой машине на обработку все новых приходящих запросов.
 *
 * Когда получение пакета завершено, если отправка разрешена, то выполняется отправка.
 * В качестве маркера, разрешающего отправку, используется флаг POLLOUT в pollfd.
 * Для ограничения количества одновременно отправляемых пакетов используется квотирование.
 * Выделяется SEND_QUOTA_MAX слотов для отправки. Каждая успешная отправка умешьшает
 * доступную квоту на единицу, каждое успешное получение увеличивает её на единицу.
 *
 * Таким образом, если целевая машина активно отвечает на запросы, то опрос идет быстро.
 * Еси целевая машина отвечает медленнее, чем мы отправляем ответы, то за счет квотирования
 * мы даем ей время на обработку накопившихся запросов. Получается back-pressure механизм.
 * Если этого не делать, то часть пакетов может быть просто отброшены, из-за чего порт
 * может быть неверно расценен как filtered.
 *
 * Когда все порты обработаны, включается режим ожидания всех оставшихся входящих пакетов
 * (когда новые пакеты уже не отправляются, и происходит ожидание ответов к отправленным),
 * после чего цикл завершается.
 *
 * @param ctx
 * @return
 */
int portscan_process(struct portscan_context *ctx)
{
	struct pollfd pfd = {
		.fd     = ctx->sock,
		.events = POLLIN | POLLOUT,
	};

	// Число пакетов, которые мы можем отправить заранее, прежде чем перейдем к чтению ответов
	int send_quota = SEND_QUOTA_MAX;

	// Число оставшихся попыток отправки пакетов
	int retry_counter  = RETRY_LIMIT;

	// Число портов, с которых были получены ответы
	int answered_ports = 0;

	// Общее число опрашиваемых портов
	int total_ports    = ctx->dport_end - ctx->dport_start + 1;

	// Текущая позиция в диапазоне портов
	int cursor = 0;

	// Признак завершения одного прохода по всему диапазону портов
	bool wait_all_before_pollout = false;


	// Крутимся в цикле до тех пор, пока не обработаем все порты (или пока он не будет прерван извне)
	while (answered_ports < total_ports) {
		log_debug("Start iteration, current status: retry_counter=%d cursor=%d answered_ports=%d send_quota=%d",
		          retry_counter, cursor, answered_ports, send_quota);

		int ret = poll(&pfd, 1, 1000);
		log_debug("poll() returned: %d", ret);

		if (ret < 0) {
			plog_err("Error on poll");
			return -1;
		}

		// Таймаут при ожидании доступных действий
		if (ret == 0) {
			if (pfd.events & POLLOUT && (pfd.revents & POLLOUT) == 0)
				log_warning("Cannot send a packet within 1 second, looks like there is a kernel/network problem");

			// Число попыток отправки пакетов уже превышено, нам больше нечего отправлять
			if (retry_counter == 0) {
				// Если нечего отправлять, и если таймаут при получении ответов - значит, больше нечего делать
				break;
			}

			// Все порты, для которых мы ждали ответы, так и останутся отмеченными как filtered.
			// Очищаем квоту и продолжаем спам дальше.
			log_debug("timeout waiting responses - refill send_quota and enable POLLOUT");
			send_quota = SEND_QUOTA_MAX;
			pfd.events |= POLLOUT;
			continue;
		}

		// Этап получения ответов
		if (pfd.revents & POLLIN) {
			log_debug("Process POLLIN");
			struct portscan_result result;

			// Пробуем прочитать ответ и сопоставить его с нашими данными
			if (probe_recv_one(ctx->sock, ctx->route, ctx->sport, ctx->dport_start, ctx->dport_end, ctx->tcp_sn, &result) < 0)
				continue;

			// Нашли ответ - проверим, что мы не получали его раньше, и занесем в массив ответов
			int index = result.port - ctx->dport_start;

			assert(index < total_ports);

			if (ctx->results[index].status != PORT_STATUS_FILTERED) {
				plog_warning("Found another response for port %u (TCP retransmission?)", result.port);
				continue;
			}

			// Это новый ответ - сохраняем его
			memcpy(&ctx->results[index], &result, sizeof(result));
			answered_ports++;

			log_debug("Successfully processed one response - increase send_quota");
			send_quota++;

			// Если нам не нужно дожидаться все ответы, или если нужно, но квота уже полна  - включаем режим отправки
			if (wait_all_before_pollout == false || send_quota == SEND_QUOTA_MAX) {
				log_debug("POLLOUT is allowed now - enable POLLOUT");
				wait_all_before_pollout = false;
				pfd.events |= POLLOUT;
			}
		}

		// Этап отправки новых запросов
		if (pfd.revents & POLLOUT) {
			log_debug("Process POLLOUT, cursor = %d", cursor);

			// Если снова вошли в начало этапа отправки, то wait_all_before_pollout больше не нужен
			wait_all_before_pollout = false;

			// Отправляем пакеты, пока не упремся в ограничение квоты или в ошибку отправки
			while (retry_counter > 0 && ctx->results[cursor].status != PORT_STATUS_FILTERED) {
				cursor_advance(cursor, retry_counter, wait_all_before_pollout);
			}

			// Либо мы нашли подходящий порт со статусом FILTERED, либо в итоге число попыток истекло
			if (retry_counter == 0) {
				log_debug("No more retries, disable POLLOUT");
				pfd.events &= ~POLLOUT;
				continue;
			}

			assert(cursor < total_ports);

			// Создаем пакет и пробуем отправить его
			ret = probe_send_one(ctx->sock, ctx->route, ctx->sport, cursor + ctx->dport_start, ctx->tcp_sn);
			log_debug("Packet sent to port %d, with errno %s (%d)", cursor + ctx->dport_start, strerror(ret), ret);

			if (ret < 0) {
				if (ret == ENOBUFS) {
					// Ядро не успевает за нами отправлять запросы, так что сбросим флаг POLLOUT на время
					log_debug("ENOBUFS while trying to send - disable POLLOUT");
					pfd.events &= ~POLLOUT;
					continue;
				}

				// Неизвестная ошибка - прерываем работу
				log_err("Cannot send a packet!");
				return -1;
			}

			// Отправили пакет, переходим к следующему порту
			cursor_advance(cursor, retry_counter, wait_all_before_pollout);
			send_quota--;

			// Если квота закончилась, или если в результате cursor_advance мы прошли весь диапазон - отключаем POLLOUT
			if (send_quota == 0 || wait_all_before_pollout == true) {
				log_debug("Send quota exceeded or cursor moved to the end - disable POLLOUT");
				pfd.events &= ~POLLOUT;
			}
		}
	}

	return 0;
}

int portscan_execute(struct portscan_req *req, struct portscan_result *results)
{
	struct route_info route_info;
	int ret;

	memset(&route_info, 0, sizeof(route_info));

	if (!results) {
		return -1;
	}

	if ((ret = validate_request(req, &route_info)))
		return ret;

	if (fetch_route_info(&route_info) < 0)
		return -1;

	log_route(&route_info, req->dst_ip);

	struct portscan_context ctx = {
		.results     = results,
		.route       = &route_info,
		.dport_start = req->port_start,
		.dport_end   = req->port_end,
	};

	if (portscan_prepare(&ctx) < 0)
		return -1;

	ret = portscan_process(&ctx);

	close(ctx.sock);
	return ret;
}



const char *portscan_version(void)
{
	return PORTSCAN_VERSION;
}

const char *portscan_strstatus(enum port_status status)
{
	switch (status) {
		case PORT_STATUS_OPEN:     return "open";
		case PORT_STATUS_FILTERED: return "filtered";
		case PORT_STATUS_CLOSED:   return "closed";
		default: break;
	}

	return "unknown";
}
