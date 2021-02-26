#include <sys/types.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
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


struct portscan_context *portscan_prepare(struct portscan_req *req, struct portscan_result *results)
{
	struct route_info route_info;

	memset(&route_info, 0, sizeof(route_info));

	if (!results) {
		return NULL;
	}

	if (validate_request(req, &route_info))
		return NULL;

	if (fetch_route_info(&route_info) < 0)
		return NULL;

	log_route(&route_info, req->dst_ip);

	int sock = socket(route_info.af, SOCK_RAW, IPPROTO_TCP);

	if (sock < 0) {
		plog_err("Cannot open socket(%s, SOCK_RAW, IPPROTO_TCP)", route_info.af == AF_INET6 ? "AF_INET6" : "AF_INET");
		return NULL;
	}

	int timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);

	if (timerfd < 0) {
		plog_err("Cannot create timerfd");
		close(sock);
		return NULL;
	}

	struct portscan_context *ctx = calloc(1, sizeof(*ctx));

	ctx->sock = sock;
	ctx->timerfd = timerfd;
	ctx->results = results;
	ctx->dport_start = req->port_start;
	ctx->dport_end   = req->port_end;
	ctx->total_ports = req->port_end - req->port_start + 1;
	ctx->send_quota = SEND_QUOTA_MAX;
	ctx->retry_counter  = RETRY_LIMIT;
	ctx->events = POLLIN | POLLOUT;
	memcpy(&ctx->route, &route_info, sizeof(route_info));

	for (int i = 0; i <= ctx->dport_end - ctx->dport_start; i++) {
		ctx->results[i].port   = ctx->dport_start + i;
		ctx->results[i].status = PORT_STATUS_FILTERED;
	}

	// Генерируем рандомный порт в диапазоне 32768-61000
	ctx->sport = rand() % (61000 - 32768) + 32768;

	// Генерируем рандомный sequence number
	ctx->tcp_sn = rand();

	if (bpf_attach_filter(ctx->sock, ctx)) {
		log_info("eBPF feature is disabled, all received packets will be filtered by userland.");
	}

	return ctx;
}


/**
 * Сдвигает курсор на следующую позицию с учетом возможного завершения диапазона
 *
 * Если курсор вышел за пределы диапазона, то он устанавливается обратно в 0.
 * Число попыток при этом уменьшается, и дополнительно выставляется признак ожидания всех ответов
 * перед началом работы с новой попыткой.
 */
#define cursor_advance(ctx) do { \
	if (++(ctx)->cursor >= (ctx)->total_ports) {                            \
	    (ctx)->retry_counter--;                                             \
	    (ctx)->cursor = 0;                                                  \
	}                                                                       \
} while (0)

static inline int timerfd_oneshot(int tfd, int timeout)
{
	struct itimerspec spec = {
		.it_value = {
			.tv_sec = timeout / 1000,
			.tv_nsec = (timeout % 1000) * 1000000
		}
	};

	return timerfd_settime(tfd, 0, &spec, NULL);
}

static inline int portscan_continue(struct portscan_context *ctx)
{
	return ctx->answered_ports < ctx->total_ports;
}

int portscan_pollin(struct portscan_context *ctx)
{
	log_debug("Process POLLIN");
	struct portscan_result result;

	// Пробуем прочитать ответ и сопоставить его с нашими данными
	if (probe_recv_one(ctx->sock, &ctx->route, ctx->sport, ctx->dport_start, ctx->dport_end, ctx->tcp_sn, &result) < 0)
		return portscan_continue(ctx);

	// Нашли ответ - проверим, что мы не получали его раньше, и занесем в массив ответов
	int index = result.port - ctx->dport_start;

	assert(index < ctx->total_ports);

	if (ctx->results[index].status != PORT_STATUS_FILTERED) {
		plog_warning("Found another response for port %u (TCP retransmission?)", result.port);
		return portscan_continue(ctx);
	}

	// Это новый ответ - сохраняем его
	memcpy(&ctx->results[index], &result, sizeof(result));
	ctx->answered_ports++;

	log_debug("Successfully processed one response - increase send_quota");
	ctx->send_quota++;

	// Если нам не нужно дожидаться все ответы, или если нужно, но квота уже полна  - включаем режим отправки
	if (ctx->send_quota == SEND_QUOTA_MAX) {
		log_debug("POLLOUT is allowed now - enable POLLOUT");
		ctx->events |= POLLOUT;
	}

	return portscan_continue(ctx);
}

int portscan_pollout(struct portscan_context *ctx)
{
	log_debug("Process POLLOUT, cursor = %d", ctx->cursor);

	// Отправляем пакеты, пока не упремся в ограничение квоты или в ошибку отправки
	while (ctx->retry_counter > 0 && ctx->results[ctx->cursor].status != PORT_STATUS_FILTERED) {
		cursor_advance(ctx);
	}

	// Либо мы нашли подходящий порт со статусом FILTERED, либо в итоге число попыток истекло
	if (ctx->retry_counter == 0) {
		log_debug("No more retries, disable POLLOUT");
		ctx->events &= ~POLLOUT;
		return portscan_continue(ctx);
	}

	assert(ctx->cursor < ctx->total_ports);

	// Создаем пакет и пробуем отправить его
	int ret = probe_send_one(ctx->sock, &ctx->route, ctx->sport, ctx->cursor + ctx->dport_start, ctx->tcp_sn);
	log_debug("Packet sent to port %d, with errno %s (%d)", ctx->cursor + ctx->dport_start, strerror(ret), ret);

	if (ret < 0) {
		if (ret == ENOBUFS) {
			// Ядро не успевает за нами отправлять запросы, так что сбросим флаг POLLOUT на время
			log_debug("ENOBUFS while trying to send - disable POLLOUT");
			ctx->events &= ~POLLOUT;
			return portscan_continue(ctx);
		}

		// Неизвестная ошибка - прерываем работу
		log_err("Cannot send a packet!");
		return -1;
	}

	// Отправили пакет, переходим к следующему порту
	cursor_advance(ctx);
	ctx->send_quota--;
	timerfd_oneshot(ctx->timerfd, 1000);

	// Если квота закончилась, или если в результате cursor_advance мы прошли весь диапазон - отключаем POLLOUT
	if (ctx->send_quota == 0) {
		log_debug("Send quota exceeded - disable POLLOUT");
		ctx->events &= ~POLLOUT;
	}

	// Если мы в итоге сделали полный цикл, то отключаем отправку
	if (ctx->cursor == 0) {
		log_debug("Сursor moved to the end - disable POLLOUT");
		ctx->events &= ~POLLOUT;
	}

	return portscan_continue(ctx);
}

int portscan_timeout(struct portscan_context *ctx)
{
	log_debug("timeout");
	// Таймаут при ожидании доступных действий
	uint64_t expires;
	read(ctx->timerfd, &expires, sizeof(expires));

	if (ctx->retry_counter == 0) {
		// Число попыток отправки пакетов уже превышено, нам больше нечего отправлять
		return 0;
	}

	// Все порты, для которых мы ждали ответы, так и останутся отмеченными как filtered.
	// Очищаем квоту и продолжаем спам дальше.
	log_debug("timeout waiting responses - refill send_quota and enable POLLOUT");
	ctx->send_quota = SEND_QUOTA_MAX;
	ctx->events |= POLLOUT;
	return portscan_continue(ctx);
}

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
static int portscan_process(struct portscan_context *ctx)
{
	int ret;

	// Крутимся в цикле до тех пор, пока не обработаем все порты (или пока он не будет прерван извне)
	while (1) {
		struct pollfd pfd[2] = {
			{
				.fd     = ctx->timerfd,
				.events = POLLIN
			}, {
				.fd     = ctx->sock,
				.events = ctx->events,
			}
		};

		log_debug("Start iteration, current status: retry_counter=%d cursor=%d answered_ports=%d send_quota=%d",
		          ctx->retry_counter, ctx->cursor, ctx->answered_ports, ctx->send_quota);

		ret = poll(pfd, 2, -1);
		log_debug("poll() returned: %d", ret);

		if (ret < 0) {
			plog_err("Error on poll");
			return -1;
		}

		if (pfd[0].revents & POLLIN) {
			ret = portscan_timeout(ctx);

			if (ret <= 0)
				break;
		}

		// Этап получения ответов
		if (pfd[1].revents & POLLIN) {
			ret = portscan_pollin(ctx);

			if (ret <= 0)
				break;
		}

		// Этап отправки новых запросов
		if (pfd[1].revents & POLLOUT && portscan_pollout(ctx)) {
			ret = portscan_pollout(ctx);

			if (ret <= 0)
				break;
		}
	}

	return ret;
}

void portscan_cleanup(struct portscan_context *ctx)
{
	if (!ctx)
		return;

	close(ctx->sock);
	close(ctx->timerfd);
	free(ctx);
}

int portscan_execute(struct portscan_req *req, struct portscan_result *results)
{
	struct portscan_context *ctx = portscan_prepare(req, results);

	if (!ctx)
		return -1;

	int ret = portscan_process(ctx);

	portscan_cleanup(ctx);
	return ret;
}


int portscan_scanfd(const struct portscan_context *ctx)
{
	return ctx ? ctx->sock : -1;
}

int portscan_timerfd(const struct portscan_context *ctx)
{
	return ctx ? ctx->timerfd : -1;
}

int portscan_wanted_events(const struct portscan_context *ctx)
{
	return ctx ? ctx->events : 0;
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
