#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <assert.h>

#include "packet.h"
#include "log.h"

// Максимальный размер окна TCP с учетом MTU 1500 и размеров заголовков TCP (20) и IP (20)
// Максимальный MSS - 1460 (1500 - 20 - 20),
// 1460 * 44 = 64240 - умещается в поле 16 бит (максимум 65535)
// 1460 * 45 = 65700 - уже не умещается
#define TCP_MAX_WINDOW 64240

/**
 * Рассчитывает стандартную контрольную сумму для последовательности байт.
 *
 * Алгоритм расчета соответствует https://tools.ietf.org/html/rfc1071.
 * Последовательность байт расценивается как массив чисел uint16_t, которые последовательно суммируются друг с другом,
 * попадая в сумматор размерностью uint32_t. Если число байт не кратно 2, то последний байт дополняется нулем справа и
 * суммируется с остальными.
 * После прохода всей последовательности сумматор делится на верхнюю и нижнюю половины, которые суммируются между собой.
 * Результат инвертируется для того, чтобы затем при расчете контрольной суммы во время валидации получить значение FFFF.
 *
 * @param cksum - текущее значение контрольной суммы в host byte-order (0 при первом подсчете);
 * @param bytes - массив байт, для которого надо рассчитать контрольную сумму;
 * @param size  - размер массива;
 * @return новая контрольная сумма в host byte-order..
 */
static int sum_data(uint16_t cksum, const void *bytes, size_t size)
{
	const uint16_t *bytes16 = bytes; // TODO: стоит копировать данные, чтобы избежать нарушения strict aliasing rules
	const uint8_t  *bytes8  = bytes;
	uint32_t acc = cksum;

	for (size_t i = 0; i < size / 2; i++)
		acc += bytes16[i];

	if (size % 2)
		acc += bytes8[size - 1] << 16;

	cksum = (acc & 0xFFFF) + (acc >> 16);
	return cksum;
}

/**
 * Рассчитывает контрольную сумму TCP для TCP-пакета.
 *
 * Алгоритм расчета соответствует https://tools.ietf.org/html/rfc793#section-3.1 и https://tools.ietf.org/html/rfc2460#section-8.1.
 *
 * Для расчета контрольной суммы TCP нужно дополнительно составить и посчитать контрольную сумму для псевдо-заголовка
 * IP. Затем считается контрольная сумма как обычно от самого заголовка TCP и от полезных данных.
 *
 * Предполагается, что отправляется всего один TCP-заголовок без полезной нагрузки.
 *
 * @param setup_info - информация о TCP-сессии
 * @param hdr        - TCP-заголовок
 * @return контрольная сумма в host byte-order.
 */
static uint16_t calculate_tcp_cksum(const struct tcp_setup *setup_info, struct tcphdr *hdr)
{
	uint16_t cksum = 0;
	uint16_t next_hdr = htons(IPPROTO_TCP); // захватим сразу два байта

	// Для IPv4 и IPv6 нужны разные псевдозаголовки, поэтому проще просто посчитать контрольную сумму от нужных полей.
	if (setup_info->route->af == AF_INET6) {
		// Посчитаем сумму для псевдо-IPv6 заголовка
		uint32_t tcp_len = htonl(sizeof(struct tcphdr));

		cksum = sum_data(cksum, &setup_info->route->src, sizeof(struct in6_addr));
		cksum = sum_data(cksum, &setup_info->route->dst, sizeof(struct in6_addr));
		cksum = sum_data(cksum, &next_hdr, sizeof(next_hdr));
		cksum = sum_data(cksum, &tcp_len,  sizeof(tcp_len));
	} else {
		// Посчитаем сумму для псевдо-IPv4 заголовка
		uint16_t tcp_len = htons(sizeof(struct tcphdr));

		cksum = sum_data(cksum, &setup_info->route->src, sizeof(struct in_addr));
		cksum = sum_data(cksum, &setup_info->route->dst, sizeof(struct in_addr));
		cksum = sum_data(cksum, &next_hdr, sizeof(next_hdr));
		cksum = sum_data(cksum, &tcp_len,  sizeof(tcp_len));
	}

	cksum = sum_data(cksum, hdr, sizeof(*hdr));

	return ~cksum;
}


/**
 * Заполняет заголовок TCP всеми необходимыми данными для отправки.
 *
 * Предполагается, что отправляется всего один TCP-заголовок без полезной нагрузки.
 *
 * @param setup_info - информация о требуемой TCP-сессии
 * @param hdr        - TCP-заголовок
 */
static void packet_craft_tcp(const struct tcp_setup *setup_info, struct tcphdr *hdr)
{
	hdr->th_sport = htons(setup_info->src_port);
	hdr->th_dport = htons(setup_info->dst_port);
	hdr->seq      = htonl(setup_info->sn);
	hdr->ack      = 0;
	hdr->doff     = 5;
	// flags
	hdr->syn      = 1;
	// flags end
	hdr->window   = htons(TCP_MAX_WINDOW);

	// must be last
	hdr->check    = calculate_tcp_cksum(setup_info, hdr);
}


int packet_craft(const struct tcp_setup *setup_info, uint8_t *packet, size_t packet_size)
{
	assert(setup_info && packet);

	struct tcphdr *tcphdr;
	size_t crafted_size = sizeof(struct tcphdr);

	if (packet_size < crafted_size) {
		log_err("Packet size is too small: %zu bytes needed but only %zu provided", crafted_size, packet_size);
		return -1;
	}

	memset(packet, 0, crafted_size);
	tcphdr = (struct tcphdr *) packet;

	packet_craft_tcp(setup_info, tcphdr);

	return crafted_size;
}
