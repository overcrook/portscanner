#ifndef PORTSCANNER_BPF_H
#define PORTSCANNER_BPF_H
#include "portscan_context.h"

/**
 * Устанавливает фильтр eBPF на сокет для фильтрации только ожидаемых пакетов
 *
 * Нужен для того, чтобы уменьшить нагрузку на ядро и на приложение.
 *
 * @param sock - сокет, на который нужно навесить фильтр;
 * @param ctx  - заполненный контекст сканера;
 * @return  0 - успех;
 * @return -1 - ошибка (см errno).
 */
int bpf_attach_filter(int sock, const struct portscan_context *ctx);

#endif //PORTSCANNER_BPF_H
