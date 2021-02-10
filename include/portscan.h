#ifndef PORTSCANNER_PORTSCAN_H
#define PORTSCANNER_PORTSCAN_H
#include <netdb.h>

/**
 * Версия библиотеки.
 *
 * Если нужно получить версию у динамическии слинкованной библиотеки, используйте portscan_version()
 */
#define PORTSCAN_VERSION "0.0.1"

/**
 * Возможные состояния порта
 */
enum port_status {
	/// Порт находится за файрволом, блокирующим точное определение состояния (либо адрес недоступен)
	PORT_STATUS_FILTERED,

	/// Порт открыт (получен ответный пакет TCP SYN-ACK)
	PORT_STATUS_OPEN,

	/// Порт закрыт (получен ответный пакет TCP RST)
	PORT_STATUS_CLOSED,
};


/**
 * Форма для запроса сканирования портов
 *
 * @note Предполагается, что *src_ip*, если он задан, соответствует адресу, с которого действительно
 * есть доступ к целевой машине. Единственное полезное использование для этих опций - явно указать исходящий
 * адрес в ситуации, когда настроено несколько адресов/подсетей и стандартный маршрут (см `ip route get`) отличается от
 * требуемого маршрута до целевой машины.
 * Если неверно указать эти данные, то сканер портов не сможет добраться до целевой машины и все порты будут помечены
 * как `filtered`.
 */
struct portscan_req {
	/// Адрес источника (если не задан, будет определен автоматически на основе таблицы маршрутизации)
	const char *src_ip;

	/// Адрес назначения
	const char *dst_ip;

	/// Начальное значение диапазона сканируемых портов
	int port_start;

	/// Конечное значение диапазона сканируемых портов
	int port_end;
};


/**
 * Структура с описанием одного результата - состояние для одного порта
 */
struct portscan_result {
	in_port_t port;           ///< Номер порта
	enum port_status status;  ///< Статус порта (open, filtered, closed)
};


/**
 * Выполняет сканирование портов от начала и до конца.
 *
 * Предварительно нужно настроить структуру запроса *req*, чтобы указать адрес назначения, диапазон портов, другие
 * опции по желанию.
 *
 * Перед вызовом нужно заранее подготовить массив под результаты *results* - его размер должен совпадать с числом портов
 * в диапазоне (т.е. `port_end - port_start + 1`).
 *
 * Функция отправляет TCP SYN-пакеты на адрес назначения по указанному диапазону портов. Этот быстрый способ
 * сканирования позволяет определить доступные для подключения порты, не нагружая целевую машину, так как TCP-сессия
 * обрывается, не установившись (и соответственно, сервер не обрабатывает эту попытку сканирования).
 *
 * Затем начинается ожидание ответов. В течение определенного таймаута функция ожидает получить либо TCP SYN-ACK
 * (для открытого порта), либо TCP RST (для закрытого порта). Если за указанный таймаут никакого ответа не последовало,
 * то порт считается фильтруемым.
 *
 * @param req     - параметры запроса;
 * @param results - массив для заполнения результатов опроса.
 * @retval 0  - успешное сканирование (результаты заполнены в *results*;
 * @retval -1 - ошибка вызова функции либо ошибка сканирования.
 */
int portscan_execute(struct portscan_req *req, struct portscan_result *results);


/**
 * Возвращает версию библиотеки в строковой форме
 *
 * @note Строка не имеет определенного формата и не предполагает машинный разбор.
 *
 * @return строка с версией библиотеки
 */
const char *portscan_version(void);


/**
 * Возвращает строковое значение состояния порта (open, filtered, closed)
 *
 * @param status - состояние порта
 * @return строковое значение состояния порта
 */
const char *portscan_strstatus(enum port_status status);


#endif //PORTSCANNER_PORTSCAN_H
