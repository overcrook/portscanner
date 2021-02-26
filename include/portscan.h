#ifndef PORTSCANNER_PORTSCAN_H
#define PORTSCANNER_PORTSCAN_H
#include <netdb.h>
#include <poll.h>

/**
 * Версия библиотеки.
 *
 * Если нужно получить версию у динамическии слинкованной библиотеки, используйте portscan_version()
 */
#define PORTSCAN_VERSION "0.1.0"

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
 * Внутренний контекст сканера портов
 */
struct portscan_context;


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
 * Эта функция реализует весь цикл сканера - подготовку запроса и периодическая оптравка/получение данных.
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
 * Настраивает контекст для работы сканера.
 *
 * Этот контекст содержит все runtime-данные, которые нужны на всем протяжении одного сканирования.
 * Благодаря этому можно выполнять сразу несколько сканирований параллельно.
 *
 * Функция определяет, с какого IP-адреса нужно отправлять запросы, подготавливает raw-сокет AF_INET/AF_INET6,
 * дополнительно настраивает eBPF-фильтр на сокете (для уменьшения нагрузки на ядро и на процесс) и создает timerfd
 * для отслеживания таймаутов ожидания ответов.
 *
 * Созданный контекст затем нужно передавать во все остальные функции на протяжении всего сканирования, а в конце работы
 * - закрыть и освободить функцией portscan_cleanup().
 *
 * @param ctx   - контекст для portscan
 * @retval ctx  - успешно созданный и готовый к работе контекст сканирования.
 * @retval NULL - ошибка создания
 */
struct portscan_context *portscan_prepare(struct portscan_req *req, struct portscan_result *results);


/**
 * Возвращает файловый дескриптор сетевого raw-сокета
 *
 * Этот сокет используется сканером для того, чтобы отправлять с него запросы и слушать ответы.
 * Этот сокет может использоваться в poll() или другом event loop, в качестве reader и/или writer.
 *
 * @param ctx - контекст для portscan
 * @return файловый дескриптор raw-сокета
 */
int portscan_scanfd(const struct portscan_context *ctx);


/**
 * Возвращает файловый дескриптор для ожидания таймаута получения
 *
 * Этот сокет используется сканером для того, чтобы ожидать истечения таймера в event-loop-совместимых приложениях.
 * Этот сокет может использоваться в poll() или другом event loop, в качестве reader.
 *
 * @param ctx - контекст для portscan
 * @return файловый дескриптор timerfd
 */
int portscan_timerfd(const struct portscan_context *ctx);


/**
 * Возвращает битовую маску ожидаемых событий на raw-сокете для poll()
 *
 * Так как периодически нужно отключать отправку запросов (чтобы не допустить флуд), маска ожидаемых событий постоянно
 * меняется. При нормальной работе маска событий равна POLLIN | POLLOUT. Если сканер уже отправил достаточно запросов
 * и уже достиг лимита, то битовая маска будет содержать только POLLIN.
 *
 * Если битовая маска равна 0, то это означает, что сканирование завершено.
 *
 * @param ctx - контекст для portscan
 * @return битовая маска из POLLIN и POLLOUT
 */
int portscan_wanted_events(const struct portscan_context *ctx);


/**
 * Обработчик входящих пакетов на raw-сокете.
 *
 * Обрабатывает только один пакет за раз. Если в итоге пакет будет успешно распознан как ответ на запрос сканера, то
 * сканер снова сможет отправлять события (к маске ожидаемых событий добавляется POLLOUT).
 *
 * @param ctx - контекст для portscan.
 * @retval  1 - сканер продолжает работу;
 * @retval  0 - сканер завершил работу без ошибок;
 * @retval -1 - произошла системная ошибка (см. errno).
 */
int portscan_pollin(struct portscan_context *ctx);


/**
 * Обработчик отправки запросов с raw-сокета.
 *
 * Отправляет столько запросов, сколько может, пока не превысит лимит на отправку, не получит ошибку от ядра или
 * не будет превышено количество попыток.
 * После этого снимает флаг POLLOUT с маски ожидаемых событий.
 *
 * @param ctx - контекст для portscan.
 * @retval  1 - сканер продолжает работу;
 * @retval  0 - сканер завершил работу без ошибок;
 * @retval -1 - произошла системная ошибка (см. errno).
 */
int portscan_pollout(struct portscan_context *ctx);


/**
 * Обработчик таймаута ожидания событий на сокете.
 *
 * Таймаут заводится и снимается автоматически внутри сканера. Таймер заводится при успешной отправке запроса, в этом
 * случае сканер ожидает некоторое время ответа.
 *
 * Таймер заводится только для последнего отправленного пакета. То есть возможна ситуация, когда для какого-то порта
 * ответ будет получен в действительности позже, чем ожидается, но в пределах погрешности это не критично.
 *
 * А вот если таймер срабатывает - это автоматически означает, что для всех портов, на которые были отправлены запросы,
 * не получен ни один ответ, и все они в итоге пропускаются. В таком случае лимит отправки пакетов сбрасывается и
 * сканер переходит к следующей порции портов.
 *
 * @param ctx - контекст для portscan.
 * @retval  1 - сканер продолжает работу;
 * @retval  0 - сканер завершил работу без ошибок;
 * @retval -1 - произошла системная ошибка (см. errno).
 */
int portscan_timeout(struct portscan_context *ctx);



/**
 * Очищает контекст после использования.
 *
 * Функция закрывает открытые файловые дескрипторы и удаляет саму структуру.
 *
 * Эту функцию необходимо вызывать всегда после успешного вызова portscan_prepare().
 *
 * @warning После вызова этой функции все файловые дескрипторы, полученные через portscan_scanfd() и portscan_timerfd(),
 * становятся невалидны. Вызывающая функция должна прекратить работу с этими дескрипторами.
 *
 * @param ctx
 */
void portscan_cleanup(struct portscan_context *ctx);


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
