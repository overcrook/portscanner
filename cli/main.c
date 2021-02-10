#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <portscan.h>
#include <syslog.h>
#include <time.h>

#define BIT(x)  (1UL << x)

struct cli_options {
	uint8_t show_filter;
};

__attribute__((noreturn))
static void usage(int exitcode)
{
	FILE *out = (exitcode == EXIT_SUCCESS) ? stdout : stderr;

	fprintf(out, "Usage:\n");
	exit(exitcode);
}

static void show_version(void)
{
	fprintf(stdout, "Port scanner version %s", portscan_version());
}

static void parse_show_filter(struct cli_options *options, const char *source)
{
	char *source_copy = strdup(source);
	char *saveptr = NULL;
	char *strtok_tmp = source_copy;

	// Сбрасываем текущий фильтр, настраиваем заново
	options->show_filter = 0;

	for (const char *token; (token  = strtok_r(strtok_tmp, ",", &saveptr)); strtok_tmp = NULL) {
		if (!strcasecmp(token, "open"))
			options->show_filter |= BIT(PORT_STATUS_OPEN);
		else if (!strcasecmp(token, "filtered"))
			options->show_filter |= BIT(PORT_STATUS_FILTERED);
		else if (!strcasecmp(token, "closed"))
			options->show_filter |= BIT(PORT_STATUS_CLOSED);
		else
			usage(EXIT_FAILURE);
	}

	if (options->show_filter == 0)
		usage(EXIT_FAILURE);

	free(source_copy);
}

static inline int parse_ports(struct portscan_req *req, const char *source)
{
	unsigned long val;
	char *delim;

	if (!source || source[0] == '-')
		return -1;

	// parse start port
	val = strtoul(source, &delim, 10);

	if (val == 0 || val > 65535)
		return -1;

	req->port_start = val;

	if (*delim == '-') {
		// parse end port
		val = strtoul(delim + 1, &delim, 10);

		if (val == 0 || val > 65535)
			return -1;

		req->port_end = val;
	} else {
		req->port_end = req->port_start;
	}

	if (*delim != '\0')
		return -1;

	if (req->port_start == 0 || req->port_start > 65535 || req->port_end < req->port_start || req->port_end > 65535) {
		usage(EXIT_FAILURE);
		return -1; // unreachable
	}

	return 0;
}

static void parse_args(int argc, char *const argv[], struct portscan_req *req, struct cli_options *options)
{
	const struct option long_options[] = {
		{"source",          required_argument, 0, 's'},
		{"dest",            required_argument, 0, 'd'},
		{"interface",       required_argument, 0, 'i'},
		{"ports",           required_argument, 0, 'p'},
		{"show",            required_argument, 0, 1},
		{"help",            required_argument, 0, 'h'},
		{"version",         required_argument, 0, 'v'},
		{0, 0, 0, 0}
	};

	while (1) {
		int option_index = 0;
		int opt = getopt_long(argc, argv, "hvs:d:i:p:", long_options, &option_index);

		if (opt == -1)
			break;

		switch (opt) {
			case 's':
				req->src_ip = optarg;
				break;

			case 'd':
				req->dst_ip = optarg;
				break;

			case 'i':
				req->interface = optarg;
				break;

			case 'p':
				if (parse_ports(req, optarg))
					usage(EXIT_FAILURE);

				break;

			case 1:
				parse_show_filter(options, optarg);
				break;

			case 'h':
				usage(EXIT_SUCCESS);
				break;

			case 'v':
				show_version();
				exit(EXIT_SUCCESS);

			default:
				usage(EXIT_FAILURE);
				break;
		}
	}
}

int main(int argc, char *const argv[])
{
	struct cli_options options;
	struct portscan_req req;
	struct portscan_result *results;
	int ret;

	memset(&req, 0, sizeof(req));
	memset(&options, 0, sizeof(options));
	options.show_filter = BIT(PORT_STATUS_OPEN) | BIT(PORT_STATUS_FILTERED);

	parse_args(argc, argv, &req, &options);

	size_t results_count = req.port_end - req.port_start + 1;
	results = malloc(sizeof(struct portscan_result) * results_count);

	if (!results) {
		fprintf(stderr, "Cannot allocate memory!\n");
		exit(EXIT_FAILURE);
	}

	openlog("portscan", LOG_PERROR | LOG_CONS | LOG_PID, LOG_USER);
	srand(time(NULL));
	ret = portscan_execute(&req, results);
	closelog();

	if (ret == 0) {
		printf("Port scan result for %s\n", req.dst_ip);

		for (int i = 0; i <= req.port_end - req.port_start; i++) {
			int status = results[i].status;

			if ((options.show_filter & BIT(status)) == 0)
				continue;

			printf(" %d/tcp  \t%s\n", results[i].port, portscan_strstatus(status));
		}
	}

	free(results);
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
