#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <portscan.h>
#include <syslog.h>

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
	}

	return (*delim == '\0') ? 0 : -1;
}

static void parse_args(int argc, char *const argv[], struct portscan_req *req)
{
	const struct option long_options[] = {
		{"source",     required_argument, 0, 's'},
		{"dest",       required_argument, 0, 'd'},
		{"interface",  required_argument, 0, 'i'},
		{"ports",      required_argument, 0, 'p'},
		{"help",       required_argument, 0, 'h'},
		{"version",    required_argument, 0, 'v'},
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
	struct portscan_req req;
	int ret;

	memset(&req, 0, sizeof(req));
	parse_args(argc, argv, &req);

	openlog("portscan", LOG_PERROR | LOG_CONS | LOG_PID, LOG_USER);
	ret = portscan_execute(&req, NULL);
	closelog();

	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
