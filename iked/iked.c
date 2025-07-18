/*	$OpenBSD: iked.c,v 1.72 2024/12/26 18:24:54 sthen Exp $	*/

/*
 * Copyright (c) 2019 Tobias Heider <tobias.heider@stusta.de>
 * Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>
#ifdef __APPLE__
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <err.h>
#include <pwd.h>
#include <event.h>

#include "iked.h"
#include "ikev2.h"
#include "version.h"

#ifdef WITH_APPARMOR
#include "apparmor.h"
#endif

__dead void usage(void);

/* Saves a copy of argv for setproctitle emulation */
#ifndef HAVE_SETPROCTITLE
static char **saved_av;
#endif

void	 parent_shutdown(struct iked *);
void	 parent_sig_handler(int, short, void *);
int	 parent_dispatch_ca(int, struct privsep_proc *, struct imsg *);
int	 parent_dispatch_control(int, struct privsep_proc *, struct imsg *);
int	 parent_dispatch_ikev2(int, struct privsep_proc *, struct imsg *);
void	 parent_connected(struct privsep *);
int	 parent_configure(struct iked *);

struct iked	*iked_env;
//FUZZ
static int end_of_msgs_count = 0;

static struct privsep_proc procs[] = {
	{ "ca",		PROC_CERT,	parent_dispatch_ca, caproc, IKED_CA },
	{ "control",	PROC_CONTROL,	parent_dispatch_control, control },
	{ "ikev2",	PROC_IKEV2,	parent_dispatch_ikev2, ikev2 }
};

__dead void
usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-dnSTtVv] [-D macro=value] "
	    "[-f file] [-p udpencap_port] [-s socket]\n", __progname);
	exit(1);
}

int 
get_metadata(uint8_t *compartment, uint32_t *type, uint32_t *id, pid_t *pid, size_t *datalen)
{ 
	ssize_t bytes_read; uint8_t
		buf[sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(pid_t) + sizeof(size_t)]; 
	size_t offset = 0;

	bytes_read = read(STDIN_FILENO, buf, sizeof(buf)); 
	if (bytes_read != sizeof(buf)) 
		return (-1);

	memcpy(compartment, buf + offset, sizeof(uint8_t)); 
	offset += sizeof(uint8_t);

	memcpy(type, buf + offset, sizeof(uint32_t)); 
	offset += sizeof(uint32_t);

	memcpy(id, buf + offset, sizeof(uint32_t)); 
	offset += sizeof(uint32_t);

	memcpy(pid, buf + offset, sizeof(pid_t)); 
	offset += sizeof(pid_t);

	memcpy(datalen, buf + offset, sizeof(size_t));

	return 0; 
}

size_t
get_payload(size_t datalen, char *buf)
{
	ssize_t bytes_read;
	size_t total_read = 0;

	while (total_read < datalen)
	{
		bytes_read = read(STDIN_FILENO, buf + total_read, datalen - total_read);
		if (bytes_read <= 0)
		{
			break;
		}
		total_read += bytes_read;
	}

	return (total_read);
}

int
main(int argc, char *argv[])
{
	int			 c;
	int			 debug = 0, verbose = 0;
	int			 opts = 0;
	enum natt_mode		 natt_mode = NATT_DEFAULT;
	in_port_t		 port = IKED_NATT_PORT;
	const char		*conffile = IKED_CONFIG;
	const char		*sock = IKED_SOCKET;
	const char		*errstr, *title = NULL;
	struct iked		*env = NULL;
	struct privsep		*ps;
	enum privsep_procid	 proc_id = PROC_PARENT;
	int			 proc_instance = 0;
	int			 argc0 = argc;

	log_init(1, LOG_DAEMON);

#ifndef HAVE_SETPROCTITLE
	int		 i;
	saved_av = calloc(argc + 1, sizeof(*saved_av));
	if (saved_av == NULL)
		errx(1, "calloc");
	for (i = 0; i < argc; i++) {
		saved_av[i] = strdup(argv[i]);
		if (saved_av[i] == NULL)
			errx(1, "strdup");
	}
	saved_av[i] = NULL;
	compat_init_setproctitle(argc, argv);
	argv = saved_av;
#endif

	while ((c = getopt(argc, argv, "6D:df:I:nP:p:Ss:TtvV")) != -1) {
		switch (c) {
		case '6':
			log_warnx("the -6 option is ignored and will be "
			    "removed in the future.");
			break;
		case 'D':
			if (cmdline_symset(optarg) < 0)
				log_warnx("could not parse macro definition %s",
				    optarg);
			break;
		case 'd':
			debug++;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'I':
			proc_instance = strtonum(optarg, 0,
			    PROC_MAX_INSTANCES, &errstr);
			if (errstr)
				fatalx("invalid process instance");
			break;
		case 'n':
			debug = 1;
			opts |= IKED_OPT_NOACTION;
			break;
		case 'P':
			title = optarg;
			proc_id = proc_getid(procs, nitems(procs), title);
			if (proc_id == PROC_MAX)
				fatalx("invalid process name");
			break;
		case 'p':
			if (natt_mode == NATT_DISABLE)
				errx(1, "-T and -p are mutually exclusive");
			port = strtonum(optarg, 1, UINT16_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "port is %s: %s", errstr, optarg);
			natt_mode = NATT_FORCE;
			break;
		case 'S':
			opts |= IKED_OPT_PASSIVE;
			break;
		case 's':
			sock = optarg;
			break;
		case 'T':
			if (natt_mode == NATT_FORCE)
				errx(1, "-T and -t/-p are mutually exclusive");
			natt_mode = NATT_DISABLE;
			break;
		case 't':
			if (natt_mode == NATT_DISABLE)
				errx(1, "-T and -t are mutually exclusive");
			natt_mode = NATT_FORCE;
			break;
		case 'v':
			verbose++;
			opts |= IKED_OPT_VERBOSE;
			break;
		case 'V':
			fprintf(stderr, "OpenIKED %s\n", IKED_VERSION);
			return 0;
		default:
			usage();
		}
	}

	/* log to stderr until daemonized */
	log_init(debug ? debug : 1, LOG_DAEMON);

	argc -= optind;
	if (argc > 0)
		usage();

	if ((env = calloc(1, sizeof(*env))) == NULL)
		fatal("calloc: env");

	iked_env = env;
	env->sc_opts = opts;
	env->sc_nattmode = natt_mode;
	env->sc_nattport = port;
#ifdef WITH_APPARMOR
	env->sc_apparmor = armor_proc_open();
#endif

	ps = &env->sc_ps;
	ps->ps_env = env;

	if (strlcpy(env->sc_conffile, conffile, PATH_MAX) >= PATH_MAX)
		errx(1, "config file exceeds PATH_MAX");

	ca_sslinit();
	group_init();
	policy_init(env);

	if ((ps->ps_pw =  getpwnam(IKED_USER)) == NULL)
		errx(1, "unknown user %s", IKED_USER);

	/* Configure the control socket */
	ps->ps_csock.cs_name = sock;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if (opts & IKED_OPT_NOACTION)
		ps->ps_noaction = 1;
	else {
		/* check for root privileges */
		if (geteuid())
			errx(1, "need root privileges");
	}

	ps->ps_instance = proc_instance;
	if (title != NULL)
		ps->ps_title[proc_id] = title;

	/* only the parent returns */
	proc_init(ps, procs, nitems(procs), debug, argc0, argv, proc_id);

	setproctitle("parent");
	log_procinit("parent");

	event_init();
	
	//FUZZ
	/*
	signal_set(&ps->ps_evsigint, SIGINT, parent_sig_handler, ps);
	signal_set(&ps->ps_evsigterm, SIGTERM, parent_sig_handler, ps);
	signal_set(&ps->ps_evsigchld, SIGCHLD, parent_sig_handler, ps);
	signal_set(&ps->ps_evsighup, SIGHUP, parent_sig_handler, ps);
	signal_set(&ps->ps_evsigpipe, SIGPIPE, parent_sig_handler, ps);
	signal_set(&ps->ps_evsigusr1, SIGUSR1, parent_sig_handler, ps);

	signal_add(&ps->ps_evsigint, NULL);
	signal_add(&ps->ps_evsigterm, NULL);
	signal_add(&ps->ps_evsigchld, NULL);
	signal_add(&ps->ps_evsighup, NULL);
	signal_add(&ps->ps_evsigpipe, NULL);
	signal_add(&ps->ps_evsigusr1, NULL);
	*/

#if defined(HAVE_VROUTE)
	vroute_init(env);
#endif

	proc_connect(ps, parent_connected);

	//FUZZ: START
	struct imsgbuf ctl_ibuf;
	int ctl_fd = ps->ps_pipes[PROC_CONTROL][0].pp_pipes[PROC_PARENT][0];
	imsgbuf_init(&ctl_ibuf, ctl_fd);

	struct imsgbuf cert_ibuf;
	int cert_fd = ps->ps_pipes[PROC_CERT][0].pp_pipes[PROC_PARENT][0];
	imsgbuf_init(&cert_ibuf, cert_fd);

	struct imsgbuf ikev2_ibuf;
	int ikev2_fd = ps->ps_pipes[PROC_IKEV2][0].pp_pipes[PROC_PARENT][0];
	imsgbuf_init(&ikev2_ibuf, ikev2_fd);

	while (1)
	{
		uint8_t compartment;
		uint32_t type;
		uint32_t id;
		pid_t pid;
		size_t datalen;

		char payload[65535];
		size_t payload_size;

		if (get_metadata(&compartment, &type, &id, &pid, &datalen) != 0)
			break;

		/* Ensure values are within valid ranges */
		compartment = compartment % (PROC_MAX - 1) + 1;
		type = type % IMSG_TYPE_COUNT;
		if (datalen > 65535)
			datalen = 65535;

		payload_size = get_payload(datalen, payload);

		struct imsgbuf *target_ibuf = NULL;
		switch (compartment)
		{
			case PROC_CONTROL:
				target_ibuf = &ctl_ibuf;
				break;
			case PROC_CERT:
				target_ibuf = &cert_ibuf;
				break;
			case PROC_IKEV2:
				target_ibuf = &ikev2_ibuf;
				break;
		}

		if (target_ibuf != NULL)
		{
			imsg_compose(target_ibuf, type, id, pid, -1, payload, payload_size);
			printf("compose! payload size is %lu, and compartment ID is %d\n\n", payload_size, compartment);
			imsgbuf_flush(target_ibuf);
		}
	}

	// Send IMSG_END_OF_MSGS to all compartments to signal end of input
	imsg_compose(&ctl_ibuf, IMSG_END_OF_MSGS, 0, 0, -1, NULL, 0);
	imsgbuf_flush(&ctl_ibuf);

	imsg_compose(&cert_ibuf, IMSG_END_OF_MSGS, 0, 0, -1, NULL, 0);
	imsgbuf_flush(&cert_ibuf);

	imsg_compose(&ikev2_ibuf, IMSG_END_OF_MSGS, 0, 0, -1, NULL, 0);
	imsgbuf_flush(&ikev2_ibuf);

	printf("before event_dispatch!\n");
	//FUZZ: END

	event_dispatch();

	log_debug("%d parent exiting", getpid());
	parent_shutdown(env);

	return (0);
}

void
parent_connected(struct privsep *ps)
{
	struct iked	*env = ps->ps_env;

	if (parent_configure(env) == -1)
		fatalx("configuration failed");
}

int
parent_configure(struct iked *env)
{
	struct sockaddr_storage	 ss;

	if (parse_config(env->sc_conffile, env) == -1) {
		proc_kill(&env->sc_ps);
		exit(1);
	}

	if (env->sc_opts & IKED_OPT_NOACTION) {
		fprintf(stderr, "configuration OK\n");
		proc_kill(&env->sc_ps);
		exit(0);
	}

	env->sc_pfkey = -1;
	config_setpfkey(env);

	/* Send private and public keys to cert after forking the children */
	if (config_setkeys(env) == -1)
		fatalx("%s: failed to send keys", __func__);
	config_setreset(env, RESET_CA, PROC_CERT);

	/* Now compile the policies and calculate skip steps */
	config_setcompile(env, PROC_IKEV2);

	bzero(&ss, sizeof(ss));
	ss.ss_family = AF_INET;

#ifdef __APPLE__
	int nattport = env->sc_nattport;
	sysctlbyname("net.inet.ipsec.esp_port", NULL, NULL, &nattport, sizeof(nattport));
#endif

	/* see comment on config_setsocket() */
	if (env->sc_nattmode != NATT_FORCE)
		config_setsocket(env, &ss, htons(IKED_IKE_PORT), PROC_IKEV2, 0);
	if (env->sc_nattmode != NATT_DISABLE)
		config_setsocket(env, &ss, htons(env->sc_nattport), PROC_IKEV2, 1);

	bzero(&ss, sizeof(ss));
	ss.ss_family = AF_INET6;

	if (env->sc_nattmode != NATT_FORCE)
		config_setsocket(env, &ss, htons(IKED_IKE_PORT), PROC_IKEV2, 0);
	if (env->sc_nattmode != NATT_DISABLE)
		config_setsocket(env, &ss, htons(env->sc_nattport), PROC_IKEV2, 1);

	/*
	 * pledge in the parent process:
	 * It has to run fairly late to allow forking the processes and
	 * opening the PFKEY socket and the listening UDP sockets (once)
	 * that need the bypass ioctls that are never allowed by pledge.
	 *
	 * Other flags:
	 * stdio - for malloc and basic I/O including events.
	 * rpath - for reload to open and read the configuration files.
	 * proc - run kill to terminate its children safely.
	 * dns - for reload and ocsp connect.
	 * inet - for ocsp connect.
	 * route - for using interfaces in iked.conf (SIOCGIFGMEMB)
	 * wroute - for adding and removing addresses (SIOCAIFGMEMB)
	 * sendfd - for ocsp sockets.
	 */
	if (pledge("stdio rpath proc dns inet route wroute sendfd", NULL) == -1)
		fatal("pledge");

	config_setstatic(env);
	config_setcoupled(env, env->sc_decoupled ? 0 : 1);
	config_setocsp(env);
	/* Must be last */
	config_setmode(env, env->sc_passive ? 1 : 0);

	return (0);
}

void
parent_reload(struct iked *env, int reset, const char *filename)
{
	/* Switch back to the default config file */
	if (filename == NULL || *filename == '\0')
		filename = env->sc_conffile;

	log_debug("%s: level %d config file %s", __func__, reset, filename);

	if (reset == RESET_RELOAD) {
		config_setreset(env, RESET_POLICY, PROC_IKEV2);
		if (config_setkeys(env) == -1)
			fatalx("%s: failed to send keys", __func__);
		config_setreset(env, RESET_CA, PROC_CERT);

		if (parse_config(filename, env) == -1) {
			log_debug("%s: failed to load config file %s",
			    __func__, filename);
		}

		/* Re-compile policies and skip steps */
		config_setcompile(env, PROC_IKEV2);

		config_setstatic(env);
		config_setcoupled(env, env->sc_decoupled ? 0 : 1);
		config_setocsp(env);
		/* Must be last */
		config_setmode(env, env->sc_passive ? 1 : 0);
	} else {
		config_setreset(env, reset, PROC_IKEV2);
		config_setreset(env, reset, PROC_CERT);
	}
}

void
parent_sig_handler(int sig, short event, void *arg)
{
	struct privsep	*ps = arg;
	int		 die = 0, status, fail, id;
	pid_t		 pid;
	char		*cause;

	switch (sig) {
	case SIGHUP:
		log_info("%s: reload requested with SIGHUP", __func__);

		/*
		 * This is safe because libevent uses async signal handlers
		 * that run in the event loop and not in signal context.
		 */
		parent_reload(ps->ps_env, 0, NULL);
		break;
	case SIGPIPE:
		log_info("%s: ignoring SIGPIPE", __func__);
		break;
	case SIGUSR1:
		log_info("%s: ignoring SIGUSR1", __func__);
		break;
	case SIGTERM:
	case SIGINT:
		die = 1;
		/* FALLTHROUGH */
	case SIGCHLD:
		do {
			int len = 0;

			pid = waitpid(-1, &status, WNOHANG);
			if (pid <= 0)
				continue;

			fail = 0;
			if (WIFSIGNALED(status)) {
				fail = 1;
				len = asprintf(&cause, "terminated; signal %d",
				    WTERMSIG(status));
			} else if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) != 0) {
					fail = 1;
					len = asprintf(&cause,
					    "exited abnormally");
				} else {
					len = asprintf(&cause, "exited okay");
					break;
				}
			} else
				fatalx("unexpected cause of SIGCHLD");

			if (len == -1)
				fatal("asprintf");

			die = 1;

			for (id = 0; id < PROC_MAX; id++)
				if (pid == ps->ps_pid[id]) {
					if (fail)
						log_warnx("lost child: %s %s",
						    ps->ps_title[id], cause);
					break;
				}

			free(cause);
		} while (pid > 0 || (pid == -1 && errno == EINTR));

		if (die)
			parent_shutdown(ps->ps_env);
		break;
	default:
		fatalx("unexpected signal");
	}
}

int
parent_dispatch_ca(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct iked	*env = iked_env;

	switch (imsg->hdr.type) {
	case IMSG_CTL_ACTIVE:
	case IMSG_CTL_PASSIVE:
		proc_forward_imsg(&env->sc_ps, imsg, PROC_IKEV2, -1);
		break;
	case IMSG_OCSP_FD:
		ocsp_connect(env, imsg);
		break;
	case IMSG_END_OF_MSGS:
		printf("cert END_OF_MSGS!!!");
		end_of_msgs_count++;
		printf(" Count: %d/3\n", end_of_msgs_count);
		if (end_of_msgs_count == 3) {
			printf("All compartments received END_OF_MSGS. Exiting program.\n");
			exit(0);
		}
		break;
	default:
		return (-1);
	}

	return (0);
}

int
parent_dispatch_control(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct iked	*env = iked_env;
	int		 v;
	char		*str = NULL;
	unsigned int	 type = imsg->hdr.type;

	switch (type) {
	case IMSG_CTL_RESET:
		IMSG_SIZE_CHECK(imsg, &v);
		memcpy(&v, imsg->data, sizeof(v));
		parent_reload(env, v, NULL);
		break;
	case IMSG_CTL_COUPLE:
	case IMSG_CTL_DECOUPLE:
	case IMSG_CTL_ACTIVE:
	case IMSG_CTL_PASSIVE:
		proc_compose(&env->sc_ps, PROC_IKEV2, type, NULL, 0);
		break;
	case IMSG_CTL_RELOAD:
		if (IMSG_DATA_SIZE(imsg) > 0)
			str = get_string(imsg->data, IMSG_DATA_SIZE(imsg));
		parent_reload(env, 0, str);
		free(str);
		break;
	case IMSG_CTL_VERBOSE:
		proc_forward_imsg(&env->sc_ps, imsg, PROC_IKEV2, -1);
		proc_forward_imsg(&env->sc_ps, imsg, PROC_CERT, -1);

		/* return 1 to let proc.c handle it locally */
		return (1);
	case IMSG_END_OF_MSGS:
		printf("control END_OF_MSGS!!!");
		end_of_msgs_count++;
		printf(" Count: %d/3\n", end_of_msgs_count);
		if (end_of_msgs_count == 3) {
			printf("All compartments received END_OF_MSGS. Exiting program.\n");
			exit(0);
		}
		break;
	default:
		return (-1);
	}

	return (0);
}

int
parent_dispatch_ikev2(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct iked	*env = iked_env;

	switch (imsg->hdr.type) {
#if defined(HAVE_VROUTE)
	case IMSG_IF_ADDADDR:
	case IMSG_IF_DELADDR:
		return (vroute_getaddr(env, imsg));
	case IMSG_VDNS_ADD:
	case IMSG_VDNS_DEL:
		return (vroute_getdns(env, imsg));
	case IMSG_VROUTE_ADD:
	case IMSG_VROUTE_DEL:
		return (vroute_getroute(env, imsg));
	case IMSG_VROUTE_CLONE:
		return (vroute_getcloneroute(env, imsg));
#endif
	case IMSG_END_OF_MSGS:
		printf("ikev2 END_OF_MSGS!!!");
		end_of_msgs_count++;
		printf(" Count: %d/3\n", end_of_msgs_count);
		if (end_of_msgs_count == 3) {
			printf("All compartments received END_OF_MSGS. Exiting program.\n");
			exit(0);
		}
		break;
	default:
		return (-1);
	}

	return (0);
}

void
parent_shutdown(struct iked *env)
{
	proc_kill(&env->sc_ps);

#if defined(HAVE_VROUTE)
	vroute_cleanup(env);
#endif
	free(env->sc_vroute);
	free(env);

	log_warnx("parent terminating");
	exit(0);
}
