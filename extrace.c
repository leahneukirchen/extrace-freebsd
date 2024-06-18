/* extrace - trace exec() calls system-wide
 *
 * Usage: extrace [-deflq] [-o FILE] [-p PID|CMD...]
 * default: show all exec(), globally
 * -p PID   only show exec() descendant of PID
 * CMD...   run CMD... and only show exec() descendant of it
 * -o FILE  log to FILE instead of standard output
 * -d       print cwd of process
 * -e       print environment of process
 * -f       flat output: no indentation
 * -l       print full path of argv[0]
 * -q       don't print exec() arguments
 *
 * Copyright (c) 2014-2016, 2023 Leah Neukirchen <leah@vuxu.org>
 * Copyright (c) 2017 Duncan Overbruck <mail@duncano.de>
 */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <err.h>
#include <kvm.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static FILE *output;
static pid_t parent = 1;
static int flat = 0;
static int full_path = 0;
static int show_args = 1;
static int show_cwd = 0;
static int show_env = 0;

static kvm_t *kd;
static int kq;
static int quit = 0;

static int
pid_depth(pid_t pid)
{
	struct kinfo_proc *kp;
	pid_t ppid = 0;
	int d;
	int n;

	kp = kvm_getprocs(kd, KERN_PROC_PID, pid, &n);
	if (!kp) {
		fprintf(stderr, "extrace: kvm_getprocs: %s\n", kvm_geterr(kd));
		return -1;
	}
	ppid = kp->ki_ppid;

	if (pid == parent)
		return 0;

	if (ppid == parent)
		return 1;

	if (ppid == 0)
		return -1;  /* a parent we are not interested in */

	d = pid_depth(ppid);
	if (d == -1)
		return -1;

	return d+1;
}

static void
print_shquoted(const char *s)
{
	if (*s && !strpbrk(s,
	    "\001\002\003\004\005\006\007\010"
	    "\011\012\013\014\015\016\017\020"
	    "\021\022\023\024\025\026\027\030"
	    "\031\032\033\034\035\036\037\040"
	    "`^#*[]=|\\?${}()'\"<>&;\177")) {
		fprintf(output, "%s", s);
		return;
	}

	putc('\'', output);
	for (; *s; s++)
		if (*s == '\'')
			fprintf(output, "'\\''");
		else if (*s == '\n')
			fprintf(output, "'$'\\n''");
		else
			putc(*s, output);
	putc('\'', output);
}

static void
handle_msg(pid_t pid)
{
	char **pp;
	struct kinfo_proc *kp;

	int d, n;

	if (!flat) {
		d = pid_depth(pid);
		if (d < 0)
			return;
		fprintf(output, "%*s", 2*d, "");
	}
	fprintf(output, "%d ", pid);

	if (show_cwd) {
		int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_CWD, pid };
		struct kinfo_file info;
		size_t len = sizeof info;
		if (sysctl(name, 4, &info, &len, 0, 0) != 1)
			print_shquoted(info.kf_path);
		else
			fprintf(output, "?");
		fprintf(output, " %% ");
	}

	kp = kvm_getprocs(kd, KERN_PROC_PID, pid, &n);
	if (!kp)
		err(1, "kvm_getprocs");
	pp = kvm_getargv(kd, kp, 0);
	if (!pp)
		err(1, "kvm_getargv");

	if (full_path) {
		int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, pid };
		char path[PATH_MAX];
		size_t len = sizeof path;
		if (sysctl(name, 4, &path, &len, 0, 0) != 1)
			print_shquoted(path);
		else
			print_shquoted(*pp);
		pp++;
	} else {
		print_shquoted(*pp++);
	}

	if (show_args)
		for (; *pp; pp++) {
			putc(' ', output);
			print_shquoted(*pp);
		}

	if (show_env) {
		char *eq;
		pp = kvm_getenvv(kd, kp, 0);
		if (pp) {
			for (; *pp; pp++) {
				putc(' ', output);
				if ((eq = strchr(*pp, '='))) {
					/* print split so = doesn't trigger escaping.  */
					*eq = 0;
					print_shquoted(*pp);
					putc('=', output);
					print_shquoted(eq+1);
				} else {
					/* weird env entry without equal sign.  */
					print_shquoted(*pp);
				
				}
			}
		} else {
			fprintf(output, " -");
		}
	}

	fprintf(output, "\n");
	fflush(output);
}

int
main(int argc, char *argv[])
{
	struct kevent kev[4];
	int opt, i, n;

	output = stdout;

	while ((opt = getopt(argc, argv, "deflo:p:qw")) != -1)
		switch (opt) {
		case 'd': show_cwd = 1; break;
		case 'e': show_env = 1; break;
		case 'f': flat = 1; break;
		case 'l': full_path = 1; break;
		case 'p': parent = atoi(optarg); break;
		case 'q': show_args = 0; break;
		case 'o':
			output = fopen(optarg, "w");
			if (!output) {
				  perror("fopen");
				  exit(1);
			}
			break;
		case 'w': /* obsoleted, ignore */; break;
		default: goto usage;
		}

	if (parent != 1 && optind != argc) {
usage:
		fprintf(stderr, "Usage: extrace [-deflq] [-o FILE] [-p PID|CMD...]\n");
		exit(1);
	}

	if ((kq = kqueue()) == -1)
		err(1, "kqueue");

	kd = kvm_openfiles(0, 0, 0, O_RDONLY, 0);
	if (!kd)
		err(1, "kvm_open");

	if (optind != argc) {
		EV_SET(&kev[0], SIGCHLD, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);
		if (kevent(kq, kev, 1, 0, 0, 0) == -1)
			err(1, "kevent");

		switch ((parent = fork())) {
		case -1: err(1, "fork"); break;
		case 0:
			execvp(argv[optind], argv+optind);
			err(1, "execvp");
		}
	} 

	signal(SIGINT, SIG_IGN);
	EV_SET(&kev[0], SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, 0);
	if (kevent(kq, kev, 1, 0, 0, 0) == -1)
		err(1, "kevent");

	if (parent != 1) {
		EV_SET(&kev[0], parent, EVFILT_PROC, EV_ADD, NOTE_EXEC | NOTE_TRACK, 0, 0);
		if (kevent(kq, kev, 1, 0, 0, 0) == -1)
			err(1, "kevent");
	} else {
		struct kinfo_proc *kp;
		struct kevent *kevs;

again:
		kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, &n);
		if (!kp) {
			fprintf(stderr, "extrace: kvm_getprocs ALL: %s\n", kvm_geterr(kd));
			return -1;
		}
		if (!(kevs = calloc(n, sizeof (struct kevent))))
			err(1, "calloc");
		for (i = 0; i < n; i++) {
			if (!kp[i].ki_pid || !kp[i].ki_ppid)
				continue;
			if (kp[i].ki_stat == SZOMB)
				continue;
			EV_SET(&kevs[i], kp[i].ki_pid, EVFILT_PROC, EV_ADD, NOTE_EXEC | NOTE_TRACK, 0, 0);
		}
		errno = 0;
		if (kevent(kq, kevs, n, 0, 0, 0) == -1)
			warn("kevent ALL");
		free(kevs);
		if (errno == ESRCH)
			goto again;
	}

	while (!quit) {
		n = kevent(kq, 0, 0, kev, 4, 0);
		for (i = 0; i < n; i++)  {
			struct kevent *ke = &kev[i];
			switch (ke->filter) {
			case EVFILT_SIGNAL:
				if (ke->ident == SIGCHLD)
					while (waitpid(-1, 0, WNOHANG) > 0)
						;
				quit = 1;
				break;
			case EVFILT_PROC:
				if (ke->fflags & NOTE_EXEC)
					handle_msg(ke->ident);
			}
			if (quit)
				break;
		}
	}

	return 0;
}
