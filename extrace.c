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
 * Copyright (c) 2014-2025 Leah Neukirchen <leah@vuxu.org>
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
static int show_exit = 0;

static kvm_t *kd;
static int kq;
static int quit = 0;

#define CMDLINE_DB_MAX 32
#define PID_DB_SIZE 1024
struct {
        pid_t pid;
        int depth;
        struct timeval start;
        char cmdline[CMDLINE_DB_MAX];
} pid_db[PID_DB_SIZE];

static int
pid_depth(pid_t pid)
{
	struct kinfo_proc *kp;
	pid_t ppid = 0;
	int n, d, i;

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

	for (i = 0; i < PID_DB_SIZE - 1; i++)
		if (pid_db[i].pid == ppid)
			d = pid_db[i].depth;
	if (i == PID_DB_SIZE - 1)
		d = pid_depth(ppid);  /* recurse */

	if (d == -1)
		return -1;

	return d + 1;
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
handle_exit(pid_t pid, int status)
{
	int d, i;

	for (i = 0; i < PID_DB_SIZE - 1; i++)
		if (pid_db[i].pid == 0 || pid_db[i].pid == pid)
			break;

	if (!flat) {
		d = pid_db[i].depth;
		if (d < 0)
			return;
		fprintf(output, "%*s", 2*d, "");
	}

	fprintf(output, "%d- ", pid);
	print_shquoted(pid_db[i].cmdline);
	if (WIFSIGNALED(status))
		fprintf(output, " exited signal=%s", sys_signame[WTERMSIG(status)]);
	else
		fprintf(output, " exited status=%d", WEXITSTATUS(status));

	struct timeval now, diff;
	gettimeofday(&now, 0);
	timersub(&now, &pid_db[i].start, &diff);
	fprintf(output, " time=%.3fs\n", (double)diff.tv_sec + (double)diff.tv_usec / 1e6);

	fflush(output);
	pid_db[i].pid = 0;
}

static void
handle_exec(pid_t pid)
{
	char **pp;
	struct kinfo_proc *kp;

	int d, i, n;

	d = pid_depth(pid);
	if (d < 0)
		return;

	kp = kvm_getprocs(kd, KERN_PROC_PID, pid, &n);
	if (!kp) {
		fprintf(output, "\n");
		warn("kvm_getprocs");
		return;
	}
	pp = kvm_getargv(kd, kp, 0);
	if (!pp) {
		fprintf(output, "\n");
		warn("kvm_getargv");
		return;
	}

	if (show_exit || !flat) {
		for (i = 0; i < PID_DB_SIZE - 1; i++)
			if (pid_db[i].pid == 0 || pid_db[i].pid == pid)
				break;
		if (i == PID_DB_SIZE - 1)
			fprintf(stderr, "extrace: warning: pid_db of "
			    "size %d overflowed\n", PID_DB_SIZE);

		if (show_exit && pid_db[i].pid == pid) {
			if (!flat)
				fprintf(output, "%*s", 2*d, "");

			struct timeval now, diff;
			gettimeofday(&now, 0);
			timersub(&now, &pid_db[i].start, &diff);

			fprintf(output, "%d- %s execed time=%.3fs\n",
			    pid,
			    pid_db[i].cmdline,
			    (double)diff.tv_sec + (double)diff.tv_usec / 1e6);

			pid_db[i].start = now;
		} else {
			pid_db[i].pid = pid;
			pid_db[i].depth = d;
			pid_db[i].start = kp->ki_start;
		}
	}

	if (!flat)
		fprintf(output, "%*s", 2*d, "");
	fprintf(output, "%d", pid);
	if (show_exit)
		putc('+', output);
	putc(' ', output);

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

	if (full_path) {
		int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, pid };
		char path[PATH_MAX];
		size_t len = sizeof path;
		if (sysctl(name, 4, &path, &len, 0, 0) != 1) {
			snprintf(pid_db[i].cmdline, CMDLINE_DB_MAX, "%s", path);
			print_shquoted(path);
		} else {
			snprintf(pid_db[i].cmdline, CMDLINE_DB_MAX, "%s", *pp);
			print_shquoted(*pp);
		}
		pp++;
	} else {
		snprintf(pid_db[i].cmdline, CMDLINE_DB_MAX, "%s", *pp);
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

	while ((opt = getopt(argc, argv, "deflo:p:qtw")) != -1)
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
		case 't': show_exit = 1; break;
		case 'w': /* obsoleted, ignore */; break;
		default: goto usage;
		}

	if (parent != 1 && optind != argc) {
usage:
		fprintf(stderr, "Usage: extrace [-deflqt] [-o FILE] [-p PID|CMD...]\n");
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
			EV_SET(&kevs[i], kp[i].ki_pid, EVFILT_PROC, EV_ADD, NOTE_EXEC | (show_exit ? NOTE_EXIT : 0) | NOTE_TRACK, 0, 0);
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
				if (ke->ident == SIGCHLD) {
					pid_t pid;
					int wstatus;
					while ((pid = waitpid(-1, &wstatus, WNOHANG)) > 0)
						if (show_exit)
							handle_exit(pid, wstatus);
				}
				quit = 1;
				break;
			case EVFILT_PROC:
				if (ke->fflags & NOTE_EXIT)
					handle_exit(ke->ident, ke->data);
				else if (ke->fflags & NOTE_EXEC)
					handle_exec(ke->ident);
			}
			if (quit)
				break;
		}
	}

	return 0;
}
