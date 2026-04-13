#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include "monitor_ioctl.h"

#define MAX_CONTAINERS 16
#define STACK_SIZE     (1024 * 1024)
#define SOCKET_PATH    "/tmp/engine.sock"
#define LOG_DIR        "/tmp/engine_logs"
#define LOG_BUF_CAP    256
#define LOG_LINE_MAX   512

#define CMD_START 1
#define CMD_PS    2
#define CMD_STOP  3
#define CMD_LOGS  4
#define CMD_RUN   5

typedef struct {
    int  type;
    char name[64];
    char rootfs[256];
    char cmd[128];
    long soft_mib;
    long hard_mib;
} ipc_cmd_t;

typedef struct {
    char   id[64];
    pid_t  host_pid;
    time_t start_time;
    char   state[16];
    long   soft_bytes;
    long   hard_bytes;
    char   log_path[256];
    int    exit_status;
    int    pipe_read_fd;
} container_t;

typedef struct {
    char lines[LOG_BUF_CAP][LOG_LINE_MAX];
    int  head, tail, count, done;
    pthread_mutex_t lock;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
} log_buf_t;

container_t           containers[MAX_CONTAINERS];
int                   container_count = 0;
pthread_mutex_t       containers_lock = PTHREAD_MUTEX_INITIALIZER;
volatile sig_atomic_t shutdown_flag   = 0;
int                   monitor_fd      = -1;

void buf_push(log_buf_t *b, const char *line) {
    pthread_mutex_lock(&b->lock);
    while (b->count == LOG_BUF_CAP && !b->done)
        pthread_cond_wait(&b->not_full, &b->lock);
    if (!b->done) {
        strncpy(b->lines[b->tail], line, LOG_LINE_MAX - 1);
        b->tail = (b->tail + 1) % LOG_BUF_CAP;
        b->count++;
        pthread_cond_signal(&b->not_empty);
    }
    pthread_mutex_unlock(&b->lock);
}

int buf_pop(log_buf_t *b, char *out) {
    pthread_mutex_lock(&b->lock);
    while (b->count == 0 && !b->done)
        pthread_cond_wait(&b->not_empty, &b->lock);
    if (b->count == 0) {
        pthread_mutex_unlock(&b->lock);
        return -1;
    }
    strncpy(out, b->lines[b->head], LOG_LINE_MAX - 1);
    b->head = (b->head + 1) % LOG_BUF_CAP;
    b->count--;
    pthread_cond_signal(&b->not_full);
    pthread_mutex_unlock(&b->lock);
    return 0;
}

typedef struct {
    int pipe_fd;
    log_buf_t *buf;
} prod_args_t;

typedef struct {
    log_buf_t *buf;
    char log_path[256];
} cons_args_t;

void *producer_thread(void *arg) {
    prod_args_t *a = arg;
    char tmp[LOG_LINE_MAX];
    int  n;
    while ((n = read(a->pipe_fd, tmp, sizeof(tmp) - 1)) > 0) {
        tmp[n] = '\0';
        char *line = strtok(tmp, "\n");
        while (line) {
            buf_push(a->buf, line);
            line = strtok(NULL, "\n");
        }
    }
    pthread_mutex_lock(&a->buf->lock);
    a->buf->done = 1;
    pthread_cond_signal(&a->buf->not_empty);
    pthread_mutex_unlock(&a->buf->lock);
    close(a->pipe_fd);
    free(a);
    return NULL;
}

void *consumer_thread(void *arg) {
    cons_args_t *a = arg;
    FILE *f = fopen(a->log_path, "a");
    if (!f) { free(a); return NULL; }
    char line[LOG_LINE_MAX];
    while (buf_pop(a->buf, line) == 0) {
        fprintf(f, "%s\n", line);
        fflush(f);
    }
    fclose(f);
    free(a->buf);
    free(a);
    return NULL;
}

void start_logger(container_t *c) {
    log_buf_t *buf = calloc(1, sizeof(log_buf_t));
    pthread_mutex_init(&buf->lock, NULL);
    pthread_cond_init(&buf->not_empty, NULL);
    pthread_cond_init(&buf->not_full, NULL);

    prod_args_t *pa = malloc(sizeof(*pa));
    pa->pipe_fd = c->pipe_read_fd;
    pa->buf     = buf;

    cons_args_t *ca = malloc(sizeof(*ca));
    ca->buf = buf;
    strncpy(ca->log_path, c->log_path, sizeof(ca->log_path) - 1);

    pthread_t pt, ct;
    pthread_create(&pt, NULL, producer_thread, pa);
    pthread_create(&ct, NULL, consumer_thread, ca);
    pthread_detach(pt);
    pthread_detach(ct);
}

void open_monitor() {
    monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (monitor_fd < 0)       fprintf(stderr, "[warn] monitor device not available\n");
}

void register_monitor(pid_t pid, long soft, long hard) {
    if (monitor_fd < 0) return;
    struct monitor_request r;
    memset(&r, 0, sizeof(r));
    r.pid               = pid;
    r.soft_limit_bytes  = soft;
    r.hard_limit_bytes  = hard;
    ioctl(monitor_fd, MONITOR_REGISTER, &r);
}

void unregister_monitor(pid_t pid) {
    if (monitor_fd < 0) return;
    struct monitor_request r;
    memset(&r, 0, sizeof(r));
    r.pid = pid;
    ioctl(monitor_fd, MONITOR_UNREGISTER, &r);
}

typedef struct {
    char rootfs[256];
    char cmd[128];
    char name[64];
    int  pipe_write_fd;
} cargs_t;

int container_main(void *arg) {
    cargs_t *a = arg;
    dup2(a->pipe_write_fd, STDOUT_FILENO);
    dup2(a->pipe_write_fd, STDERR_FILENO);
    close(a->pipe_write_fd);
    sethostname(a->name, strlen(a->name));
    if (chroot(a->rootfs) < 0) {
        perror("chroot");
        return 1;
    }
    chdir("/");
    mount("proc", "/proc", "proc", 0, NULL);
    char *argv[] = { a->cmd, NULL };
    execv(a->cmd, argv);
    perror("execv");
    return 1;
}

int launch_container(const char *name, const char *rootfs,
                     const char *cmd, long soft_mib, long hard_mib) {
    int pipefd[2];
    if (pipe(pipefd) < 0) { perror("pipe"); return -1; }

    char *stack     = malloc(STACK_SIZE);
    char *stack_top = stack + STACK_SIZE;

    cargs_t *a = malloc(sizeof(*a));
    strncpy(a->rootfs, rootfs, sizeof(a->rootfs) - 1);
    strncpy(a->cmd,    cmd,    sizeof(a->cmd) - 1);
    strncpy(a->name,   name,   sizeof(a->name) - 1);
    a->pipe_write_fd = pipefd[1];

    pid_t pid = clone(container_main, stack_top,
                      CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD, a);
    if (pid < 0) {
        perror("clone");
        free(stack);
        return -1;
    }
    close(pipefd[1]);

    mkdir(LOG_DIR, 0755);

    pthread_mutex_lock(&containers_lock);
    container_t *c = &containers[container_count++];
    strncpy(c->id, name, sizeof(c->id) - 1);
    c->host_pid    = pid;
    c->start_time  = time(NULL);
    strcpy(c->state, "running");
    c->soft_bytes   = soft_mib * 1024 * 1024;
    c->hard_bytes   = hard_mib * 1024 * 1024;
    snprintf(c->log_path, sizeof(c->log_path), "%s/%s.log", LOG_DIR, name);
    c->pipe_read_fd = pipefd[0];
    c->exit_status  = -1;
    pthread_mutex_unlock(&containers_lock);

    start_logger(c);
    register_monitor(pid, c->soft_bytes, c->hard_bytes);

    printf("[supervisor] started '%s' host_pid=%d\n", name, pid);
    fflush(stdout);
    return pid;
}

void sigchld_handler(int sig) {
    (void)sig;
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        pthread_mutex_lock(&containers_lock);
        for (int i = 0; i < container_count; i++) {
            if (containers[i].host_pid == pid) {
                if (WIFSIGNALED(status)) {
                    strcpy(containers[i].state, "killed");
                    containers[i].exit_status = WTERMSIG(status);
                } else {
                    strcpy(containers[i].state, "stopped");
                    containers[i].exit_status = WEXITSTATUS(status);
                }
                unregister_monitor(pid);
                break;
            }
        }
        pthread_mutex_unlock(&containers_lock);
    }
}

void sigterm_handler(int sig) {
    (void)sig;
    shutdown_flag = 1;
    pthread_mutex_lock(&containers_lock);
    for (int i = 0; i < container_count; i++)
        if (strcmp(containers[i].state, "running") == 0)
            kill(containers[i].host_pid, SIGTERM);
    pthread_mutex_unlock(&containers_lock);
}

void handle_cmd(ipc_cmd_t *cmd, int reply_fd) {
    char reply[8192];
    memset(reply, 0, sizeof(reply));

    if (cmd->type == CMD_START || cmd->type == CMD_RUN) {
        int pid = launch_container(cmd->name, cmd->rootfs,
                                   cmd->cmd, cmd->soft_mib, cmd->hard_mib);
        if (pid < 0)
            snprintf(reply, sizeof(reply),
                     "ERROR: failed to start '%s'\n", cmd->name);
        else
            snprintf(reply, sizeof(reply),
                     "started '%s' pid=%d\n", cmd->name, pid);

        if (cmd->type == CMD_RUN && pid > 0) {
            int st;
            waitpid(pid, &st, 0);
            snprintf(reply, sizeof(reply),
                     "'%s' exited with %d\n", cmd->name, WEXITSTATUS(st));
        }

    } else if (cmd->type == CMD_PS) {
        snprintf(reply, sizeof(reply),
                 "%-16s %-8s %-10s %-10s %-10s\n",
                 "NAME", "PID", "STATE", "SOFT(MB)", "HARD(MB)");
        pthread_mutex_lock(&containers_lock);
        for (int i = 0; i < container_count; i++) {
            container_t *c = &containers[i];
            char line[256];
            snprintf(line, sizeof(line),
                     "%-16s %-8d %-10s %-10ld %-10ld\n",
                     c->id, c->host_pid, c->state,
                     c->soft_bytes / 1024 / 1024,
                     c->hard_bytes / 1024 / 1024);
            strncat(reply, line, sizeof(reply) - strlen(reply) - 1);
        }
        pthread_mutex_unlock(&containers_lock);

    } else if (cmd->type == CMD_STOP) {
        int found = 0;
        pthread_mutex_lock(&containers_lock);
        for (int i = 0; i < container_count; i++) {
            if (strcmp(containers[i].id, cmd->name) == 0) {
                kill(containers[i].host_pid, SIGTERM);
                strcpy(containers[i].state, "stopping");
                snprintf(reply, sizeof(reply),
                         "stopped '%s'\n", cmd->name);
                found = 1;
                break;
            }
        }
        pthread_mutex_unlock(&containers_lock);
        if (!found)
            snprintf(reply, sizeof(reply),
                     "ERROR: container '%s' not found\n", cmd->name);

    } else if (cmd->type == CMD_LOGS) {
        char path[256];
        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, cmd->name);
        FILE *f = fopen(path, "r");
        if (!f) {
            snprintf(reply, sizeof(reply),
                     "no log found for '%s'\n", cmd->name);
        } else {
            size_t n = fread(reply, 1, sizeof(reply) - 1, f);
            reply[n] = '\0';
            fclose(f);
        }
    }

    write(reply_fd, reply, strlen(reply));
}

void run_supervisor(const char *base_rootfs) {
    (void)base_rootfs;

    signal(SIGCHLD, sigchld_handler);
    signal(SIGINT,  sigterm_handler);
    signal(SIGTERM, sigterm_handler);

    open_monitor();

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); exit(1); }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    unlink(SOCKET_PATH);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }
    listen(srv, 10);
    printf("[supervisor] ready. socket=%s\n", SOCKET_PATH);
    fflush(stdout);

    while (!shutdown_flag) {
        int cli = accept(srv, NULL, NULL);
        if (cli < 0) continue;
        ipc_cmd_t cmd;
        memset(&cmd, 0, sizeof(cmd));
        if (read(cli, &cmd, sizeof(cmd)) > 0)
            handle_cmd(&cmd, cli);
        close(cli);
    }

    sleep(2);
    int st;
    while (waitpid(-1, &st, WNOHANG) > 0);
    if (monitor_fd >= 0) close(monitor_fd);
    close(srv);
    unlink(SOCKET_PATH);
    printf("[supervisor] exited cleanly\n");
}

void send_cmd(ipc_cmd_t *cmd) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Cannot connect to supervisor. Is it running?\n");
        exit(1);
    }
    write(fd, cmd, sizeof(ipc_cmd_t));

    char reply[8192];
    int n;
    while ((n = read(fd, reply, sizeof(reply) - 1)) > 0) {
        reply[n] = '\0';
        printf("%s", reply);
    }
    close(fd);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage:\n"
            "  ./engine supervisor <base-rootfs>\n"
            "  ./engine start <name> <rootfs> <cmd> --soft-mib N --hard-mib N\n"
            "  ./engine run   <name> <rootfs> <cmd> --soft-mib N --hard-mib N\n"
            "  ./engine ps\n"
            "  ./engine stop  <name>\n"
            "  ./engine logs  <name>\n");
        return 1;
    }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: ./engine supervisor <base-rootfs>\n");
            return 1;
        }
        run_supervisor(argv[2]);

    } else if (strcmp(argv[1], "start") == 0 ||
               strcmp(argv[1], "run")   == 0) {
        if (argc < 5) {
            fprintf(stderr,
                "Usage: ./engine start <name> <rootfs> <cmd>\n");
            return 1;
        }
        ipc_cmd_t cmd;
        memset(&cmd, 0, sizeof(cmd));
        cmd.type = (strcmp(argv[1], "run") == 0) ? CMD_RUN : CMD_START;
        strncpy(cmd.name,   argv[2], sizeof(cmd.name)   - 1);
        strncpy(cmd.rootfs, argv[3], sizeof(cmd.rootfs) - 1);
        strncpy(cmd.cmd,    argv[4], sizeof(cmd.cmd)    - 1);
        cmd.soft_mib = 64;
        cmd.hard_mib = 128;
        for (int i = 5; i < argc - 1; i++) {
            if (strcmp(argv[i], "--soft-mib") == 0)
                cmd.soft_mib = atol(argv[i + 1]);
            if (strcmp(argv[i], "--hard-mib") == 0)
                cmd.hard_mib = atol(argv[i + 1]);
        }
        send_cmd(&cmd);

    } else if (strcmp(argv[1], "ps") == 0) {
        ipc_cmd_t cmd;
        memset(&cmd, 0, sizeof(cmd));
        cmd.type = CMD_PS;
        send_cmd(&cmd);

    } else if (strcmp(argv[1], "stop") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: ./engine stop <name>\n");
            return 1;
        }
        ipc_cmd_t cmd;
        memset(&cmd, 0, sizeof(cmd));
        cmd.type = CMD_STOP;
        strncpy(cmd.name, argv[2], sizeof(cmd.name) - 1);
        send_cmd(&cmd);

    } else if (strcmp(argv[1], "logs") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: ./engine logs <name>\n");
            return 1;
        }
        ipc_cmd_t cmd;
        memset(&cmd, 0, sizeof(cmd));
        cmd.type = CMD_LOGS;
        strncpy(cmd.name, argv[2], sizeof(cmd.name) - 1);
        send_cmd(&cmd);

    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
