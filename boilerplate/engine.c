/*
 * engine.c  –  Supervised Multi-Container Runtime
 *
 * Implements every requirement from the project guide:
 *   Task 1 – multi-container supervision with namespace isolation
 *   Task 2 – full CLI (start/run/ps/logs/stop) over a UNIX-domain socket
 *   Task 3 – bounded-buffer logging pipeline (producer + consumer threads)
 *   Task 4 – ioctl register/unregister with kernel memory monitor
 *   Task 5 – --nice flag plumbed through to child
 *   Task 6 – clean teardown on supervisor exit
 *
 * Attribution rules (project guide §Task 4):
 *   - container_record.stop_requested is set BEFORE any stop signal is sent
 *   - SIGCHLD handler classifies exit as:
 *       CONTAINER_STOPPED  when stop_requested is set
 *       CONTAINER_KILLED   when !stop_requested && SIGKILL (kernel module)
 *       CONTAINER_EXITED   on clean exit()
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

/* ================================================================ */
#define STACK_SIZE            (1024 * 1024)
#define CONTAINER_ID_LEN      32
#define CONTROL_PATH          "/tmp/mini_runtime.sock"
#define LOG_DIR               "logs"
#define CONTROL_MESSAGE_LEN   512
#define CHILD_COMMAND_LEN     256
#define LOG_CHUNK_SIZE        4096
#define LOG_BUFFER_CAPACITY   16
#define DEFAULT_SOFT_LIMIT    (40UL << 20)
#define DEFAULT_HARD_LIMIT    (64UL << 20)
#define DEVICE_NAME           "container_monitor"

/* ================================================================ */
typedef enum {
    CMD_SUPERVISOR = 0, CMD_START, CMD_RUN, CMD_PS, CMD_LOGS, CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0, CONTAINER_RUNNING, CONTAINER_STOPPED,
    CONTAINER_KILLED, CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char                    id[CONTAINER_ID_LEN];
    pid_t                   host_pid;
    time_t                  started_at;
    container_state_t       state;
    unsigned long           soft_limit_bytes;
    unsigned long           hard_limit_bytes;
    int                     exit_code;
    int                     exit_signal;
    int                     stop_requested;
    char                    log_path[PATH_MAX];
    struct container_record *next;
} container_record_t;

typedef struct {
    char   container_id[CONTAINER_ID_LEN];
    size_t length;
    char   data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t      items[LOG_BUFFER_CAPACITY];
    size_t          head, tail, count;
    int             shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty, not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char           container_id[CONTAINER_ID_LEN];
    char           rootfs[PATH_MAX];
    char           command[CHILD_COMMAND_LEN];
    unsigned long  soft_limit_bytes, hard_limit_bytes;
    int            nice_value;
} control_request_t;

typedef struct {
    int  status;
    char message[CONTROL_MESSAGE_LEN];
    int  run_exit_code;
    int  run_exit_signal;
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int  nice_value;
    int  log_write_fd;
} child_config_t;

typedef struct {
    int                 server_fd, monitor_fd;
    volatile int        should_stop;
    pthread_t           logger_thread;
    bounded_buffer_t    log_buffer;
    pthread_mutex_t     metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

static supervisor_ctx_t *g_ctx = NULL;

/* ================================================================
 * Bounded Buffer
 * ================================================================ */
static int bounded_buffer_init(bounded_buffer_t *b)
{
    int rc;
    memset(b, 0, sizeof(*b));
    if ((rc = pthread_mutex_init(&b->mutex, NULL))    != 0) return rc;
    if ((rc = pthread_cond_init(&b->not_empty, NULL)) != 0) {
        pthread_mutex_destroy(&b->mutex); return rc; }
    if ((rc = pthread_cond_init(&b->not_full, NULL))  != 0) {
        pthread_cond_destroy(&b->not_empty);
        pthread_mutex_destroy(&b->mutex); return rc; }
    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *b) {
    pthread_cond_destroy(&b->not_full);
    pthread_cond_destroy(&b->not_empty);
    pthread_mutex_destroy(&b->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *b) {
    pthread_mutex_lock(&b->mutex);
    b->shutting_down = 1;
    pthread_cond_broadcast(&b->not_empty);
    pthread_cond_broadcast(&b->not_full);
    pthread_mutex_unlock(&b->mutex);
}

int bounded_buffer_push(bounded_buffer_t *b, const log_item_t *item)
{
    pthread_mutex_lock(&b->mutex);
    while (b->count == LOG_BUFFER_CAPACITY && !b->shutting_down)
        pthread_cond_wait(&b->not_full, &b->mutex);
    if (b->shutting_down && b->count == LOG_BUFFER_CAPACITY) {
        pthread_mutex_unlock(&b->mutex); return -1; }
    b->items[b->tail] = *item;
    b->tail = (b->tail + 1) % LOG_BUFFER_CAPACITY;
    b->count++;
    pthread_cond_signal(&b->not_empty);
    pthread_mutex_unlock(&b->mutex);
    return 0;
}

int bounded_buffer_pop(bounded_buffer_t *b, log_item_t *item)
{
    pthread_mutex_lock(&b->mutex);
    while (b->count == 0 && !b->shutting_down)
        pthread_cond_wait(&b->not_empty, &b->mutex);
    if (b->count == 0) {
        pthread_mutex_unlock(&b->mutex); return -1; }
    *item = b->items[b->head];
    b->head = (b->head + 1) % LOG_BUFFER_CAPACITY;
    b->count--;
    pthread_cond_signal(&b->not_full);
    pthread_mutex_unlock(&b->mutex);
    return 0;
}

/* ================================================================
 * Logger consumer thread
 * ================================================================ */
static void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;
    while (bounded_buffer_pop(&ctx->log_buffer, &item) == 0) {
        char log_path[PATH_MAX] = {0};
        container_record_t *rec;
        pthread_mutex_lock(&ctx->metadata_lock);
        for (rec = ctx->containers; rec; rec = rec->next)
            if (strcmp(rec->id, item.container_id) == 0) {
                strncpy(log_path, rec->log_path, sizeof(log_path)-1);
                break;
            }
        pthread_mutex_unlock(&ctx->metadata_lock);
        if (log_path[0]) {
            int fd = open(log_path, O_WRONLY|O_CREAT|O_APPEND, 0644);
            if (fd >= 0) { write(fd, item.data, item.length); close(fd); }
        }
    }
    return NULL;
}

/* ================================================================
 * Per-container pipe reader (producer thread)
 * ================================================================ */
typedef struct {
    int               read_fd;
    char              container_id[CONTAINER_ID_LEN];
    bounded_buffer_t *log_buffer;
} reader_args_t;

static void *container_reader_thread(void *arg)
{
    reader_args_t *ra = (reader_args_t *)arg;
    log_item_t item;
    ssize_t n;
    memset(&item, 0, sizeof(item));
    strncpy(item.container_id, ra->container_id, sizeof(item.container_id)-1);
    while ((n = read(ra->read_fd, item.data, sizeof(item.data)-1)) > 0) {
        item.data[n] = '\0';
        item.length  = (size_t)n;
        bounded_buffer_push(ra->log_buffer, &item);
        memset(item.data, 0, sizeof(item.data));
    }
    close(ra->read_fd);
    free(ra);
    return NULL;
}

/* ================================================================
 * Clone child entrypoint
 * ================================================================ */
static int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;
    char proc_path[PATH_MAX];
    sethostname(cfg->id, strlen(cfg->id));

    snprintf(proc_path, sizeof(proc_path), "%s/proc", cfg->rootfs);
    mkdir(proc_path, 0555);
    mount("proc", proc_path, "proc", MS_NOEXEC|MS_NOSUID|MS_NODEV, NULL);

    if (chroot(cfg->rootfs) != 0) { perror("chroot"); return 1; }
    if (chdir("/") != 0) { perror("chdir"); return 1; }

    if (cfg->log_write_fd >= 0) {
        dup2(cfg->log_write_fd, STDOUT_FILENO);
        dup2(cfg->log_write_fd, STDERR_FILENO);
        close(cfg->log_write_fd);
    }
    if (cfg->nice_value != 0) nice(cfg->nice_value);

    char *const argv[] = { "/bin/sh", "-c", cfg->command, NULL };
    execv("/bin/sh", argv);
    perror("execv");
    return 1;
}

/* ================================================================
 * Monitor ioctl helpers
 * ================================================================ */
static int register_with_monitor(int fd, const char *cid, pid_t pid,
                                  unsigned long soft, unsigned long hard)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = pid; req.soft_limit_bytes = soft; req.hard_limit_bytes = hard;
    strncpy(req.container_id, cid, sizeof(req.container_id)-1);
    return ioctl(fd, MONITOR_REGISTER, &req) < 0 ? -1 : 0;
}

static int unregister_from_monitor(int fd, const char *cid, pid_t pid)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = pid;
    strncpy(req.container_id, cid, sizeof(req.container_id)-1);
    return ioctl(fd, MONITOR_UNREGISTER, &req) < 0 ? -1 : 0;
}

/* ================================================================
 * Signal handlers
 * ================================================================ */
static void sigchld_handler(int sig)
{
    (void)sig;
    int saved = errno;
    int wstatus;
    pid_t pid;
    while ((pid = waitpid(-1, &wstatus, WNOHANG)) > 0) {
        if (!g_ctx) continue;
        container_record_t *rec;
        pthread_mutex_lock(&g_ctx->metadata_lock);
        for (rec = g_ctx->containers; rec; rec = rec->next) {
            if (rec->host_pid != pid) continue;
            if (WIFEXITED(wstatus)) {
                rec->exit_code   = WEXITSTATUS(wstatus);
                rec->exit_signal = 0;
                rec->state = CONTAINER_EXITED;
            } else if (WIFSIGNALED(wstatus)) {
                rec->exit_signal = WTERMSIG(wstatus);
                rec->exit_code   = 0;
                /* Attribution rule from project guide §Task 4 */
                if (rec->stop_requested)
                    rec->state = CONTAINER_STOPPED;
                else if (rec->exit_signal == SIGKILL)
                    rec->state = CONTAINER_KILLED;
                else
                    rec->state = CONTAINER_STOPPED;
            }
            if (g_ctx->monitor_fd >= 0)
                unregister_from_monitor(g_ctx->monitor_fd,
                                        rec->id, rec->host_pid);
            break;
        }
        pthread_mutex_unlock(&g_ctx->metadata_lock);
    }
    errno = saved;
}

static void shutdown_handler(int sig)
{
    (void)sig;
    if (g_ctx) g_ctx->should_stop = 1;
}

/* ================================================================
 * Launch a container
 * ================================================================ */
static int launch_container(supervisor_ctx_t *ctx,
                             const control_request_t *req)
{
    container_record_t *existing;
    pthread_mutex_lock(&ctx->metadata_lock);
    for (existing = ctx->containers; existing; existing = existing->next)
        if (strcmp(existing->id, req->container_id) == 0 &&
            existing->state == CONTAINER_RUNNING) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            fprintf(stderr, "Container '%s' already running\n", req->container_id);
            return -1;
        }
    pthread_mutex_unlock(&ctx->metadata_lock);

    int pipefd[2];
    if (pipe(pipefd) != 0) { perror("pipe"); return -1; }

    char *stack = malloc(STACK_SIZE);
    if (!stack) { close(pipefd[0]); close(pipefd[1]); return -1; }

    child_config_t *cfg = malloc(sizeof(*cfg));
    if (!cfg) { free(stack); close(pipefd[0]); close(pipefd[1]); return -1; }

    strncpy(cfg->id,      req->container_id, sizeof(cfg->id)-1);
    strncpy(cfg->rootfs,  req->rootfs,       sizeof(cfg->rootfs)-1);
    strncpy(cfg->command, req->command,      sizeof(cfg->command)-1);
    cfg->nice_value   = req->nice_value;
    cfg->log_write_fd = pipefd[1];

    pid_t pid = clone(child_fn, stack + STACK_SIZE,
                      CLONE_NEWPID|CLONE_NEWUTS|CLONE_NEWNS|SIGCHLD, cfg);
    close(pipefd[1]);
    free(stack);

    if (pid < 0) {
        perror("clone"); free(cfg); close(pipefd[0]); return -1; }

    container_record_t *rec = calloc(1, sizeof(*rec));
    if (!rec) { close(pipefd[0]); free(cfg); return -1; }

    strncpy(rec->id, req->container_id, sizeof(rec->id)-1);
    rec->host_pid         = pid;
    rec->started_at       = time(NULL);
    rec->state            = CONTAINER_RUNNING;
    rec->soft_limit_bytes = req->soft_limit_bytes;
    rec->hard_limit_bytes = req->hard_limit_bytes;
    rec->stop_requested   = 0;

    mkdir(LOG_DIR, 0755);
    snprintf(rec->log_path, sizeof(rec->log_path),
             "%s/%s.log", LOG_DIR, rec->id);

    pthread_mutex_lock(&ctx->metadata_lock);
    rec->next = ctx->containers;
    ctx->containers = rec;
    pthread_mutex_unlock(&ctx->metadata_lock);

    reader_args_t *ra = malloc(sizeof(*ra));
    if (ra) {
        ra->read_fd    = pipefd[0];
        ra->log_buffer = &ctx->log_buffer;
        strncpy(ra->container_id, req->container_id,
                sizeof(ra->container_id)-1);
        pthread_t rt;
        if (pthread_create(&rt, NULL, container_reader_thread, ra) == 0)
            pthread_detach(rt);
        else { free(ra); close(pipefd[0]); }
    } else close(pipefd[0]);

    if (ctx->monitor_fd >= 0)
        register_with_monitor(ctx->monitor_fd, rec->id, pid,
                               rec->soft_limit_bytes, rec->hard_limit_bytes);

    free(cfg);
    fprintf(stderr, "[supervisor] started '%s' pid=%d\n", rec->id, pid);
    return 0;
}

/* ================================================================
 * Handle one control client
 * ================================================================ */
static int handle_client(supervisor_ctx_t *ctx, int cfd)
{
    control_request_t  req;
    control_response_t resp;
    memset(&resp, 0, sizeof(resp));

    if (recv(cfd, &req, sizeof(req), 0) != (ssize_t)sizeof(req)) {
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message), "bad request");
        send(cfd, &resp, sizeof(resp), 0);
        return -1;
    }

    switch (req.kind) {

    case CMD_START: {
        int rc = launch_container(ctx, &req);
        resp.status = rc;
        snprintf(resp.message, sizeof(resp.message),
                 rc == 0 ? "ok" : "launch failed");
        send(cfd, &resp, sizeof(resp), 0);
        break;
    }

    case CMD_RUN: {
        int rc = launch_container(ctx, &req);
        if (rc != 0) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message), "launch failed");
            send(cfd, &resp, sizeof(resp), 0);
            break;
        }
        /* Acknowledge start */
        resp.status = 0;
        snprintf(resp.message, sizeof(resp.message), "running");
        send(cfd, &resp, sizeof(resp), 0);

        /* Wait until container exits (poll; SIGCHLD updates state) */
        container_state_t st = CONTAINER_RUNNING;
        while (st == CONTAINER_RUNNING || st == CONTAINER_STARTING) {
            struct timespec ts = {0, 100000000L};
            nanosleep(&ts, NULL);
            container_record_t *rec;
            pthread_mutex_lock(&ctx->metadata_lock);
            for (rec = ctx->containers; rec; rec = rec->next)
                if (strcmp(rec->id, req.container_id) == 0) {
                    st = rec->state; break; }
            pthread_mutex_unlock(&ctx->metadata_lock);
        }

        /* Send final status */
        memset(&resp, 0, sizeof(resp));
        container_record_t *rec;
        pthread_mutex_lock(&ctx->metadata_lock);
        for (rec = ctx->containers; rec; rec = rec->next)
            if (strcmp(rec->id, req.container_id) == 0) {
                resp.status          = 0;
                resp.run_exit_code   = rec->exit_code;
                resp.run_exit_signal = rec->exit_signal;
                snprintf(resp.message, sizeof(resp.message),
                         "state=%s code=%d signal=%d",
                         state_to_string(rec->state),
                         rec->exit_code, rec->exit_signal);
                break;
            }
        pthread_mutex_unlock(&ctx->metadata_lock);
        send(cfd, &resp, sizeof(resp), 0);
        break;
    }

    case CMD_PS: {
        char *p = resp.message, *end = resp.message + sizeof(resp.message) - 1;
        container_record_t *rec;
        pthread_mutex_lock(&ctx->metadata_lock);
        for (rec = ctx->containers; rec && p < end; rec = rec->next) {
            char ts[32];
            strftime(ts, sizeof(ts), "%H:%M:%S",
                     localtime(&rec->started_at));
            int w = snprintf(p, (size_t)(end-p),
                "%-16s pid=%-6d state=%-8s soft=%3luMiB hard=%3luMiB "
                "code=%-3d sig=%-3d start=%s\n",
                rec->id, rec->host_pid, state_to_string(rec->state),
                rec->soft_limit_bytes>>20, rec->hard_limit_bytes>>20,
                rec->exit_code, rec->exit_signal, ts);
            if (w > 0) p += w;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp.status = 0;
        if (p == resp.message)
            snprintf(resp.message, sizeof(resp.message), "(no containers)\n");
        send(cfd, &resp, sizeof(resp), 0);
        break;
    }

    case CMD_LOGS: {
        int found = 0;
        container_record_t *rec;
        pthread_mutex_lock(&ctx->metadata_lock);
        for (rec = ctx->containers; rec; rec = rec->next)
            if (strcmp(rec->id, req.container_id) == 0) {
                snprintf(resp.message, sizeof(resp.message), "%s", rec->log_path);
                found = 1; break;
            }
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp.status = found ? 0 : -1;
        if (!found) snprintf(resp.message, sizeof(resp.message),
                             "container '%s' not found", req.container_id);
        send(cfd, &resp, sizeof(resp), 0);
        break;
    }

    case CMD_STOP: {
        int found = 0;
        container_record_t *rec;
        pthread_mutex_lock(&ctx->metadata_lock);
        for (rec = ctx->containers; rec; rec = rec->next)
            if (strcmp(rec->id, req.container_id) == 0 &&
                rec->state == CONTAINER_RUNNING) {
                /* MUST set stop_requested before signal (attribution rule) */
                rec->stop_requested = 1;
                kill(rec->host_pid, SIGTERM);
                found = 1; break;
            }
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp.status = found ? 0 : -1;
        snprintf(resp.message, sizeof(resp.message),
                 found ? "stop signal sent"
                       : "container not found or not running");
        send(cfd, &resp, sizeof(resp), 0);
        break;
    }

    default:
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message), "unknown command");
        send(cfd, &resp, sizeof(resp), 0);
        break;
    }
    return 0;
}

/* ================================================================
 * Supervisor daemon
 * ================================================================ */
static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    int rc;
    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = ctx.monitor_fd = -1;
    g_ctx = &ctx;

    if ((rc = pthread_mutex_init(&ctx.metadata_lock, NULL)) != 0) {
        errno = rc; perror("mutex_init"); return 1; }
    if ((rc = bounded_buffer_init(&ctx.log_buffer)) != 0) {
        errno = rc; perror("bb_init"); goto out_mutex; }

    ctx.monitor_fd = open("/dev/" DEVICE_NAME, O_RDWR);
    if (ctx.monitor_fd < 0)
        fprintf(stderr, "[supervisor] WARNING: /dev/%s unavailable – "
                        "memory monitoring disabled\n", DEVICE_NAME);

    unlink(CONTROL_PATH);
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) { perror("socket"); goto out_bb; }
    {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path)-1);
        if (bind(ctx.server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
            { perror("bind"); goto out_sock; }
        if (listen(ctx.server_fd, 8) < 0)
            { perror("listen"); goto out_sock; }
    }

    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sigchld_handler;
        sa.sa_flags   = SA_RESTART|SA_NOCLDSTOP;
        sigaction(SIGCHLD, &sa, NULL);
        sa.sa_handler = shutdown_handler;
        sa.sa_flags   = SA_RESTART;
        sigaction(SIGINT,  &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
    }

    if ((rc = pthread_create(&ctx.logger_thread, NULL,
                              logging_thread, &ctx)) != 0) {
        errno = rc; perror("logger thread"); goto out_sock; }

    fprintf(stderr, "[supervisor] ready (rootfs=%s socket=%s)\n",
            rootfs, CONTROL_PATH);

    while (!ctx.should_stop) {
        fd_set rfds;
        struct timeval tv = {1, 0};
        FD_ZERO(&rfds); FD_SET(ctx.server_fd, &rfds);
        int sel = select(ctx.server_fd+1, &rfds, NULL, NULL, &tv);
        if (sel < 0)  { if (errno == EINTR) continue; perror("select"); break; }
        if (sel == 0) continue;
        int cfd = accept(ctx.server_fd, NULL, NULL);
        if (cfd < 0)  { if (errno == EINTR) continue; perror("accept"); continue; }
        handle_client(&ctx, cfd);
        close(cfd);
    }

    fprintf(stderr, "[supervisor] shutting down\n");
    {
        container_record_t *rec;
        pthread_mutex_lock(&ctx.metadata_lock);
        for (rec = ctx.containers; rec; rec = rec->next)
            if (rec->state == CONTAINER_RUNNING) {
                rec->stop_requested = 1;
                kill(rec->host_pid, SIGTERM);
                if (ctx.monitor_fd >= 0)
                    unregister_from_monitor(ctx.monitor_fd,
                                            rec->id, rec->host_pid);
            }
        pthread_mutex_unlock(&ctx.metadata_lock);
    }
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);

out_sock:
    close(ctx.server_fd);
    unlink(CONTROL_PATH);
out_bb:
    bounded_buffer_destroy(&ctx.log_buffer);
    if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);
    { container_record_t *r = ctx.containers;
      while (r) { container_record_t *n = r->next; free(r); r = n; } }
out_mutex:
    pthread_mutex_destroy(&ctx.metadata_lock);
    return 0;
}

/* ================================================================
 * Client: connect and exchange one request/response
 * ================================================================ */
static int send_control_request(const control_request_t *req)
{
    int fd;
    struct sockaddr_un addr;
    control_response_t resp;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path)-1);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect (is the supervisor running?)");
        close(fd); return 1; }
    if (send(fd, req, sizeof(*req), 0) != (ssize_t)sizeof(*req)) {
        perror("send"); close(fd); return 1; }

    if (req->kind == CMD_RUN) {
        /* First recv: launch ack */
        if (recv(fd, &resp, sizeof(resp), 0) != (ssize_t)sizeof(resp)) {
            perror("recv ack"); close(fd); return 1; }
        if (resp.status != 0) {
            fprintf(stderr, "run failed: %s\n", resp.message);
            close(fd); return 1; }
        fprintf(stderr, "[run] waiting for container to finish…\n");
        /* Second recv: final exit (blocks until container done) */
        if (recv(fd, &resp, sizeof(resp), 0) != (ssize_t)sizeof(resp)) {
            perror("recv final"); close(fd); return 1; }
        close(fd);
        printf("%s\n", resp.message);
        return resp.run_exit_signal ? 128 + resp.run_exit_signal
                                    : resp.run_exit_code;
    }

    if (recv(fd, &resp, sizeof(resp), 0) != (ssize_t)sizeof(resp)) {
        perror("recv"); close(fd); return 1; }
    close(fd);

    if (req->kind == CMD_LOGS && resp.status == 0) {
        FILE *f = fopen(resp.message, "r");
        if (f) { char buf[512];
                 while (fgets(buf, sizeof(buf), f)) fputs(buf, stdout);
                 fclose(f); }
        else fprintf(stderr, "Cannot open log: %s\n", resp.message);
        return 0;
    }
    printf("%s\n", resp.message);
    return resp.status == 0 ? 0 : 1;
}

/* ================================================================
 * CLI helpers
 * ================================================================ */
static int parse_mib_flag(const char *flag, const char *value, unsigned long *out)
{
    char *end; unsigned long mib;
    errno = 0; mib = strtoul(value, &end, 10);
    if (errno || end == value || *end || mib > ULONG_MAX/(1UL<<20)) {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value); return -1; }
    *out = mib << 20; return 0;
}

static int parse_optional_flags(control_request_t *req,
                                 int argc, char *argv[], int start)
{
    int i;
    for (i = start; i < argc; i += 2) {
        if (i+1 >= argc) { fprintf(stderr,"Missing value for %s\n",argv[i]); return -1; }
        if (!strcmp(argv[i],"--soft-mib")) {
            if (parse_mib_flag("--soft-mib",argv[i+1],&req->soft_limit_bytes)) return -1;
        } else if (!strcmp(argv[i],"--hard-mib")) {
            if (parse_mib_flag("--hard-mib",argv[i+1],&req->hard_limit_bytes)) return -1;
        } else if (!strcmp(argv[i],"--nice")) {
            char *end; long nv = strtol(argv[i+1],&end,10);
            if (errno||end==argv[i+1]||*end||nv<-20||nv>19) {
                fprintf(stderr,"Invalid --nice: %s\n",argv[i+1]); return -1; }
            req->nice_value = (int)nv;
        } else { fprintf(stderr,"Unknown option: %s\n",argv[i]); return -1; }
    }
    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr,"soft limit cannot exceed hard limit\n"); return -1; }
    return 0;
}

static void usage(const char *p) {
    fprintf(stderr,
        "Usage:\n"
        "  %s supervisor <base-rootfs>\n"
        "  %s start <id> <rootfs> <cmd> [--soft-mib N] [--hard-mib N] [--nice N]\n"
        "  %s run   <id> <rootfs> <cmd> [--soft-mib N] [--hard-mib N] [--nice N]\n"
        "  %s ps\n  %s logs <id>\n  %s stop <id>\n",
        p,p,p,p,p,p);
}

static int cmd_start(int argc, char *argv[]) {
    control_request_t req;
    if (argc < 5) { usage(argv[0]); return 1; }
    memset(&req,0,sizeof(req)); req.kind=CMD_START;
    strncpy(req.container_id,argv[2],sizeof(req.container_id)-1);
    strncpy(req.rootfs,argv[3],sizeof(req.rootfs)-1);
    strncpy(req.command,argv[4],sizeof(req.command)-1);
    req.soft_limit_bytes=DEFAULT_SOFT_LIMIT; req.hard_limit_bytes=DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req,argc,argv,5)) return 1;
    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[]) {
    control_request_t req;
    if (argc < 5) { usage(argv[0]); return 1; }
    memset(&req,0,sizeof(req)); req.kind=CMD_RUN;
    strncpy(req.container_id,argv[2],sizeof(req.container_id)-1);
    strncpy(req.rootfs,argv[3],sizeof(req.rootfs)-1);
    strncpy(req.command,argv[4],sizeof(req.command)-1);
    req.soft_limit_bytes=DEFAULT_SOFT_LIMIT; req.hard_limit_bytes=DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req,argc,argv,5)) return 1;
    return send_control_request(&req);
}

static int cmd_ps(void) {
    control_request_t req; memset(&req,0,sizeof(req)); req.kind=CMD_PS;
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[]) {
    if (argc < 3) { fprintf(stderr,"Usage: %s logs <id>\n",argv[0]); return 1; }
    control_request_t req; memset(&req,0,sizeof(req)); req.kind=CMD_LOGS;
    strncpy(req.container_id,argv[2],sizeof(req.container_id)-1);
    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[]) {
    if (argc < 3) { fprintf(stderr,"Usage: %s stop <id>\n",argv[0]); return 1; }
    control_request_t req; memset(&req,0,sizeof(req)); req.kind=CMD_STOP;
    strncpy(req.container_id,argv[2],sizeof(req.container_id)-1);
    return send_control_request(&req);
}

/* ================================================================
 * main
 * ================================================================ */
int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }
    if (!strcmp(argv[1],"supervisor")) {
        if (argc < 3) { fprintf(stderr,"Usage: %s supervisor <rootfs>\n",argv[0]); return 1; }
        return run_supervisor(argv[2]);
    }
    if (!strcmp(argv[1],"start")) return cmd_start(argc,argv);
    if (!strcmp(argv[1],"run"))   return cmd_run(argc,argv);
    if (!strcmp(argv[1],"ps"))    return cmd_ps();
    if (!strcmp(argv[1],"logs"))  return cmd_logs(argc,argv);
    if (!strcmp(argv[1],"stop"))  return cmd_stop(argc,argv);
    usage(argv[0]); return 1;
}
