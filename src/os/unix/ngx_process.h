
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


#include <ngx_setaffinity.h>
#include <ngx_setproctitle.h>


typedef pid_t       ngx_pid_t;

#define NGX_INVALID_PID  -1

typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);

typedef struct {
    ngx_pid_t           pid;            // 子进程的进程ID（PID）。用于标识进程。
    int                 status;         // 子进程的状态。通常用来标记进程是否正常运行、退出或出错。
    ngx_socket_t        channel[2];     /** 用于父子进程间通信的套接字对，通常是通过 `socketpair()` 创建。channel[0] 是父进程和子进程通信的其中一端，channel[1] 是另一端。父进程通过 channel[0] 向子进程发送数据，反之亦然。*/

    ngx_spawn_proc_pt   proc;           // 子进程启动时需要执行的函数（函数指针）。通常会传入处理逻辑或任务。
    void               *data;           // 传递给 `proc` 的额外数据。可以用来传递上下文或其他必要的参数。
    char               *name;           // 子进程的名称。通常是进程的标识符，用于日志或调试输出。

    unsigned            respawn:1;      // 标记子进程是否需要重生。如果为 1，表示进程需要在退出时自动重生。
    unsigned            just_spawn:1;   // 标记子进程是否是“刚启动”的状态。如果为 1，表示子进程是刚创建的，还没有启动任务。
    unsigned            detached:1;     // 标记子进程是否是“脱离”父进程的。如果为 1，表示子进程是分离的，不需要父进程管理。
    unsigned            exiting:1;      // 标记子进程是否正在退出。如果为 1，表示该进程正在退出并且正在清理资源。
    unsigned            exited:1;       // 标记子进程是否已经退出。如果为 1，表示该进程已经退出并且资源已清理完毕。
} ngx_process_t;


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} ngx_exec_ctx_t;


#define NGX_MAX_PROCESSES         1024

#define NGX_PROCESS_NORESPAWN     -1
#define NGX_PROCESS_JUST_SPAWN    -2
#define NGX_PROCESS_RESPAWN       -3
#define NGX_PROCESS_JUST_RESPAWN  -4
#define NGX_PROCESS_DETACHED      -5


#define ngx_getpid   getpid
#define ngx_getppid  getppid

#ifndef ngx_log_pid
#define ngx_log_pid  ngx_pid
#endif


/**
 * @brief 在 Nginx 中创建一个新的子进程。
 * 该函数的核心功能是启动一个子进程，设置子进程的相关属性（如进程的信号处理、通道等），并根据不同的参数（如是否需要重启、是否需要脱离父进程等）处理子进程的生命周期管理。
 * @param cycle 
 * @param proc 
 * @param data 
 * @param name 
 * @param respawn 
 * @return ngx_pid_t 
 */
ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
    ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
ngx_int_t ngx_init_signals(ngx_log_t *log);
void ngx_debug_point(void);


#if (NGX_HAVE_SCHED_YIELD)
#define ngx_sched_yield()  sched_yield()
#else
#define ngx_sched_yield()  usleep(1)
#endif


extern int            ngx_argc;
extern char         **ngx_argv;
extern char         **ngx_os_argv;

extern ngx_pid_t      ngx_pid;
extern ngx_pid_t      ngx_parent;
extern ngx_socket_t   ngx_channel;
extern ngx_int_t      ngx_process_slot;
extern ngx_int_t      ngx_last_process;
extern ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


#endif /* _NGX_PROCESS_H_INCLUDED_ */
