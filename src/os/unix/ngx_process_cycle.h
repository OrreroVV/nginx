/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

/*
 * 该头文件定义了Nginx进程管理相关的数据结构和函数声明
 * 包括进程类型、进程间通信命令、以及进程生命周期控制
 */

#ifndef _NGX_PROCESS_CYCLE_H_INCLUDED_
#define _NGX_PROCESS_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/* 进程间通信的命令定义 */
#define NGX_CMD_OPEN_CHANNEL   1    /* 打开通道命令 */
#define NGX_CMD_CLOSE_CHANNEL  2    /* 关闭通道命令 */
#define NGX_CMD_QUIT           3    /* 优雅退出命令 */
#define NGX_CMD_TERMINATE      4    /* 立即终止命令 */
#define NGX_CMD_REOPEN         5    /* 重新打开文件命令 */


/* Nginx进程类型定义 */
#define NGX_PROCESS_SINGLE     0    /* 单进程模式 */
#define NGX_PROCESS_MASTER     1    /* master进程 */
#define NGX_PROCESS_SIGNALLER  2    /* 信号处理进程 */
#define NGX_PROCESS_WORKER     3    /* worker进程 */
#define NGX_PROCESS_HELPER     4    /* 辅助进程(如缓存管理进程) */


/* 缓存管理器上下文结构体 */
typedef struct {
    ngx_event_handler_pt       handler;    /* 事件处理函数指针 */
    char                      *name;        /* 进程名称 */
    ngx_msec_t                 delay;       /* 处理延迟时间 */
} ngx_cache_manager_ctx_t;


/**
 * @brief Nginx master进程的主循环函数
 * 
 * master进程主要负责：
 * 1. 监控和管理worker进程
 * 2. 处理信号
 * 3. 实现热重启、热升级等功能
 * 4. 不处理网络事件和业务
 *
 * 工作流程：
 * 1. 初始化信号集，设置需要处理的信号
 * 2. 设置进程标题
 * 3. 启动worker进程和cache管理进程
 * 4. 进入无限循环:
 *    - 处理子进程退出
 *    - 处理信号(退出、重启、重载配置等)
 *    - 管理worker进程数量
 *
 * @param cycle Nginx核心配置结构体
 */
void ngx_master_process_cycle(ngx_cycle_t *cycle);    /* master进程的主循环 */
void ngx_single_process_cycle(ngx_cycle_t *cycle);    /* 单进程模式的主循环 */


/* 全局变量声明 */
extern ngx_uint_t      ngx_process;        /* 当前进程类型 */
extern ngx_uint_t      ngx_worker;         /* worker进程序号 */
extern ngx_pid_t       ngx_pid;            /* 当前进程ID */
extern ngx_pid_t       ngx_new_binary;     /* 新的二进制文件进程ID */
extern ngx_uint_t      ngx_inherited;      /* 标识是否是继承的socket */
extern ngx_uint_t      ngx_daemonized;     /* 是否以守护进程方式运行 */
extern ngx_uint_t      ngx_exiting;        /* 进程是否正在退出 */

/* 信号相关的全局标志位 */
extern sig_atomic_t    ngx_reap;           /* 子进程结束信号标志 */
extern sig_atomic_t    ngx_sigio;          /* SIGIO信号标志 */
extern sig_atomic_t    ngx_sigalrm;        /* SIGALRM信号标志 */
extern sig_atomic_t    ngx_quit;           /* 优雅退出信号标志 */
extern sig_atomic_t    ngx_debug_quit;     /* 调试模式退出信号标志 */
extern sig_atomic_t    ngx_terminate;      /* 立即终止信号标志 */
extern sig_atomic_t    ngx_noaccept;       /* 停止接受新连接信号标志 */
extern sig_atomic_t    ngx_reconfigure;    /* 重新加载配置信号标志 */
extern sig_atomic_t    ngx_reopen;         /* 重新打开文件信号标志 */
extern sig_atomic_t    ngx_change_binary;  /* 平滑升级信号标志 */


#endif /* _NGX_PROCESS_CYCLE_H_INCLUDED_ */
