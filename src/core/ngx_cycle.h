
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
    void                     *data;
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init;
    void                     *tag;
    void                     *sync;
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


struct ngx_cycle_s {
    void                  ****conf_ctx; /* 配置上下文的多维数组，每个模块的配置信息按不同级别组织（如 main、srv、loc）。 */
    ngx_pool_t               *pool; /* 全局内存池地址，用于管理生命周期内的内存分配。 */

    ngx_log_t                *log; /* 指向全局日志对象，用于记录服务器运行时的日志信息。 */
    ngx_log_t                 new_log; /* 启动期间使用的临时日志对象。 */

    ngx_uint_t                log_use_stderr;  /* 标志位，指示是否将日志输出到标准错误(stderr)。 */

    ngx_connection_t        **files; /* 文件描述符与连接对象的映射数组，用于管理活动连接的文件句柄。 */
    ngx_connection_t         *free_connections; /* 空闲连接链表，用于快速复用连接对象，减少内存分配开销。 */
    ngx_uint_t                free_connection_n; /* 当前可用的空闲连接数量。 */

    ngx_module_t            **modules; /* 已加载模块的数组，每个元素是一个模块定义（ngx_module_t）。 */
    ngx_uint_t                modules_n; /* 模块的总数，用于遍历和管理模块。 */
    ngx_uint_t                modules_used;    /* 标志位，指示模块是否被实际使用。 */

    ngx_queue_t               reusable_connections_queue; /* 可重复使用连接的队列，用于连接复用优化。 */
    ngx_uint_t                reusable_connections_n; /* 可复用连接的数量。 */
    time_t                    connections_reuse_time; /* 可复用连接的超时时间，用于控制复用策略。 */

    ngx_array_t               listening; /* 监听套接字数组，存储所有监听端口的配置信息（ngx_listening_t）。 */
    ngx_array_t               paths; /* 路径数组，存储运行过程中需要操作的路径（如日志、临时文件路径等）。 */

    ngx_array_t               config_dump; /* 配置转储数组，用于调试或导出当前的配置状态。 */
    ngx_rbtree_t              config_dump_rbtree; /* 配置转储的红黑树，用于快速存储和查找配置项。 */
    ngx_rbtree_node_t         config_dump_sentinel; /* 红黑树的哨兵节点，用于标识树的边界。 */

    ngx_list_t                open_files; /* 已打开文件的链表，记录所有活动的文件句柄信息。 */
    ngx_list_t                shared_memory; /* 共享内存链表，用于管理模块间的共享内存段。 */

    ngx_uint_t                connection_n; /* 最大连接数，表示服务器支持的并发连接上限。 */
    ngx_uint_t                files_n; /* 最大文件描述符数，表示支持的最大打开文件数量。 */

    ngx_connection_t         *connections; /* 连接对象数组，每个元素表示一个活动连接（ngx_connection_t）。 */
    ngx_event_t              *read_events; /* 读事件数组，每个元素表示一个读事件（ngx_event_t）。 */
    ngx_event_t              *write_events; /* 写事件数组，每个元素表示一个写事件（ngx_event_t）。 */

    ngx_cycle_t              *old_cycle; /* 指向旧的周期上下文，通常用于热重载保存之前的状态。 */

    ngx_str_t                 conf_file; /* 配置文件路径，指定服务器启动时加载的配置文件。 */
    ngx_str_t                 conf_param; /* 配置参数，表示通过命令行传递的动态配置。 */
    ngx_str_t                 conf_prefix; /* 配置文件前缀，用于处理相对路径。 */
    ngx_str_t                 prefix; /* Nginx 的安装路径前缀，用于构建绝对路径。 */
    ngx_str_t                 error_log; /* 错误日志文件路径，用于记录运行时的错误信息。 */
    ngx_str_t                 lock_file; /* 锁文件路径，用于进程间的互斥锁操作。 */
    ngx_str_t                 hostname; /* 主机名称，存储服务器运行时的主机名信息。 */
};


/**
 * 核心配置文件信息
 * 对应nginx.conf
 */
typedef struct {
    ngx_flag_t                daemon; /* 是否以守护进程模式运行（1 表示启用守护进程）。 */
    ngx_flag_t                master; /* 是否启用 master-worker 模式（1 表示启用）。 */

    ngx_msec_t                timer_resolution; /* 定时器分辨率，控制时间事件的精度。 */
    ngx_msec_t                shutdown_timeout; /* 优雅关闭的超时时间。 */

    ngx_int_t                 worker_processes; /* 工作进程数，表示并发处理能力。 */
    ngx_int_t                 debug_points; /* 调试点标志，用于启用特定的调试功能。 */

    ngx_int_t                 rlimit_nofile; /* 最大打开文件数限制，对应 ulimit -n 的配置。 */
    off_t                     rlimit_core; /* core 文件的大小限制，用于调试时生成 core dump 文件。 */

    int                       priority; /* 进程优先级，数值越小优先级越高。 */

    ngx_uint_t                cpu_affinity_auto; /* 自动 CPU 亲和性标志，决定是否自动绑定 CPU。 */
    ngx_uint_t                cpu_affinity_n; /* CPU 亲和性配置的 CPU 核心数量。 */
    ngx_cpuset_t             *cpu_affinity; /* CPU 亲和性设置的掩码，用于绑定具体的 CPU 核心。 */

    char                     *username; /* 启动进程的用户名，用于权限控制。 */
    ngx_uid_t                 user; /* 用户 ID，与 username 对应。 */
    ngx_gid_t                 group; /* 用户组 ID，与 username 对应。 */

    ngx_str_t                 working_directory; /* 工作目录路径，指定服务器运行的默认目录。 */
    ngx_str_t                 lock_file; /* 锁文件路径，用于进程间互斥锁操作。 */

    ngx_str_t                 pid; /* 主进程 PID 文件路径。 */
    ngx_str_t                 oldpid; /* 热重载时的旧 PID 文件路径。 */

    ngx_array_t               env; /* 自定义环境变量数组。 */
    char                    **environment; /* 环境变量数组的实际存储指针。 */

    ngx_uint_t                transparent; /* 标志位，是否启用透明代理功能（1 表示启用）。 */
} ngx_core_conf_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);
void ngx_set_shutdown_timer(ngx_cycle_t *cycle);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
