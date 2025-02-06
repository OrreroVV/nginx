
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

struct ngx_listening_s {
    ngx_socket_t        fd;                 /* 套接字文件描述符，用于标识一个具体的监听端口 */

    struct sockaddr    *sockaddr;           /* 指向监听的地址（IP 和端口）的 sockaddr 结构 */
    socklen_t           socklen;            /* sockaddr 结构的长度，用于 bind 或 accept 调用 */
    size_t              addr_text_max_len;  /* addr_text 的最大长度（以字节为单位） */
    ngx_str_t           addr_text;          /* 地址的字符串形式（例如 "127.0.0.1:80"） */

    int                 type;               /* 套接字类型，例如 SOCK_STREAM 表示 TCP，SOCK_DGRAM 表示 UDP */

    int                 backlog;            /* listen 的队列长度，控制未完成连接的最大数量 */
    int                 rcvbuf;             /* 接收缓冲区大小，通过 setsockopt 设置 SO_RCVBUF */
    int                 sndbuf;             /* 发送缓冲区大小，通过 setsockopt 设置 SO_SNDBUF */

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;           /* TCP 连接空闲时首次发送保活探测包的等待时间（秒） */
    int                 keepintvl;          /* TCP 保活探测包之间的间隔时间（秒） */
    int                 keepcnt;            /* TCP 保活探测失败的最大次数 */
#endif

    ngx_connection_handler_pt   handler;    /* 接收到连接后调用的回调函数，处理新连接 */
    void               *servers;            /* 指向与此监听端口相关的服务模块配置，
                                               例如 HTTP 模块会指向 ngx_http_in_addr_t 数组 */

    ngx_log_t           log;                /* 套接字相关的日志对象 */
    ngx_log_t          *logp;               /* 指向日志对象的指针（可能与 log 相同，也可能不同） */

    size_t              pool_size;          /* 每个连接内存池的大小，用于管理连接的内存分配 */
    size_t              post_accept_buffer_size; /* AcceptEx 的预读缓冲区大小（仅在 Windows 平台使用） */

    ngx_listening_t    *previous;           /* 指向上一个监听套接字，用于管理链表结构 */
    ngx_connection_t   *connection;         /* 当前监听套接字对应的连接对象 */

    ngx_rbtree_t        rbtree;             /* 红黑树，用于存储和快速查找与此监听端口相关的数据 */
    ngx_rbtree_node_t   sentinel;           /* 红黑树的哨兵节点 */

    ngx_uint_t          worker;             /* 当前监听套接字所属的工作进程 ID */

    /* 套接字的标志位，用于控制不同的行为 */
    unsigned            open:1;             /* 套接字是否已打开 */
    unsigned            remain:1;           /* 套接字是否需要保持在当前进程中 */
    unsigned            ignore:1;           /* 是否忽略此监听端口 */

    unsigned            bound:1;            /* 是否已绑定到地址 */
    unsigned            inherited:1;        /* 是否从父进程继承的监听套接字 */
    unsigned            nonblocking_accept:1; /* 是否使用非阻塞方式接受连接 */
    unsigned            listen:1;           /* 是否已调用 listen 函数 */
    unsigned            nonblocking:1;      /* 是否已设置为非阻塞模式 */
    unsigned            shared:1;           /* 是否在多线程或多进程间共享 */
    unsigned            addr_ntop:1;        /* 是否需要将地址转为字符串形式存储在 addr_text 中 */
    unsigned            wildcard:1;         /* 是否为通配符地址（如 0.0.0.0 或 [::]，表示监听所有地址） */

#if (NGX_HAVE_INET6)
    unsigned            ipv6only:1;         /* 是否为 IPv6 only 模式，仅监听 IPv6 地址（通过 setsockopt 设置） */
#endif
    unsigned            reuseport:1;        /* 是否启用了 SO_REUSEPORT 选项，允许多个进程监听同一端口 */
    unsigned            add_reuseport:1;    /* 是否需要为此监听套接字添加 reuseport 标志 */
    unsigned            keepalive:2;        /* 是否启用了 TCP 保活选项（SO_KEEPALIVE） */
    unsigned            quic:1;             /* 是否为 QUIC 协议监听 */

    unsigned            deferred_accept:1;  /* 是否启用了延迟接受（Deferred Accept），在有数据时才建立连接 */
    unsigned            delete_deferred:1;  /* 是否删除延迟接受 */
    unsigned            add_deferred:1;     /* 是否添加延迟接受 */

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char               *accept_filter;      /* FreeBSD 的 Accept 过滤器 */
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;             /* FreeBSD 的 FIB（Forwarding Information Base）标识 */
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;           /* 是否启用了 TCP Fast Open，值为最大队列长度 */
#endif
};


typedef enum {
    NGX_ERROR_ALERT = 0,
    NGX_ERROR_ERR,
    NGX_ERROR_INFO,
    NGX_ERROR_IGNORE_ECONNRESET,
    NGX_ERROR_IGNORE_EINVAL,
    NGX_ERROR_IGNORE_EMSGSIZE
} ngx_connection_log_error_e;


typedef enum {
    NGX_TCP_NODELAY_UNSET = 0,
    NGX_TCP_NODELAY_SET,
    NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
    NGX_TCP_NOPUSH_UNSET = 0,
    NGX_TCP_NOPUSH_SET,
    NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_HTTP_V2_BUFFERED   0x02


struct ngx_connection_s {
    void               *data;
    ngx_event_t        *read;
    ngx_event_t        *write;

    ngx_socket_t        fd;

    ngx_recv_pt         recv;
    ngx_send_pt         send;
    ngx_recv_chain_pt   recv_chain;
    ngx_send_chain_pt   send_chain;

    ngx_listening_t    *listening;

    off_t               sent;

    ngx_log_t          *log;

    ngx_pool_t         *pool;

    int                 type;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;
    ngx_str_t           addr_text;

    ngx_proxy_protocol_t  *proxy_protocol;

#if (NGX_QUIC || NGX_COMPAT)
    ngx_quic_stream_t     *quic;
#endif

#if (NGX_SSL || NGX_COMPAT)
    ngx_ssl_connection_t  *ssl;
#endif

    ngx_udp_connection_t  *udp;

    struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;

    ngx_buf_t          *buffer;

    ngx_queue_t         queue;

    ngx_atomic_uint_t   number;

    ngx_msec_t          start_time;
    ngx_uint_t          requests;

    unsigned            buffered:8;

    unsigned            log_error:3;     /* ngx_connection_log_error_e */

    unsigned            timedout:1;
    unsigned            error:1;
    unsigned            destroyed:1;
    unsigned            pipeline:1;

    unsigned            idle:1;
    unsigned            reusable:1;
    unsigned            close:1;
    unsigned            shared:1;

    unsigned            sendfile:1;
    unsigned            sndlowat:1;
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */

    unsigned            need_last_buf:1;
    unsigned            need_flush_buf:1;

#if (NGX_HAVE_SENDFILE_NODISKIO || NGX_COMPAT)
    unsigned            busy_count:2;
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_thread_task_t  *sendfile_task;
#endif
};


#define ngx_set_connection_log(c, l)                                         \
                                                                             \
    c->log->file = l->file;                                                  \
    c->log->next = l->next;                                                  \
    c->log->writer = l->writer;                                              \
    c->log->wdata = l->wdata;                                                \
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {                   \
        c->log->log_level = l->log_level;                                    \
    }


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, struct sockaddr *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_clone_listening(ngx_cycle_t *cycle, ngx_listening_t *ls);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
void ngx_close_idle_connections(ngx_cycle_t *cycle);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_tcp_nodelay(ngx_connection_t *c);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
