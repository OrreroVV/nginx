
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_H_INCLUDED_
#define _NGX_EVENT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_INVALID_INDEX  0xd0d0d0d0


#if (NGX_HAVE_IOCP)

typedef struct {
    WSAOVERLAPPED    ovlp;
    ngx_event_t     *event;
    int              error;
} ngx_event_ovlp_t;

#endif


struct ngx_event_s {
    // data 字段：指向与该事件相关联的用户自定义数据，可以存储连接、请求等上下文信息
    void            *data;

    // write 标志：占用1位，标识该事件是否为写事件（1表示写事件）
    unsigned         write:1;

    // accept 标志：占用1位，用于指示该事件是否用于接受新连接（1表示是accept事件）
    unsigned         accept:1;

    /* used to detect the stale events in kqueue and epoll */
    // instance 标志：占用1位，用于在kqueue和epoll中检测陈旧（stale）的事件
    unsigned         instance:1;

    /*
     * the event was passed or would be passed to a kernel;
     * in aio mode - operation was posted.
     */
    // active 标志：占用1位，表明该事件是否已经传递给内核或在AIO模式下已提交操作
    unsigned         active:1;

    // disabled 标志：占用1位，指示该事件是否被禁用，在禁用状态下该事件将不会被激活处理
    unsigned         disabled:1;

    /* the ready event; in aio mode 0 means that no operation can be posted */
    // ready 标志：占用1位，表示事件是否准备就绪；在AIO模式下，0表示无法提交后续操作
    unsigned         ready:1;

    // oneshot 标志：占用1位，标识该事件是否为一次性事件，触发后事件需重新注册
    unsigned         oneshot:1;

    /* aio operation is complete */
    // complete 标志：占用1位，用以标记AIO操作是否已完成
    unsigned         complete:1;

    // eof 标志：占用1位，表示在该事件中是否遇到了文件结束（EOF）情况
    unsigned         eof:1;
    // error 标志：占用1位，表示事件处理中是否产生了错误
    unsigned         error:1;

    // timedout 标志：占用1位，指明该事件是否因超时而触发
    unsigned         timedout:1;
    // timer_set 标志：占用1位，表示是否为事件设置了定时器
    unsigned         timer_set:1;

    // delayed 标志：占用1位，指示该事件的处理是否被延迟
    unsigned         delayed:1;

    // deferred_accept 标志：占用1位，用于指示是否启用延迟接受机制，只有在有数据到达时才真正接受连接
    unsigned         deferred_accept:1;

    /* the pending eof reported by kqueue, epoll or in aio chain operation */
    // pending_eof 标志：占用1位，用于存储由kqueue、epoll或AIO链操作报告的待处理EOF状态
    unsigned         pending_eof:1;

    // posted 标志：占用1位，表示该事件是否已被添加到事件队列中等待调度处理
    unsigned         posted:1;

    // closed 标志：占用1位，标识关联的连接是否已经关闭（1表示连接已关闭）
    unsigned         closed:1;

    /* to test on worker exit */
    // channel 标志：占用1位，可用于在工作进程退出时进行状态检测
    unsigned         channel:1;
    // resolver 标志：占用1位，用于标识事件是否与DNS解析相关
    unsigned         resolver:1;

    // cancelable 标志：占用1位，指示该事件是否支持在处理中被取消
    unsigned         cancelable:1;

#if (NGX_HAVE_KQUEUE)
    // kq_vnode 标志：占用1位，仅在使用kqueue时有效，用于标记vnode相关的事件
    unsigned         kq_vnode:1;

    /* the pending errno reported by kqueue */
    // kq_errno字段：用来存储kqueue报告的待处理错误码
    int              kq_errno;
#endif

    /*
     * kqueue only:
     *   accept:     number of sockets that wait to be accepted
     *   read:       bytes to read when event is ready
     *               or lowat when event is set with NGX_LOWAT_EVENT flag
     *   write:      available space in buffer when event is ready
     *               or lowat when event is set with NGX_LOWAT_EVENT flag
     *
     * iocp: TODO
     *
     * otherwise:
     *   accept:     1 if accept many, 0 otherwise
     *   read:       bytes to read when event is ready, -1 if not known
     */
    // available 字段：整型数据，用于记录与事件相关的可用数量，如待接受的socket数量或可读/可写的字节数
    int              available;

    // handler 字段：函数指针，指向事件触发时调用的处理函数
    ngx_event_handler_pt  handler;

#if (NGX_HAVE_IOCP)
    // ovlp字段：在IOCP模式下使用的重叠结构体，保存与IOCP操作相关的参数和状态
    ngx_event_ovlp_t ovlp;
#endif

    // index 字段：无符号整型，用于标识该事件在数组或其他数据结构中的索引位置
    ngx_uint_t       index;

    // log 字段：指向日志结构体的指针，用于在事件处理过程中记录调试、错误等日志信息
    ngx_log_t       *log;

    // timer 字段：红黑树节点，利用该节点将事件安排至定时器管理的红黑树中
    ngx_rbtree_node_t   timer;

    /* the posted queue */
    // queue 字段：队列节点，用于将该事件插入到待处理（posted）的事件队列中
    ngx_queue_t      queue;

#if 0
    // 以下代码块被禁用，目前用于多线程支持扩展，当编译器不支持__thread声明且pthread_getspecific()性能不足时使用

    /* the threads support */

    /*
     * the event thread context, we store it here
     * if $(CC) does not understand __thread declaration
     * and pthread_getspecific() is too costly
     */
    // thr_ctx 字段：保存事件对应的线程上下文信息，用于优化线程本地存储的访问
    void            *thr_ctx;

#if (NGX_EVENT_T_PADDING)
    /* event should not cross cache line in SMP */
    // padding 数组：用于填充结构体，确保事件结构体不会跨越CPU缓存行，在SMP系统中提升性能
    uint32_t         padding[NGX_EVENT_T_PADDING];
#endif
#endif
};


#if (NGX_HAVE_FILE_AIO)

struct ngx_event_aio_s {
    void                      *data;
    ngx_event_handler_pt       handler;
    ngx_file_t                *file;

    ngx_fd_t                   fd;

#if (NGX_HAVE_EVENTFD)
    int64_t                    res;
#endif

#if !(NGX_HAVE_EVENTFD) || (NGX_TEST_BUILD_EPOLL)
    ngx_err_t                  err;
    size_t                     nbytes;
#endif

    ngx_aiocb_t                aiocb;
    ngx_event_t                event;
};

#endif


typedef struct {
    ngx_int_t  (*add)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
    ngx_int_t  (*del)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);

    ngx_int_t  (*enable)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
    ngx_int_t  (*disable)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);

    ngx_int_t  (*add_conn)(ngx_connection_t *c);
    ngx_int_t  (*del_conn)(ngx_connection_t *c, ngx_uint_t flags);

    ngx_int_t  (*notify)(ngx_event_handler_pt handler);

    ngx_int_t  (*process_events)(ngx_cycle_t *cycle, ngx_msec_t timer,
                                 ngx_uint_t flags);

    ngx_int_t  (*init)(ngx_cycle_t *cycle, ngx_msec_t timer);
    void       (*done)(ngx_cycle_t *cycle);
} ngx_event_actions_t;


extern ngx_event_actions_t   ngx_event_actions;
#if (NGX_HAVE_EPOLLRDHUP)
extern ngx_uint_t            ngx_use_epoll_rdhup;
#endif


/*
 * The event filter requires to read/write the whole data:
 * select, poll, /dev/poll, kqueue, epoll.
 */
#define NGX_USE_LEVEL_EVENT      0x00000001

/*
 * The event filter is deleted after a notification without an additional
 * syscall: kqueue, epoll.
 */
#define NGX_USE_ONESHOT_EVENT    0x00000002

/*
 * The event filter notifies only the changes and an initial level:
 * kqueue, epoll.
 */
#define NGX_USE_CLEAR_EVENT      0x00000004

/*
 * The event filter has kqueue features: the eof flag, errno,
 * available data, etc.
 */
#define NGX_USE_KQUEUE_EVENT     0x00000008

/*
 * The event filter supports low water mark: kqueue's NOTE_LOWAT.
 * kqueue in FreeBSD 4.1-4.2 has no NOTE_LOWAT so we need a separate flag.
 */
#define NGX_USE_LOWAT_EVENT      0x00000010

/*
 * The event filter requires to do i/o operation until EAGAIN: epoll.
 */
#define NGX_USE_GREEDY_EVENT     0x00000020

/*
 * The event filter is epoll.
 */
#define NGX_USE_EPOLL_EVENT      0x00000040

/*
 * Obsolete.
 */
#define NGX_USE_RTSIG_EVENT      0x00000080

/*
 * Obsolete.
 */
#define NGX_USE_AIO_EVENT        0x00000100

/*
 * Need to add socket or handle only once: i/o completion port.
 */
#define NGX_USE_IOCP_EVENT       0x00000200

/*
 * The event filter has no opaque data and requires file descriptors table:
 * poll, /dev/poll.
 */
#define NGX_USE_FD_EVENT         0x00000400

/*
 * The event module handles periodic or absolute timer event by itself:
 * kqueue in FreeBSD 4.4, NetBSD 2.0, and MacOSX 10.4, Solaris 10's event ports.
 */
#define NGX_USE_TIMER_EVENT      0x00000800

/*
 * All event filters on file descriptor are deleted after a notification:
 * Solaris 10's event ports.
 */
#define NGX_USE_EVENTPORT_EVENT  0x00001000

/*
 * The event filter support vnode notifications: kqueue.
 */
#define NGX_USE_VNODE_EVENT      0x00002000


/*
 * The event filter is deleted just before the closing file.
 * Has no meaning for select and poll.
 * kqueue, epoll, eventport:         allows to avoid explicit delete,
 *                                   because filter automatically is deleted
 *                                   on file close,
 *
 * /dev/poll:                        we need to flush POLLREMOVE event
 *                                   before closing file.
 */
#define NGX_CLOSE_EVENT    1

/*
 * disable temporarily event filter, this may avoid locks
 * in kernel malloc()/free(): kqueue.
 */
#define NGX_DISABLE_EVENT  2

/*
 * event must be passed to kernel right now, do not wait until batch processing.
 */
#define NGX_FLUSH_EVENT    4


/* these flags have a meaning only for kqueue */
#define NGX_LOWAT_EVENT    0
#define NGX_VNODE_EVENT    0


#if (NGX_HAVE_EPOLL) && !(NGX_HAVE_EPOLLRDHUP)
#define EPOLLRDHUP         0
#endif


#if (NGX_HAVE_KQUEUE)

#define NGX_READ_EVENT     EVFILT_READ
#define NGX_WRITE_EVENT    EVFILT_WRITE

#undef  NGX_VNODE_EVENT
#define NGX_VNODE_EVENT    EVFILT_VNODE

/*
 * NGX_CLOSE_EVENT, NGX_LOWAT_EVENT, and NGX_FLUSH_EVENT are the module flags
 * and they must not go into a kernel so we need to choose the value
 * that must not interfere with any existent and future kqueue flags.
 * kqueue has such values - EV_FLAG1, EV_EOF, and EV_ERROR:
 * they are reserved and cleared on a kernel entrance.
 */
#undef  NGX_CLOSE_EVENT
#define NGX_CLOSE_EVENT    EV_EOF

#undef  NGX_LOWAT_EVENT
#define NGX_LOWAT_EVENT    EV_FLAG1

#undef  NGX_FLUSH_EVENT
#define NGX_FLUSH_EVENT    EV_ERROR

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  EV_ONESHOT
#define NGX_CLEAR_EVENT    EV_CLEAR

#undef  NGX_DISABLE_EVENT
#define NGX_DISABLE_EVENT  EV_DISABLE


#elif (NGX_HAVE_DEVPOLL && !(NGX_TEST_BUILD_DEVPOLL)) \
      || (NGX_HAVE_EVENTPORT && !(NGX_TEST_BUILD_EVENTPORT))

#define NGX_READ_EVENT     POLLIN
#define NGX_WRITE_EVENT    POLLOUT

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  1


#elif (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)

#define NGX_READ_EVENT     (EPOLLIN|EPOLLRDHUP)
#define NGX_WRITE_EVENT    EPOLLOUT

#define NGX_LEVEL_EVENT    0
#define NGX_CLEAR_EVENT    EPOLLET
#define NGX_ONESHOT_EVENT  0x70000000
#if 0
#define NGX_ONESHOT_EVENT  EPOLLONESHOT
#endif

#if (NGX_HAVE_EPOLLEXCLUSIVE)
#define NGX_EXCLUSIVE_EVENT  EPOLLEXCLUSIVE
#endif

#elif (NGX_HAVE_POLL)

#define NGX_READ_EVENT     POLLIN
#define NGX_WRITE_EVENT    POLLOUT

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  1


#else /* select */

#define NGX_READ_EVENT     0
#define NGX_WRITE_EVENT    1

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  1

#endif /* NGX_HAVE_KQUEUE */


#if (NGX_HAVE_IOCP)
#define NGX_IOCP_ACCEPT      0
#define NGX_IOCP_IO          1
#define NGX_IOCP_CONNECT     2
#endif


#if (NGX_TEST_BUILD_EPOLL)
#define NGX_EXCLUSIVE_EVENT  0
#endif


#ifndef NGX_CLEAR_EVENT
#define NGX_CLEAR_EVENT    0    /* dummy declaration */
#endif


#define ngx_process_events   ngx_event_actions.process_events
#define ngx_done_events      ngx_event_actions.done

#define ngx_add_event        ngx_event_actions.add
#define ngx_del_event        ngx_event_actions.del
#define ngx_add_conn         ngx_event_actions.add_conn
#define ngx_del_conn         ngx_event_actions.del_conn

#define ngx_notify           ngx_event_actions.notify

#define ngx_add_timer        ngx_event_add_timer
#define ngx_del_timer        ngx_event_del_timer


extern ngx_os_io_t  ngx_io;

#define ngx_recv             ngx_io.recv
#define ngx_recv_chain       ngx_io.recv_chain
#define ngx_udp_recv         ngx_io.udp_recv
#define ngx_send             ngx_io.send
#define ngx_send_chain       ngx_io.send_chain
#define ngx_udp_send         ngx_io.udp_send
#define ngx_udp_send_chain   ngx_io.udp_send_chain


#define NGX_EVENT_MODULE      0x544E5645  /* "EVNT" */
#define NGX_EVENT_CONF        0x02000000


/**
 * event事件模块配置的结构对象
 */
typedef struct {
    ngx_uint_t    connections;         /* 连接池的大小 */
    ngx_uint_t    use;                 /* 事件模型的标识，用于选择使用哪种事件模型(select/poll/epoll等) */

    ngx_flag_t    multi_accept;        /* 标识是否一次接受多个新连接,为1时开启 */
    ngx_flag_t    accept_mutex;        /* 是否启用accept锁。当启用时,多个worker进程轮流接受新连接 */

    ngx_msec_t    accept_mutex_delay;  /* 当accept锁获取失败后,延迟重试的时间,单位为毫秒 */

    u_char       *name;                /* 所使用的事件模型的名称 */

#if (NGX_DEBUG)
    ngx_array_t   debug_connection;    /* 调试连接的IP地址数组,只在调试模式下生效 */
#endif
} ngx_event_conf_t;


typedef struct {
    ngx_str_t              *name;

    void                 *(*create_conf)(ngx_cycle_t *cycle);
    char                 *(*init_conf)(ngx_cycle_t *cycle, void *conf);

    ngx_event_actions_t     actions;
} ngx_event_module_t;


extern ngx_atomic_t          *ngx_connection_counter;

extern ngx_atomic_t          *ngx_accept_mutex_ptr;
extern ngx_shmtx_t            ngx_accept_mutex;
extern ngx_uint_t             ngx_use_accept_mutex;
extern ngx_uint_t             ngx_accept_events;
extern ngx_uint_t             ngx_accept_mutex_held;
extern ngx_msec_t             ngx_accept_mutex_delay;
extern ngx_int_t              ngx_accept_disabled;
extern ngx_uint_t             ngx_use_exclusive_accept;


#if (NGX_STAT_STUB)

extern ngx_atomic_t  *ngx_stat_accepted;
extern ngx_atomic_t  *ngx_stat_handled;
extern ngx_atomic_t  *ngx_stat_requests;
extern ngx_atomic_t  *ngx_stat_active;
extern ngx_atomic_t  *ngx_stat_reading;
extern ngx_atomic_t  *ngx_stat_writing;
extern ngx_atomic_t  *ngx_stat_waiting;

#endif


#define NGX_UPDATE_TIME         1
#define NGX_POST_EVENTS         2


extern sig_atomic_t           ngx_event_timer_alarm;
extern ngx_uint_t             ngx_event_flags;
extern ngx_module_t           ngx_events_module;
extern ngx_module_t           ngx_event_core_module;


#define ngx_event_get_conf(conf_ctx, module)                                  \
             (*(ngx_get_conf(conf_ctx, ngx_events_module))) [module.ctx_index]



/* 
 * 处理监听事件的函数，当监听的套接字上有新的连接到达时，
 * 该函数被调用以接收新的连接并进行相应的处理。
 */
void ngx_event_accept(ngx_event_t *ev);

/*
 * 尝试获取 accept 互斥锁的函数。
 * 该函数用于在多进程环境下防止惊群效应，
 * 即避免多个工作进程同时处理 accept 事件。 
 * 如果成功获取互斥锁，则允许当前进程接受新连接，
 * 否则会根据具体情况设置相应的延迟或禁用事件。
 */
ngx_int_t ngx_trylock_accept_mutex(ngx_cycle_t *cycle);

/*
 * 启用监听套接字上接收事件的函数。
 * 该函数遍历所有的监听套接字，并为尚未激活的读事件添加监听，
 * 确保系统能够及时捕获和处理新的连接请求。
 */
ngx_int_t ngx_enable_accept_events(ngx_cycle_t *cycle);

/*
 * accept 错误日志记录函数。
 * 当在处理 accept 操作时发生错误，该函数被调用，用于格式化错误信息，
 * 并将其写入日志缓冲区，以便进行后续的调试和错误分析。
 */
u_char *ngx_accept_log_error(ngx_log_t *log, u_char *buf, size_t len);
#if (NGX_DEBUG)
void ngx_debug_accepted_connection(ngx_event_conf_t *ecf, ngx_connection_t *c);
#endif


/**
 * @brief 处理事件和定时器的核心函数
 * 
 * 该函数是Nginx事件处理的核心，主要职责包括：
 * 1. 处理定时器事件
 * 2. 处理网络I/O事件
 * 3. 管理accept锁
 * 4. 处理post事件
 *
 * 工作流程：
 * 1. 获取最近的定时器超时时间
 * 2. 尝试获取accept锁(如果启用)
 * 3. 调用具体事件模型(epoll/select等)处理事件
 * 4. 释放accept锁(如果持有)
 * 5. 处理post事件队列
 * 
 * @param cycle Nginx核心配置结构体
 */
void ngx_process_events_and_timers(ngx_cycle_t *cycle);
ngx_int_t ngx_handle_read_event(ngx_event_t *rev, ngx_uint_t flags);
ngx_int_t ngx_handle_write_event(ngx_event_t *wev, size_t lowat);


#if (NGX_WIN32)
void ngx_event_acceptex(ngx_event_t *ev);
ngx_int_t ngx_event_post_acceptex(ngx_listening_t *ls, ngx_uint_t n);
u_char *ngx_acceptex_log_error(ngx_log_t *log, u_char *buf, size_t len);
#endif


ngx_int_t ngx_send_lowat(ngx_connection_t *c, size_t lowat);


/* used in ngx_log_debugX() */
#define ngx_event_ident(p)  ((ngx_connection_t *) (p))->fd


#include <ngx_event_timer.h>
#include <ngx_event_posted.h>
#include <ngx_event_udp.h>

#if (NGX_WIN32)
#include <ngx_iocp_module.h>
#endif


#endif /* _NGX_EVENT_H_INCLUDED_ */
