
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static ngx_int_t ngx_disable_accept_events(ngx_cycle_t *cycle, ngx_uint_t all);
#if (NGX_HAVE_EPOLLEXCLUSIVE)
static void ngx_reorder_accept_events(ngx_listening_t *ls);
#endif
static void ngx_close_accepted_connection(ngx_connection_t *c);


void
ngx_event_accept(ngx_event_t *ev)
{
    // 声明变量用于存储socket地址长度
    socklen_t          socklen;
    // 用于存储错误码
    ngx_err_t          err;
    // 日志对象指针
    ngx_log_t         *log;
    // 日志级别
    ngx_uint_t         level;
    // socket文件描述符
    ngx_socket_t       s;
    // 读写事件对象指针
    ngx_event_t       *rev, *wev;
    // socket地址结构体
    ngx_sockaddr_t     sa;
    // 监听对象指针
    ngx_listening_t   *ls;
    // 连接对象指针
    ngx_connection_t  *c, *lc;
    // 事件模块配置对象指针
    ngx_event_conf_t  *ecf;
#if (NGX_HAVE_ACCEPT4)
    // 是否使用accept4系统调用的标志
    static ngx_uint_t  use_accept4 = 1;
#endif

    // 如果事件超时,重新启用accept事件
    if (ev->timedout) {
        if (ngx_enable_accept_events((ngx_cycle_t *) ngx_cycle) != NGX_OK) {
            return;
        }

        ev->timedout = 0;
    }

    // 获取事件模块配置
    ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module);

    // 如果不是kqueue事件,设置一次可以接受的连接数
    if (!(ngx_event_flags & NGX_USE_KQUEUE_EVENT)) {
        ev->available = ecf->multi_accept;
    }

    // 获取监听连接对象
    lc = ev->data;
    ls = lc->listening;
    ev->ready = 0;

    // 记录调试日志
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "accept on %V, ready: %d", &ls->addr_text, ev->available);

    do {
        socklen = sizeof(ngx_sockaddr_t);

#if (NGX_HAVE_ACCEPT4)
        // 如果支持accept4系统调用则优先使用
        if (use_accept4) {
            s = accept4(lc->fd, &sa.sockaddr, &socklen, SOCK_NONBLOCK);
        } else {
            s = accept(lc->fd, &sa.sockaddr, &socklen);
        }
#else
        s = accept(lc->fd, &sa.sockaddr, &socklen);
#endif

        // 处理accept失败的情况
        if (s == (ngx_socket_t) -1) {
            err = ngx_socket_errno;

            if (err == NGX_EAGAIN) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, err,
                               "accept() not ready");
                return;
            }

            level = NGX_LOG_ALERT;

            if (err == NGX_ECONNABORTED) {
                level = NGX_LOG_ERR;

            } else if (err == NGX_EMFILE || err == NGX_ENFILE) {
                level = NGX_LOG_CRIT;
            }

#if (NGX_HAVE_ACCEPT4)
            ngx_log_error(level, ev->log, err,
                          use_accept4 ? "accept4() failed" : "accept() failed");

            if (use_accept4 && err == NGX_ENOSYS) {
                use_accept4 = 0;
                ngx_inherited_nonblocking = 0;
                continue;
            }
#else
            ngx_log_error(level, ev->log, err, "accept() failed");
#endif

            if (err == NGX_ECONNABORTED) {
                if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
                    ev->available--;
                }

                if (ev->available) {
                    continue;
                }
            }

            // 处理文件描述符用尽的情况
            if (err == NGX_EMFILE || err == NGX_ENFILE) {
                if (ngx_disable_accept_events((ngx_cycle_t *) ngx_cycle, 1)
                    != NGX_OK)
                {
                    return;
                }

                if (ngx_use_accept_mutex) {
                    if (ngx_accept_mutex_held) {
                        ngx_shmtx_unlock(&ngx_accept_mutex);
                        ngx_accept_mutex_held = 0;
                    }

                    ngx_accept_disabled = 1;

                } else {
                    ngx_add_timer(ev, ecf->accept_mutex_delay);
                }
            }

            return;
        }

#if (NGX_STAT_STUB)
        // 更新已接受连接数统计
        (void) ngx_atomic_fetch_add(ngx_stat_accepted, 1);
#endif

        // 计算是否需要限制accept的频率
        ngx_accept_disabled = ngx_cycle->connection_n / 8
                              - ngx_cycle->free_connection_n;

        // 获取新连接对象
        c = ngx_get_connection(s, ev->log);

        if (c == NULL) {
            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                              ngx_close_socket_n " failed");
            }

            return;
        }

        c->type = SOCK_STREAM;

#if (NGX_STAT_STUB)
        // 更新活动连接数统计
        (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

        // 为连接创建内存池
        c->pool = ngx_create_pool(ls->pool_size, ev->log);
        if (c->pool == NULL) {
            ngx_close_accepted_connection(c);
            return;
        }

        // 限制socket地址长度
        if (socklen > (socklen_t) sizeof(ngx_sockaddr_t)) {
            socklen = sizeof(ngx_sockaddr_t);
        }

        // 分配存储socket地址的内存
        c->sockaddr = ngx_palloc(c->pool, socklen);
        if (c->sockaddr == NULL) {
            ngx_close_accepted_connection(c);
            return;
        }

        // 复制socket地址
        ngx_memcpy(c->sockaddr, &sa, socklen);

        // 创建日志对象
        log = ngx_palloc(c->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            ngx_close_accepted_connection(c);
            return;
        }

        /* set a blocking mode for iocp and non-blocking mode for others */

        // 根据事件模型设置socket阻塞模式
        if (ngx_inherited_nonblocking) {
            // 如果事件模型是IOCP,则设置socket为阻塞模式
            if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
                if (ngx_blocking(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                  ngx_blocking_n " failed");
                    ngx_close_accepted_connection(c);
                    return;
                }
            }

        } else {
            // 如果事件模型不是IOCP,则设置socket为非阻塞模式
            if (!(ngx_event_flags & NGX_USE_IOCP_EVENT)) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                  ngx_nonblocking_n " failed");
                    ngx_close_accepted_connection(c);
                    return;
                }
            }
        }

        // 设置日志对象
        *log = ls->log;

        // 设置连接的收发函数
        c->recv = ngx_recv;
        c->send = ngx_send;
        c->recv_chain = ngx_recv_chain;
        c->send_chain = ngx_send_chain;

        // 关联日志对象
        c->log = log;
        c->pool->log = log;

        // 设置socket相关属性
        c->socklen = socklen;
        c->listening = ls;
        c->local_sockaddr = ls->sockaddr;
        c->local_socklen = ls->socklen;

#if (NGX_HAVE_UNIX_DOMAIN)
        // Unix域socket的特殊处理
        if (c->sockaddr->sa_family == AF_UNIX) {
            c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
            c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;
#if (NGX_SOLARIS)
            /* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
            c->sendfile = 0;
#endif
        }
#endif

        // 获取读写事件对象
        rev = c->read;
        wev = c->write;

        // 设置写事件为就绪状态
        wev->ready = 1;

        // IOCP模式下设置读事件为就绪状态
        if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
            rev->ready = 1;
        }

        // 延迟接受的处理
        if (ev->deferred_accept) {
            rev->ready = 1;
#if (NGX_HAVE_KQUEUE || NGX_HAVE_EPOLLRDHUP)
            rev->available = 1;
#endif
        }

        // 设置事件日志
        rev->log = log;
        wev->log = log;

        /*
         * TODO: MT: - ngx_atomic_fetch_add()
         *             or protection by critical section or light mutex
         *
         * TODO: MP: - allocated in a shared memory
         *           - ngx_atomic_fetch_add()
         *             or protection by critical section or light mutex
         */

        // 分配连接序号
        c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

        // 记录连接开始时间
        c->start_time = ngx_current_msec;

#if (NGX_STAT_STUB)
        // 更新已处理连接数统计
        (void) ngx_atomic_fetch_add(ngx_stat_handled, 1);
#endif

        // 处理地址文本表示
        if (ls->addr_ntop) {
            c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
            if (c->addr_text.data == NULL) {
                ngx_close_accepted_connection(c);
                return;
            }

            c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
                                             c->addr_text.data,
                                             ls->addr_text_max_len, 0);
            if (c->addr_text.len == 0) {
                ngx_close_accepted_connection(c);
                return;
            }
        }

#if (NGX_DEBUG)
        {
        ngx_str_t  addr;
        u_char     text[NGX_SOCKADDR_STRLEN];

        ngx_debug_accepted_connection(ecf, c);

        if (log->log_level & NGX_LOG_DEBUG_EVENT) {
            addr.data = text;
            addr.len = ngx_sock_ntop(c->sockaddr, c->socklen, text,
                                     NGX_SOCKADDR_STRLEN, 1);

            ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0,
                           "*%uA accept: %V fd:%d", c->number, &addr, s);
        }

        }
#endif

        // 添加连接到事件处理机制
        if (ngx_add_conn && (ngx_event_flags & NGX_USE_EPOLL_EVENT) == 0) {
            if (ngx_add_conn(c) == NGX_ERROR) {
                ngx_close_accepted_connection(c);
                return;
            }
        }

        // 清除日志处理器
        log->data = NULL;
        log->handler = NULL;

        // 调用监听端口的连接处理函数，初始化ngx_connection_t客户端连接
        ls->handler(c);

        // kqueue模式下更新可用连接数
        if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
            ev->available--;
        }

    } while (ev->available);

#if (NGX_HAVE_EPOLLEXCLUSIVE)
    // 重新排序accept事件
    ngx_reorder_accept_events(ls);
#endif
}


ngx_int_t
ngx_trylock_accept_mutex(ngx_cycle_t *cycle)
{
    // 尝试获取接受事件的共享互斥锁，确保多个进程不会同时处理新连接
    if (ngx_shmtx_trylock(&ngx_accept_mutex)) {

        // 成功获取锁后，记录调试日志，表明已成功锁定
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "accept mutex locked");

        // 如果当前已经标记为持有互斥锁且没有等待处理的接受事件，则直接返回成功
        if (ngx_accept_mutex_held && ngx_accept_events == 0) {
            return NGX_OK;
        }

        // 调用函数启用所有监听套接字的接收事件
        // 如果启用事件失败，则需要释放互斥锁并返回错误
        if (ngx_enable_accept_events(cycle) == NGX_ERROR) {
            ngx_shmtx_unlock(&ngx_accept_mutex);
            return NGX_ERROR;
        }

        // 重置等待接受事件的计数为0
        ngx_accept_events = 0;
        // 标记当前进程已持有接收互斥锁
        ngx_accept_mutex_held = 1;

        // 成功启用接受事件后返回成功状态
        return NGX_OK;
    }

    // 如果尝试获取互斥锁失败，则记录调试日志，日志中指出当前的互斥锁持有状态
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "accept mutex lock failed: %ui", ngx_accept_mutex_held);

    // 如果当前进程曾经持有互斥锁，则尝试禁用接受事件以保证状态同步
    if (ngx_accept_mutex_held) {
        // 禁用接受事件，如果出错则返回错误
        if (ngx_disable_accept_events(cycle, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }
        // 更新状态标记，表示当前不再持有互斥锁
        ngx_accept_mutex_held = 0;
    }

    // 最终以成功状态结束该函数
    return NGX_OK;
}


ngx_int_t
ngx_enable_accept_events(ngx_cycle_t *cycle)
{
    // 定义循环变量，用于遍历所有监听套接字
    ngx_uint_t         i;
    // 获取监听套接字数组指针
    ngx_listening_t   *ls;
    // 定义连接对象指针
    ngx_connection_t  *c;

    // 从cycle结构体中获取所有监听套接字的数组
    ls = cycle->listening.elts;

    // 遍历整个监听套接字数组
    for (i = 0; i < cycle->listening.nelts; i++) {

        // 从当前监听套接字中取得其对应的连接对象
        c = ls[i].connection;

        // 如果连接对象不存在，或者该连接的读事件已经处于激活状态，则跳过当前循环不做处理
        if (c == NULL || c->read->active) {
            continue;
        }

        // 为未激活的读事件添加监听
        // ngx_add_event函数用于将指定的事件添加到事件处理机制中
        // 这里使用NGX_READ_EVENT表示添加读取事件，第三个参数0代表使用默认的事件标志
        if (ngx_add_event(c->read, NGX_READ_EVENT, 0) == NGX_ERROR) {
            // 如果添加事件失败，立即返回错误码NGX_ERROR，以便上层能及时处理异常情况
            return NGX_ERROR;
        }
    }

    // 如果所有监听套接字的读事件均成功添加，则返回NGX_OK表示操作成功
    return NGX_OK;
}


static ngx_int_t
ngx_disable_accept_events(ngx_cycle_t *cycle, ngx_uint_t all)
{
    ngx_uint_t         i;
    ngx_listening_t   *ls;
    ngx_connection_t  *c;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ls[i].connection;

        if (c == NULL || !c->read->active) {
            continue;
        }

#if (NGX_HAVE_REUSEPORT)

        /*
         * do not disable accept on worker's own sockets
         * when disabling accept events due to accept mutex
         */

        if (ls[i].reuseport && !all) {
            continue;
        }

#endif

        if (ngx_del_event(c->read, NGX_READ_EVENT, NGX_DISABLE_EVENT)
            == NGX_ERROR)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


#if (NGX_HAVE_EPOLLEXCLUSIVE)

static void
ngx_reorder_accept_events(ngx_listening_t *ls)
{
    ngx_connection_t  *c;

    /*
     * Linux with EPOLLEXCLUSIVE usually notifies only the process which
     * was first to add the listening socket to the epoll instance.  As
     * a result most of the connections are handled by the first worker
     * process.  To fix this, we re-add the socket periodically, so other
     * workers will get a chance to accept connections.
     */

    if (!ngx_use_exclusive_accept) {
        return;
    }

#if (NGX_HAVE_REUSEPORT)

    if (ls->reuseport) {
        return;
    }

#endif

    c = ls->connection;

    if (c->requests++ % 16 != 0
        && ngx_accept_disabled <= 0)
    {
        return;
    }

    if (ngx_del_event(c->read, NGX_READ_EVENT, NGX_DISABLE_EVENT)
        == NGX_ERROR)
    {
        return;
    }

    if (ngx_add_event(c->read, NGX_READ_EVENT, NGX_EXCLUSIVE_EVENT)
        == NGX_ERROR)
    {
        return;
    }
}

#endif


static void
ngx_close_accepted_connection(ngx_connection_t *c)
{
    ngx_socket_t  fd;

    ngx_free_connection(c);

    fd = c->fd;
    c->fd = (ngx_socket_t) -1;

    if (ngx_close_socket(fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    if (c->pool) {
        ngx_destroy_pool(c->pool);
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif
}


u_char *
ngx_accept_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    return ngx_snprintf(buf, len, " while accepting new connection on %V",
                        log->data);
}


#if (NGX_DEBUG)

void
ngx_debug_accepted_connection(ngx_event_conf_t *ecf, ngx_connection_t *c)
{
    struct sockaddr_in   *sin;
    ngx_cidr_t           *cidr;
    ngx_uint_t            i;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
    ngx_uint_t            n;
#endif

    cidr = ecf->debug_connection.elts;
    for (i = 0; i < ecf->debug_connection.nelts; i++) {
        if (cidr[i].family != (ngx_uint_t) c->sockaddr->sa_family) {
            goto next;
        }

        switch (cidr[i].family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->sockaddr;
            for (n = 0; n < 16; n++) {
                if ((sin6->sin6_addr.s6_addr[n]
                    & cidr[i].u.in6.mask.s6_addr[n])
                    != cidr[i].u.in6.addr.s6_addr[n])
                {
                    goto next;
                }
            }
            break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->sockaddr;
            if ((sin->sin_addr.s_addr & cidr[i].u.in.mask)
                != cidr[i].u.in.addr)
            {
                goto next;
            }
            break;
        }

        c->log->log_level = NGX_LOG_DEBUG_CONNECTION|NGX_LOG_DEBUG_ALL;
        break;

    next:
        continue;
    }
}

#endif
