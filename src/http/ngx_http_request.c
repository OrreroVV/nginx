
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/**
 * 处理HTTP请求等待事件的回调函数
 * @param rev 事件对象
 */
static void ngx_http_wait_request_handler(ngx_event_t *ev);
static ngx_http_request_t *ngx_http_alloc_request(ngx_connection_t *c);
static void ngx_http_process_request_line(ngx_event_t *rev);
static void ngx_http_process_request_headers(ngx_event_t *rev);
static ssize_t ngx_http_read_request_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_alloc_large_header_buffer(ngx_http_request_t *r,
    ngx_uint_t request_line);

static ngx_int_t ngx_http_process_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_process_unique_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_process_host(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_process_connection(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_process_user_agent(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);

static ngx_int_t ngx_http_find_virtual_server(ngx_connection_t *c,
    ngx_http_virtual_names_t *virtual_names, ngx_str_t *host,
    ngx_http_request_t *r, ngx_http_core_srv_conf_t **cscfp);

static void ngx_http_request_handler(ngx_event_t *ev);
static void ngx_http_terminate_request(ngx_http_request_t *r, ngx_int_t rc);
static void ngx_http_terminate_handler(ngx_http_request_t *r);
static void ngx_http_finalize_connection(ngx_http_request_t *r);
static ngx_int_t ngx_http_set_write_handler(ngx_http_request_t *r);
static void ngx_http_writer(ngx_http_request_t *r);
static void ngx_http_request_finalizer(ngx_http_request_t *r);

static void ngx_http_set_keepalive(ngx_http_request_t *r);
static void ngx_http_keepalive_handler(ngx_event_t *ev);
static void ngx_http_set_lingering_close(ngx_connection_t *c);
static void ngx_http_lingering_close_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_post_action(ngx_http_request_t *r);
static void ngx_http_log_request(ngx_http_request_t *r);

static u_char *ngx_http_log_error(ngx_log_t *log, u_char *buf, size_t len);
static u_char *ngx_http_log_error_handler(ngx_http_request_t *r,
    ngx_http_request_t *sr, u_char *buf, size_t len);

#if (NGX_HTTP_SSL)
static void ngx_http_ssl_handshake(ngx_event_t *rev);
static void ngx_http_ssl_handshake_handler(ngx_connection_t *c);
#endif


static char *ngx_http_client_errors[] = {

    /* NGX_HTTP_PARSE_INVALID_METHOD */
    "client sent invalid method",

    /* NGX_HTTP_PARSE_INVALID_REQUEST */
    "client sent invalid request",

    /* NGX_HTTP_PARSE_INVALID_VERSION */
    "client sent invalid version",

    /* NGX_HTTP_PARSE_INVALID_09_METHOD */
    "client sent invalid method in HTTP/0.9 request"
};


ngx_http_header_t  ngx_http_headers_in[] = {
    { ngx_string("Host"), offsetof(ngx_http_headers_in_t, host),
                 ngx_http_process_host },

    { ngx_string("Connection"), offsetof(ngx_http_headers_in_t, connection),
                 ngx_http_process_connection },

    { ngx_string("If-Modified-Since"),
                 offsetof(ngx_http_headers_in_t, if_modified_since),
                 ngx_http_process_unique_header_line },

    { ngx_string("If-Unmodified-Since"),
                 offsetof(ngx_http_headers_in_t, if_unmodified_since),
                 ngx_http_process_unique_header_line },

    { ngx_string("If-Match"),
                 offsetof(ngx_http_headers_in_t, if_match),
                 ngx_http_process_unique_header_line },

    { ngx_string("If-None-Match"),
                 offsetof(ngx_http_headers_in_t, if_none_match),
                 ngx_http_process_unique_header_line },

    { ngx_string("User-Agent"), offsetof(ngx_http_headers_in_t, user_agent),
                 ngx_http_process_user_agent },

    { ngx_string("Referer"), offsetof(ngx_http_headers_in_t, referer),
                 ngx_http_process_header_line },

    { ngx_string("Content-Length"),
                 offsetof(ngx_http_headers_in_t, content_length),
                 ngx_http_process_unique_header_line },

    { ngx_string("Content-Range"),
                 offsetof(ngx_http_headers_in_t, content_range),
                 ngx_http_process_unique_header_line },

    { ngx_string("Content-Type"),
                 offsetof(ngx_http_headers_in_t, content_type),
                 ngx_http_process_header_line },

    { ngx_string("Range"), offsetof(ngx_http_headers_in_t, range),
                 ngx_http_process_header_line },

    { ngx_string("If-Range"),
                 offsetof(ngx_http_headers_in_t, if_range),
                 ngx_http_process_unique_header_line },

    { ngx_string("Transfer-Encoding"),
                 offsetof(ngx_http_headers_in_t, transfer_encoding),
                 ngx_http_process_unique_header_line },

    { ngx_string("TE"),
                 offsetof(ngx_http_headers_in_t, te),
                 ngx_http_process_header_line },

    { ngx_string("Expect"),
                 offsetof(ngx_http_headers_in_t, expect),
                 ngx_http_process_unique_header_line },

    { ngx_string("Upgrade"),
                 offsetof(ngx_http_headers_in_t, upgrade),
                 ngx_http_process_header_line },

#if (NGX_HTTP_GZIP || NGX_HTTP_HEADERS)
    { ngx_string("Accept-Encoding"),
                 offsetof(ngx_http_headers_in_t, accept_encoding),
                 ngx_http_process_header_line },

    { ngx_string("Via"), offsetof(ngx_http_headers_in_t, via),
                 ngx_http_process_header_line },
#endif

    { ngx_string("Authorization"),
                 offsetof(ngx_http_headers_in_t, authorization),
                 ngx_http_process_unique_header_line },

    { ngx_string("Keep-Alive"), offsetof(ngx_http_headers_in_t, keep_alive),
                 ngx_http_process_header_line },

#if (NGX_HTTP_X_FORWARDED_FOR)
    { ngx_string("X-Forwarded-For"),
                 offsetof(ngx_http_headers_in_t, x_forwarded_for),
                 ngx_http_process_header_line },
#endif

#if (NGX_HTTP_REALIP)
    { ngx_string("X-Real-IP"),
                 offsetof(ngx_http_headers_in_t, x_real_ip),
                 ngx_http_process_header_line },
#endif

#if (NGX_HTTP_HEADERS)
    { ngx_string("Accept"), offsetof(ngx_http_headers_in_t, accept),
                 ngx_http_process_header_line },

    { ngx_string("Accept-Language"),
                 offsetof(ngx_http_headers_in_t, accept_language),
                 ngx_http_process_header_line },
#endif

#if (NGX_HTTP_DAV)
    { ngx_string("Depth"), offsetof(ngx_http_headers_in_t, depth),
                 ngx_http_process_header_line },

    { ngx_string("Destination"), offsetof(ngx_http_headers_in_t, destination),
                 ngx_http_process_header_line },

    { ngx_string("Overwrite"), offsetof(ngx_http_headers_in_t, overwrite),
                 ngx_http_process_header_line },

    { ngx_string("Date"), offsetof(ngx_http_headers_in_t, date),
                 ngx_http_process_header_line },
#endif

    { ngx_string("Cookie"), offsetof(ngx_http_headers_in_t, cookie),
                 ngx_http_process_header_line },

    { ngx_null_string, 0, NULL }
};


void
ngx_http_init_connection(ngx_connection_t *c)
{
    ngx_uint_t                 i; // 定义循环变量i
    ngx_event_t               *rev; // 定义指向事件的指针
    struct sockaddr_in        *sin; // 定义指向IPv4地址结构的指针
    ngx_http_port_t           *port; // 定义指向HTTP端口结构的指针
    ngx_http_in_addr_t        *addr; // 定义指向HTTP地址结构的指针
    ngx_http_log_ctx_t        *ctx; // 定义指向HTTP日志上下文的指针
    ngx_http_connection_t     *hc; // 定义指向HTTP连接结构的指针
    ngx_http_core_srv_conf_t  *cscf; // 定义指向核心服务器配置的指针
#if (NGX_HAVE_INET6)
    struct sockaddr_in6       *sin6; // 定义指向IPv6地址结构的指针
    ngx_http_in6_addr_t       *addr6; // 定义指向HTTP IPv6地址结构的指针
#endif

    hc = ngx_pcalloc(c->pool, sizeof(ngx_http_connection_t)); // 为HTTP连接结构分配内存
    if (hc == NULL) {
        ngx_http_close_connection(c); // 内存分配失败，关闭连接
        return;
    }

    c->data = hc; // 将HTTP连接结构赋值给连接的数据字段

    /* find the server configuration for the address:port */
    /* 查找地址:端口的服务器配置 */

    port = c->listening->servers; // 获取监听的服务器端口

    if (port->naddrs > 1) { // 如果端口上有多个地址

        /*
         * there are several addresses on this port and one of them
         * is an "*:port" wildcard so getsockname() in ngx_http_server_addr()
         * is required to determine a server address
         */
        /*
         * 端口上有多个地址，其中一个是“*:port”通配符，
         * 因此需要在ngx_http_server_addr()中使用getsockname()来确定服务器地址
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_http_close_connection(c); // 获取本地套接字地址失败，关闭连接
            return;
        }

        switch (c->local_sockaddr->sa_family) { // 根据地址族选择处理方式

#if (NGX_HAVE_INET6)
        case AF_INET6: // 处理IPv6地址
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr; // 获取IPv6地址

            addr6 = port->addrs; // 获取IPv6地址数组

            /* the last address is "*" */
            /* 最后一个地址是“*” */

            for (i = 0; i < port->naddrs - 1; i++) { // 遍历地址数组
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break; // 找到匹配的地址
                }
            }

            hc->addr_conf = &addr6[i].conf; // 设置地址配置

            break;
#endif

        default: /* AF_INET */ // 处理IPv4地址
            sin = (struct sockaddr_in *) c->local_sockaddr; // 获取IPv4地址

            addr = port->addrs; // 获取IPv4地址数组

            /* the last address is "*" */
            /* 最后一个地址是“*” */

            for (i = 0; i < port->naddrs - 1; i++) { // 遍历地址数组
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break; // 找到匹配的地址
                }
            }

            hc->addr_conf = &addr[i].conf; // 设置地址配置

            break;
        }

    } else { // 如果端口上只有一个地址

        switch (c->local_sockaddr->sa_family) { // 根据地址族选择处理方式

#if (NGX_HAVE_INET6)
        case AF_INET6: // 处理IPv6地址
            addr6 = port->addrs; // 获取IPv6地址数组
            hc->addr_conf = &addr6[0].conf; // 设置地址配置
            break;
#endif

        default: /* AF_INET */ // 处理IPv4地址
            addr = port->addrs; // 获取IPv4地址数组
            hc->addr_conf = &addr[0].conf; // 设置地址配置
            break;
        }
    }

    /* the default server configuration for the address:port */
    /* 地址:端口的默认服务器配置 */
    hc->conf_ctx = hc->addr_conf->default_server->ctx; // 获取默认服务器的上下文配置

    ctx = ngx_palloc(c->pool, sizeof(ngx_http_log_ctx_t)); // 为日志上下文分配内存
    if (ctx == NULL) {
        ngx_http_close_connection(c); // 内存分配失败，关闭连接
        return;
    }

    ctx->connection = c; // 设置日志上下文的连接
    ctx->request = NULL; // 初始化请求为NULL
    ctx->current_request = NULL; // 初始化当前请求为NULL

    c->log->connection = c->number; // 设置日志的连接编号
    c->log->handler = ngx_http_log_error; // 设置日志处理函数
    c->log->data = ctx; // 设置日志的数据为上下文
    c->log->action = "waiting for request"; // 设置日志的动作描述

    c->log_error = NGX_ERROR_INFO; // 设置日志错误级别

    rev = c->read; // 获取读事件
    rev->handler = ngx_http_wait_request_handler; // 设置读事件的处理函数
    c->write->handler = ngx_http_empty_handler; // 设置写事件的处理函数为空

#if (NGX_HTTP_V3)
    if (hc->addr_conf->quic) { // 如果支持QUIC协议
        ngx_http_v3_init_stream(c); // 初始化HTTP/3流
        return;
    }
#endif

#if (NGX_HTTP_SSL)
    if (hc->addr_conf->ssl) { // 如果支持SSL
        hc->ssl = 1; // 设置SSL标志
        c->log->action = "SSL handshaking"; // 设置日志的动作描述为SSL握手
        rev->handler = ngx_http_ssl_handshake; // 设置读事件的处理函数为SSL握手
    }
#endif

    if (hc->addr_conf->proxy_protocol) { // 如果支持代理协议
        hc->proxy_protocol = 1; // 设置代理协议标志
        c->log->action = "reading PROXY protocol"; // 设置日志的动作描述为读取代理协议
    }

    if (rev->ready) { // 如果读事件已准备好
        /* the deferred accept(), iocp */
        /* 延迟接受，IOCP */

        if (ngx_use_accept_mutex) { // 如果使用接受互斥锁
            ngx_post_event(rev, &ngx_posted_events); // 将事件加入已发布事件队列
            return;
        }

        rev->handler(rev); // 调用读事件的处理函数
        return;
    }

    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module); // 获取核心服务器配置

    ngx_add_timer(rev, cscf->client_header_timeout); // 添加客户端头超时定时器
    ngx_reusable_connection(c, 1); // 设置连接为可重用

    if (ngx_handle_read_event(rev, 0) != NGX_OK) { // 处理读事件
        ngx_http_close_connection(c); // 处理失败，关闭连接
        return;
    }
}


static void
ngx_http_wait_request_handler(ngx_event_t *rev)
{
    u_char                    *p; // 指向缓冲区位置的指针
    size_t                     size; // 缓冲区大小
    ssize_t                    n; // 接收数据的字节数
    ngx_buf_t                 *b; // 缓冲区指针
    ngx_connection_t          *c; // 连接对象
    ngx_http_connection_t     *hc; // HTTP连接对象
#if (NGX_HTTP_V2)
    ngx_http_v2_srv_conf_t    *h2scf; // HTTP/2服务器配置
#endif
    ngx_http_core_srv_conf_t  *cscf; // 核心服务器配置

    c = rev->data; // 从事件中获取连接对象

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http wait request handler"); // 记录调试日志

    if (rev->timedout) { // 检查事件是否超时
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out"); // 记录超时错误日志
        ngx_http_close_connection(c); // 关闭连接
        return;
    }

    if (c->close) { // 检查连接是否需要关闭
        ngx_http_close_connection(c); // 关闭连接
        return;
    }

    hc = c->data; // 获取HTTP连接对象
    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module); // 获取核心服务器配置

    size = cscf->client_header_buffer_size; // 获取客户端头缓冲区大小

    b = c->buffer; // 获取连接的缓冲区

    if (b == NULL) { // 如果缓冲区为空
        b = ngx_create_temp_buf(c->pool, size); // 创建临时缓冲区
        if (b == NULL) { // 检查缓冲区创建是否成功
            ngx_http_close_connection(c); // 关闭连接
            return;
        }

        c->buffer = b; // 设置连接的缓冲区

    } else if (b->start == NULL) { // 如果缓冲区的起始位置为空

        b->start = ngx_palloc(c->pool, size); // 分配缓冲区内存
        if (b->start == NULL) { // 检查内存分配是否成功
            ngx_http_close_connection(c); // 关闭连接
            return;
        }

        b->pos = b->start; // 初始化缓冲区位置
        b->last = b->start; // 初始化缓冲区末尾
        b->end = b->last + size; // 设置缓冲区结束位置
    }

    size = b->end - b->last; // 计算可用缓冲区大小

    n = c->recv(c, b->last, size); // 接收数据到缓冲区

    if (n == NGX_AGAIN) { // 如返回again，需要重新注册到事件队列中

        if (!rev->timer_set) { // 如果定时器未设置
            ngx_add_timer(rev, cscf->client_header_timeout); // 添加客户端头超时定时器
            ngx_reusable_connection(c, 1); // 设置连接为可重用
        }

        if (ngx_handle_read_event(rev, 0) != NGX_OK) { // 添加读事件到事件队列中
            ngx_http_close_connection(c); // 处理失败，关闭连接
            return;
        }

        if (b->pos == b->last) { // 如果缓冲区为空

            /*
             * 我们尝试不为空闲连接保留c->buffer的内存。
             */

            if (ngx_pfree(c->pool, b->start) == NGX_OK) { // 释放缓冲区内存
                b->start = NULL; // 设置缓冲区起始位置为空
            }
        }

        return;
    }

    if (n == NGX_ERROR) { // 如果接收数据出错
        ngx_http_close_connection(c); // 关闭连接
        return;
    }

    if (n == 0) { // 如果客户端关闭连接
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client closed connection"); // 记录客户端关闭连接日志
        ngx_http_close_connection(c); // 关闭连接
        return;
    }

    b->last += n; // 更新缓冲区末尾位置

    if (hc->proxy_protocol) { // 如果使用代理协议
        hc->proxy_protocol = 0; // 重置代理协议标志

        p = ngx_proxy_protocol_read(c, b->pos, b->last); // 读取代理协议

        if (p == NULL) { // 如果读取失败
            ngx_http_close_connection(c); // 关闭连接
            return;
        }

        b->pos = p; // 更新缓冲区位置

        if (b->pos == b->last) { // 如果缓冲区为空
            c->log->action = "waiting for request"; // 设置日志动作为等待请求
            b->pos = b->start; // 重置缓冲区位置
            b->last = b->start; // 重置缓冲区末尾
            ngx_post_event(rev, &ngx_posted_events); // 将事件加入已发布事件队列
            return;
        }
    }

#if (NGX_HTTP_V2)

    h2scf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_v2_module); // 获取HTTP/2服务器配置

    if (!hc->ssl && (h2scf->enable || hc->addr_conf->http2)) { // 如果未使用SSL且启用HTTP/2

        size = ngx_min(sizeof(NGX_HTTP_V2_PREFACE) - 1,
                       (size_t) (b->last - b->pos)); // 计算HTTP/2前言的大小

        if (ngx_memcmp(b->pos, NGX_HTTP_V2_PREFACE, size) == 0) { // 比较缓冲区内容与HTTP/2前言

            if (size == sizeof(NGX_HTTP_V2_PREFACE) - 1) { // 如果匹配完整的HTTP/2前言
                ngx_http_v2_init(rev); // 初始化HTTP/2
                return;
            }

            ngx_post_event(rev, &ngx_posted_events); // 将事件加入已发布事件队列
            return;
        }
    }

#endif

    c->log->action = "reading client request line"; // 设置日志动作为读取客户端请求行

    ngx_reusable_connection(c, 0); // 设置连接为不可重用

    c->data = ngx_http_create_request(c); // 创建HTTP请求
    if (c->data == NULL) { // 如果创建失败
        ngx_http_close_connection(c); // 关闭连接
        return;
    }

    rev->handler = ngx_http_process_request_line; // 设置事件处理函数为处理请求行
    ngx_http_process_request_line(rev); // 先尝试处理请求行
}


ngx_http_request_t *
ngx_http_create_request(ngx_connection_t *c)
{
    ngx_http_request_t        *r;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_core_loc_conf_t  *clcf;

    r = ngx_http_alloc_request(c);
    if (r == NULL) {
        return NULL;
    }

    c->requests++;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_set_connection_log(c, clcf->error_log);

    ctx = c->log->data;
    ctx->request = r;
    ctx->current_request = r;

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, 1);
    r->stat_reading = 1;
    (void) ngx_atomic_fetch_add(ngx_stat_requests, 1);
#endif

    return r;
}


static ngx_http_request_t *
ngx_http_alloc_request(ngx_connection_t *c)
{
    ngx_pool_t                 *pool;
    ngx_time_t                 *tp;
    ngx_http_request_t         *r;
    ngx_http_connection_t      *hc;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_main_conf_t  *cmcf;

    hc = c->data;

    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);

    pool = ngx_create_pool(cscf->request_pool_size, c->log);
    if (pool == NULL) {
        return NULL;
    }

    r = ngx_pcalloc(pool, sizeof(ngx_http_request_t));
    if (r == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    r->pool = pool;

    r->http_connection = hc;
    r->signature = NGX_HTTP_MODULE;
    r->connection = c;

    r->main_conf = hc->conf_ctx->main_conf;
    r->srv_conf = hc->conf_ctx->srv_conf;
    r->loc_conf = hc->conf_ctx->loc_conf;

    r->read_event_handler = ngx_http_block_reading;

    r->header_in = hc->busy ? hc->busy->buf : c->buffer;

    if (ngx_list_init(&r->headers_out.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_destroy_pool(r->pool);
        return NULL;
    }

    if (ngx_list_init(&r->headers_out.trailers, r->pool, 4,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_destroy_pool(r->pool);
        return NULL;
    }

    r->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (r->ctx == NULL) {
        ngx_destroy_pool(r->pool);
        return NULL;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    r->variables = ngx_pcalloc(r->pool, cmcf->variables.nelts
                                        * sizeof(ngx_http_variable_value_t));
    if (r->variables == NULL) {
        ngx_destroy_pool(r->pool);
        return NULL;
    }

#if (NGX_HTTP_SSL)
    if (c->ssl && !c->ssl->sendfile) {
        r->main_filter_need_in_memory = 1;
    }
#endif

    r->main = r;
    r->count = 1;

    tp = ngx_timeofday();
    r->start_sec = tp->sec;
    r->start_msec = tp->msec;

    r->method = NGX_HTTP_UNKNOWN;
    r->http_version = NGX_HTTP_VERSION_10;

    r->headers_in.content_length_n = -1;
    r->headers_in.keep_alive_n = -1;
    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;

    r->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1;
    r->subrequests = NGX_HTTP_MAX_SUBREQUESTS + 1;

    r->http_state = NGX_HTTP_READING_REQUEST_STATE;

    r->log_handler = ngx_http_log_error_handler;

    return r;
}


#if (NGX_HTTP_SSL)

static void
ngx_http_ssl_handshake(ngx_event_t *rev)
{
    u_char                    *p, buf[NGX_PROXY_PROTOCOL_MAX_HEADER + 1];
    size_t                     size;
    ssize_t                    n;
    ngx_err_t                  err;
    ngx_int_t                  rc;
    ngx_connection_t          *c;
    ngx_http_connection_t     *hc;
    ngx_http_ssl_srv_conf_t   *sscf;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    c = rev->data;
    hc = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http check ssl handshake");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_http_close_connection(c);
        return;
    }

    if (c->close) {
        ngx_http_close_connection(c);
        return;
    }

    size = hc->proxy_protocol ? sizeof(buf) : 1;

    n = recv(c->fd, (char *) buf, size, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http recv(): %z", n);

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            rev->ready = 0;

            if (!rev->timer_set) {
                cscf = ngx_http_get_module_srv_conf(hc->conf_ctx,
                                                    ngx_http_core_module);
                ngx_add_timer(rev, cscf->client_header_timeout);
                ngx_reusable_connection(c, 1);
            }

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_close_connection(c);
            }

            return;
        }

        ngx_connection_error(c, err, "recv() failed");
        ngx_http_close_connection(c);

        return;
    }

    if (hc->proxy_protocol) {
        hc->proxy_protocol = 0;

        p = ngx_proxy_protocol_read(c, buf, buf + n);

        if (p == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        size = p - buf;

        if (c->recv(c, buf, size) != (ssize_t) size) {
            ngx_http_close_connection(c);
            return;
        }

        c->log->action = "SSL handshaking";

        if (n == (ssize_t) size) {
            ngx_post_event(rev, &ngx_posted_events);
            return;
        }

        n = 1;
        buf[0] = *p;
    }

    if (n == 1) {
        if (buf[0] & 0x80 /* SSLv2 */ || buf[0] == 0x16 /* SSLv3/TLSv1 */) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                           "https ssl handshake: 0x%02Xd", buf[0]);

            clcf = ngx_http_get_module_loc_conf(hc->conf_ctx,
                                                ngx_http_core_module);

            if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
                ngx_http_close_connection(c);
                return;
            }

            sscf = ngx_http_get_module_srv_conf(hc->conf_ctx,
                                                ngx_http_ssl_module);

            if (ngx_ssl_create_connection(&sscf->ssl, c, NGX_SSL_BUFFER)
                != NGX_OK)
            {
                ngx_http_close_connection(c);
                return;
            }

            ngx_reusable_connection(c, 0);

            rc = ngx_ssl_handshake(c);

            if (rc == NGX_AGAIN) {

                if (!rev->timer_set) {
                    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx,
                                                        ngx_http_core_module);
                    ngx_add_timer(rev, cscf->client_header_timeout);
                }

                c->ssl->handler = ngx_http_ssl_handshake_handler;
                return;
            }

            ngx_http_ssl_handshake_handler(c);

            return;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "plain http");

        c->log->action = "waiting for request";

        rev->handler = ngx_http_wait_request_handler;
        ngx_http_wait_request_handler(rev);

        return;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "client closed connection");
    ngx_http_close_connection(c);
}


static void
ngx_http_ssl_handshake_handler(ngx_connection_t *c)
{
    if (c->ssl->handshaked) {

        /*
         * The majority of browsers do not send the "close notify" alert.
         * Among them are MSIE, old Mozilla, Netscape 4, Konqueror,
         * and Links.  And what is more, MSIE ignores the server's alert.
         *
         * Opera and recent Mozilla send the alert.
         */

        c->ssl->no_wait_shutdown = 1;

#if (NGX_HTTP_V2                                                              \
     && defined TLSEXT_TYPE_application_layer_protocol_negotiation)
        {
        unsigned int             len;
        const unsigned char     *data;
        ngx_http_connection_t   *hc;
        ngx_http_v2_srv_conf_t  *h2scf;

        hc = c->data;

        h2scf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_v2_module);

        if (h2scf->enable || hc->addr_conf->http2) {

            SSL_get0_alpn_selected(c->ssl->connection, &data, &len);

            if (len == 2 && data[0] == 'h' && data[1] == '2') {
                ngx_http_v2_init(c->read);
                return;
            }
        }
        }
#endif

        c->log->action = "waiting for request";

        c->read->handler = ngx_http_wait_request_handler;
        /* STUB: epoll edge */ c->write->handler = ngx_http_empty_handler;

        ngx_reusable_connection(c, 1);

        ngx_http_wait_request_handler(c->read);

        return;
    }

    if (c->read->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
    }

    ngx_http_close_connection(c);
}


#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

int
ngx_http_ssl_servername(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg)
{
    ngx_int_t                  rc;
    ngx_str_t                  host;
    const char                *servername;
    ngx_connection_t          *c;
    ngx_http_connection_t     *hc;
    ngx_http_ssl_srv_conf_t   *sscf;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    c = ngx_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        *ad = SSL_AD_NO_RENEGOTIATION;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    hc = c->data;

    servername = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);

    if (servername == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "SSL server name: null");
        goto done;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "SSL server name: \"%s\"", servername);

    host.len = ngx_strlen(servername);

    if (host.len == 0) {
        goto done;
    }

    host.data = (u_char *) servername;

    rc = ngx_http_validate_host(&host, c->pool, 1);

    if (rc == NGX_ERROR) {
        goto error;
    }

    if (rc == NGX_DECLINED) {
        goto done;
    }

    rc = ngx_http_find_virtual_server(c, hc->addr_conf->virtual_names, &host,
                                      NULL, &cscf);

    if (rc == NGX_ERROR) {
        goto error;
    }

    if (rc == NGX_DECLINED) {
        goto done;
    }

    hc->ssl_servername = ngx_palloc(c->pool, sizeof(ngx_str_t));
    if (hc->ssl_servername == NULL) {
        goto error;
    }

    *hc->ssl_servername = host;

    hc->conf_ctx = cscf->ctx;

    clcf = ngx_http_get_module_loc_conf(hc->conf_ctx, ngx_http_core_module);

    ngx_set_connection_log(c, clcf->error_log);

    sscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_ssl_module);

    c->ssl->buffer_size = sscf->buffer_size;

    if (sscf->ssl.ctx) {
        if (SSL_set_SSL_CTX(ssl_conn, sscf->ssl.ctx) == NULL) {
            goto error;
        }

        /*
         * SSL_set_SSL_CTX() only changes certs as of 1.0.0d
         * adjust other things we care about
         */

        SSL_set_verify(ssl_conn, SSL_CTX_get_verify_mode(sscf->ssl.ctx),
                       SSL_CTX_get_verify_callback(sscf->ssl.ctx));

        SSL_set_verify_depth(ssl_conn, SSL_CTX_get_verify_depth(sscf->ssl.ctx));

#if OPENSSL_VERSION_NUMBER >= 0x009080dfL
        /* only in 0.9.8m+ */
        SSL_clear_options(ssl_conn, SSL_get_options(ssl_conn) &
                                    ~SSL_CTX_get_options(sscf->ssl.ctx));
#endif

        SSL_set_options(ssl_conn, SSL_CTX_get_options(sscf->ssl.ctx));

#ifdef SSL_OP_NO_RENEGOTIATION
        SSL_set_options(ssl_conn, SSL_OP_NO_RENEGOTIATION);
#endif

#ifdef SSL_OP_ENABLE_MIDDLEBOX_COMPAT
#if (NGX_HTTP_V3)
        if (c->listening->quic) {
            SSL_clear_options(ssl_conn, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
        }
#endif
#endif
    }

done:

    sscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_ssl_module);

    if (sscf->reject_handshake) {
        c->ssl->handshake_rejected = 1;
        *ad = SSL_AD_UNRECOGNIZED_NAME;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    return SSL_TLSEXT_ERR_OK;

error:

    *ad = SSL_AD_INTERNAL_ERROR;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

#endif


#ifdef SSL_R_CERT_CB_ERROR

int
ngx_http_ssl_certificate(ngx_ssl_conn_t *ssl_conn, void *arg)
{
    ngx_str_t                  cert, key;
    ngx_uint_t                 i, nelts;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_ssl_srv_conf_t   *sscf;
    ngx_http_complex_value_t  *certs, *keys;

    c = ngx_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        return 0;
    }

    r = ngx_http_alloc_request(c);
    if (r == NULL) {
        return 0;
    }

    r->logged = 1;

    sscf = arg;

    nelts = sscf->certificate_values->nelts;
    certs = sscf->certificate_values->elts;
    keys = sscf->certificate_key_values->elts;

    for (i = 0; i < nelts; i++) {

        if (ngx_http_complex_value(r, &certs[i], &cert) != NGX_OK) {
            goto failed;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "ssl cert: \"%s\"", cert.data);

        if (ngx_http_complex_value(r, &keys[i], &key) != NGX_OK) {
            goto failed;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "ssl key: \"%s\"", key.data);

        if (ngx_ssl_connection_certificate(c, r->pool, &cert, &key,
                                           sscf->passwords)
            != NGX_OK)
        {
            goto failed;
        }
    }

    ngx_http_free_request(r, 0);
    c->log->action = "SSL handshaking";
    c->destroyed = 0;
    return 1;

failed:

    ngx_http_free_request(r, 0);
    c->log->action = "SSL handshaking";
    c->destroyed = 0;
    return 0;
}

#endif

#endif


static void
ngx_http_process_request_line(ngx_event_t *rev)
{
    ssize_t              n; // 读取的字节数
    ngx_int_t            rc, rv; // 返回码
    ngx_str_t            host; // 主机名
    ngx_connection_t    *c; // 连接对象
    ngx_http_request_t  *r; // HTTP请求对象

    c = rev->data; // 从事件中获取连接对象
    r = c->data; // 从连接中获取请求对象

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request line"); // 记录调试日志

    if (rev->timedout) { // 检查事件是否超时
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out"); // 记录超时错误日志
        c->timedout = 1; // 设置连接超时标志
        ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT); // 关闭请求
        return;
    }

    rc = NGX_AGAIN; // 初始化返回码为NGX_AGAIN

    for ( ;; ) { // 无限循环

        if (rc == NGX_AGAIN) { // 如果返回码为NGX_AGAIN
            n = ngx_http_read_request_header(r); // 读取请求头

            if (n == NGX_AGAIN || n == NGX_ERROR) { // 如果读取结果为NGX_AGAIN或NGX_ERROR
                break; // 跳出循环，ngx_http_read_request_header中已经把AGAIN情况处理了
            }
        }

        rc = ngx_http_parse_request_line(r, r->header_in); // 解析请求行

        if (rc == NGX_OK) { // 如果解析成功

            /* the request line has been parsed successfully */
            /* 请求行已成功解析 */

            r->request_line.len = r->request_end - r->request_start; // 计算请求行长度
            r->request_line.data = r->request_start; // 设置请求行数据
            r->request_length = r->header_in->pos - r->request_start; // 计算请求长度

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http request line: \"%V\"", &r->request_line); // 记录请求行调试日志

            r->method_name.len = r->method_end - r->request_start + 1; // 计算方法名长度
            r->method_name.data = r->request_line.data; // 设置方法名数据

            if (r->http_protocol.data) { // 如果HTTP协议数据存在
                r->http_protocol.len = r->request_end - r->http_protocol.data; // 计算HTTP协议长度
            }

            if (ngx_http_process_request_uri(r) != NGX_OK) { // 处理请求URI
                break; // 如果失败，跳出循环
            }

            if (r->schema_end) { // 如果schema结束位置存在
                r->schema.len = r->schema_end - r->schema_start; // 计算schema长度
                r->schema.data = r->schema_start; // 设置schema数据
            }

            if (r->host_end) { // 如果host结束位置存在

                host.len = r->host_end - r->host_start; // 计算host长度
                host.data = r->host_start; // 设置host数据

                rc = ngx_http_validate_host(&host, r->pool, 0); // 验证host

                if (rc == NGX_DECLINED) { // 如果验证被拒绝
                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                  "client sent invalid host in request line"); // 记录无效host错误日志
                    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST); // 终止请求
                    break; // 跳出循环
                }

                if (rc == NGX_ERROR) { // 如果验证出错
                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR); // 关闭请求
                    break; // 跳出循环
                }

                if (ngx_http_set_virtual_server(r, &host) == NGX_ERROR) { // 设置虚拟服务器
                    break; // 如果失败，跳出循环
                }

                r->headers_in.server = host; // 设置请求头中的服务器
            }

            if (r->http_version < NGX_HTTP_VERSION_10) { // 如果HTTP版本小于1.0

                if (r->headers_in.server.len == 0
                    && ngx_http_set_virtual_server(r, &r->headers_in.server)
                       == NGX_ERROR)
                {
                    break; // 如果设置虚拟服务器失败，跳出循环
                }

                ngx_http_process_request(r); // 处理请求
                break; // 跳出循环
            }


            if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
                              sizeof(ngx_table_elt_t))
                != NGX_OK)
            {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR); // 初始化请求头列表失败，关闭请求
                break; // 跳出循环
            }

            c->log->action = "reading client request headers"; // 设置日志动作为读取客户端请求头

            rev->handler = ngx_http_process_request_headers; // 设置事件处理函数为处理请求头
            ngx_http_process_request_headers(rev); // 处理请求头

            break; // 跳出循环
        }

        if (rc != NGX_AGAIN) { // 如果返回码不是NGX_AGAIN

            /* there was error while a request line parsing */
            /* 请求行解析时出错 */

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          ngx_http_client_errors[rc - NGX_HTTP_CLIENT_ERROR]); // 记录客户端错误日志

            if (rc == NGX_HTTP_PARSE_INVALID_VERSION) { // 如果版本无效
                ngx_http_finalize_request(r, NGX_HTTP_VERSION_NOT_SUPPORTED); // 终止请求

            } else {
                ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST); // 终止请求
            }

            break; // 跳出循环
        }

        /* NGX_AGAIN: a request line parsing is still incomplete */
        /* NGX_AGAIN: 请求行解析仍不完整 */

        if (r->header_in->pos == r->header_in->end) { // 如果请求头已满

            rv = ngx_http_alloc_large_header_buffer(r, 1); // 分配大请求头缓冲区

            if (rv == NGX_ERROR) { // 如果分配出错
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR); // 关闭请求
                break; // 跳出循环
            }

            if (rv == NGX_DECLINED) { // 如果分配被拒绝
                r->request_line.len = r->header_in->end - r->request_start; // 计算请求行长度
                r->request_line.data = r->request_start; // 设置请求行数据

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent too long URI"); // 记录URI过长错误日志
                ngx_http_finalize_request(r, NGX_HTTP_REQUEST_URI_TOO_LARGE); // 终止请求
                break; // 跳出循环
            }
        }
    }

    ngx_http_run_posted_requests(c); // 运行已发布的请求
}


ngx_int_t
ngx_http_process_request_uri(ngx_http_request_t *r)
{
    ngx_http_core_srv_conf_t  *cscf;

    if (r->args_start) {
        r->uri.len = r->args_start - 1 - r->uri_start;
    } else {
        r->uri.len = r->uri_end - r->uri_start;
    }

    if (r->complex_uri || r->quoted_uri || r->empty_path_in_uri) {

        if (r->empty_path_in_uri) {
            r->uri.len++;
        }

        r->uri.data = ngx_pnalloc(r->pool, r->uri.len);
        if (r->uri.data == NULL) {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        if (ngx_http_parse_complex_uri(r, cscf->merge_slashes) != NGX_OK) {
            r->uri.len = 0;

            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid request");
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return NGX_ERROR;
        }

    } else {
        r->uri.data = r->uri_start;
    }

    r->unparsed_uri.len = r->uri_end - r->uri_start;
    r->unparsed_uri.data = r->uri_start;

    r->valid_unparsed_uri = r->empty_path_in_uri ? 0 : 1;

    if (r->uri_ext) {
        if (r->args_start) {
            r->exten.len = r->args_start - 1 - r->uri_ext;
        } else {
            r->exten.len = r->uri_end - r->uri_ext;
        }

        r->exten.data = r->uri_ext;
    }

    if (r->args_start && r->uri_end > r->args_start) {
        r->args.len = r->uri_end - r->args_start;
        r->args.data = r->args_start;
    }

#if (NGX_WIN32)
    {
    u_char  *p, *last;

    p = r->uri.data;
    last = r->uri.data + r->uri.len;

    while (p < last) {

        if (*p++ == ':') {

            /*
             * this check covers "::$data", "::$index_allocation" and
             * ":$i30:$index_allocation"
             */

            if (p < last && *p == '$') {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "client sent unsafe win32 URI");
                ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                return NGX_ERROR;
            }
        }
    }

    p = r->uri.data + r->uri.len - 1;

    while (p > r->uri.data) {

        if (*p == ' ') {
            p--;
            continue;
        }

        if (*p == '.') {
            p--;
            continue;
        }

        break;
    }

    if (p != r->uri.data + r->uri.len - 1) {
        r->uri.len = p + 1 - r->uri.data;
        ngx_http_set_exten(r);
    }

    }
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http uri: \"%V\"", &r->uri);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http args: \"%V\"", &r->args);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http exten: \"%V\"", &r->exten);

    return NGX_OK;
}


static void
ngx_http_process_request_headers(ngx_event_t *rev)
{
    u_char                     *p;  // 指向当前处理的头部名称的指针
    size_t                      len;  // 当前头部名称的长度
    ssize_t                     n;  // 读取的字节数
    ngx_int_t                   rc, rv;  // 返回码
    ngx_table_elt_t            *h;  // 指向头部元素的指针
    ngx_connection_t           *c;  // 当前连接
    ngx_http_header_t          *hh;  // 指向HTTP头部的指针
    ngx_http_request_t         *r;  // 当前请求
    ngx_http_core_srv_conf_t   *cscf;  // 服务器配置
    ngx_http_core_main_conf_t  *cmcf;  // 主配置

    c = rev->data;  // 从事件中获取连接
    r = c->data;  // 从连接中获取请求

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request header line");  // 记录调试日志

    if (rev->timedout) {  // 检查事件是否超时
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");  // 记录超时错误
        c->timedout = 1;  // 标记连接超时
        ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);  // 关闭请求
        return;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);  // 获取主配置

    rc = NGX_AGAIN;  // 初始化返回码

    for ( ;; ) {  // 无限循环处理头部

        if (rc == NGX_AGAIN) {  // 如果需要再次尝试

            if (r->header_in->pos == r->header_in->end) {  // 检查缓冲区是否已满

                rv = ngx_http_alloc_large_header_buffer(r, 0);  // 分配更大的缓冲区

                if (rv == NGX_ERROR) {  // 如果分配失败
                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);  // 关闭请求
                    break;
                }

                if (rv == NGX_DECLINED) {  // 如果分配被拒绝
                    p = r->header_name_start;  // 获取头部名称的起始位置

                    r->lingering_close = 1;  // 标记需要延迟关闭

                    if (p == NULL) {  // 如果头部名称为空
                        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                      "client sent too large request");  // 记录错误
                        ngx_http_finalize_request(r,
                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);  // 完成请求
                        break;
                    }

                    len = r->header_in->end - p;  // 计算头部名称的长度

                    if (len > NGX_MAX_ERROR_STR - 300) {  // 检查长度是否超过限制
                        len = NGX_MAX_ERROR_STR - 300;  // 限制长度
                    }

                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                "client sent too long header line: \"%*s...\"",
                                len, r->header_name_start);  // 记录错误

                    ngx_http_finalize_request(r,
                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);  // 完成请求
                    break;
                }
            }

            n = ngx_http_read_request_header(r);  // 读取请求头

            if (n == NGX_AGAIN || n == NGX_ERROR) {  // 如果需要再次尝试或出错
                break;
            }
        }

        /* the host header could change the server configuration context */
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);  // 获取服务器配置

        rc = ngx_http_parse_header_line(r, r->header_in,
                                        cscf->underscores_in_headers);  // 解析头部行

        if (rc == NGX_OK) {  // 如果解析成功

            r->request_length += r->header_in->pos - r->header_name_start;  // 更新请求长度

            if (r->invalid_header && cscf->ignore_invalid_headers) {  // 如果头部无效且配置忽略无效头部

                /* there was error while a header line parsing */

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid header line: \"%*s\"",
                              r->header_end - r->header_name_start,
                              r->header_name_start);  // 记录错误
                continue;
            }

            /* a header line has been parsed successfully */

            h = ngx_list_push(&r->headers_in.headers);  // 将头部添加到列表
            if (h == NULL) {  // 如果添加失败
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);  // 关闭请求
                break;
            }

            h->hash = r->header_hash;  // 设置头部哈希

            h->key.len = r->header_name_end - r->header_name_start;  // 设置头部名称长度
            h->key.data = r->header_name_start;  // 设置头部名称数据
            h->key.data[h->key.len] = '\0';  // 添加字符串结束符

            h->value.len = r->header_end - r->header_start;  // 设置头部值长度
            h->value.data = r->header_start;  // 设置头部值数据
            h->value.data[h->value.len] = '\0';  // 添加字符串结束符

            h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);  // 分配小写键的内存
            if (h->lowcase_key == NULL) {  // 如果分配失败
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);  // 关闭请求
                break;
            }

            if (h->key.len == r->lowcase_index) {  // 如果键长度匹配
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);  // 复制小写键

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);  // 转换为小写
            }

            hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);  // 查找头部处理器

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {  // 如果处理失败
                break;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header: \"%V: %V\"",
                           &h->key, &h->value);  // 记录调试日志

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {  // 如果头部解析完成

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header done");  // 记录调试日志

            r->request_length += r->header_in->pos - r->header_name_start;  // 更新请求长度

            r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;  // 更新HTTP状态

            rc = ngx_http_process_request_header(r);  // 验证请求头

            if (rc != NGX_OK) {  // 如果验证失败
                break;
            }

            ngx_http_process_request(r);  // 处理请求

            break;
        }

        if (rc == NGX_AGAIN) {  // 如果需要再次尝试

            /* a header line parsing is still not complete */

            continue;
        }

        /* rc == NGX_HTTP_PARSE_INVALID_HEADER */

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client sent invalid header line: \"%*s\\x%02xd...\"",
                      r->header_end - r->header_name_start,
                      r->header_name_start, *r->header_end);  // 记录错误

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);  // 完成请求
        break;
    }

    ngx_http_run_posted_requests(c);  // 运行已发布的请求
}


static ssize_t
ngx_http_read_request_header(ngx_http_request_t *r)
{
    ssize_t                    n;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_core_srv_conf_t  *cscf;

    c = r->connection;
    rev = c->read;

    n = r->header_in->last - r->header_in->pos;

    if (n > 0) {
        return n;
    }

    if (rev->ready) {
        n = c->recv(c, r->header_in->last,
                    r->header_in->end - r->header_in->last);
    } else {
        n = NGX_AGAIN;
    }

    if (n == NGX_AGAIN) {
        if (!rev->timer_set) {
            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
            ngx_add_timer(rev, cscf->client_header_timeout);
        }

        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client prematurely closed connection");
    }

    if (n == 0 || n == NGX_ERROR) {
        c->error = 1;
        c->log->action = "reading client request headers";

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    r->header_in->last += n;

    return n;
}


static ngx_int_t
ngx_http_alloc_large_header_buffer(ngx_http_request_t *r,
    ngx_uint_t request_line)
{
    u_char                    *old, *new;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_connection_t     *hc;
    ngx_http_core_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http alloc large header buffer");

    if (request_line && r->state == 0) {

        /* the client fills up the buffer with "\r\n" */

        r->header_in->pos = r->header_in->start;
        r->header_in->last = r->header_in->start;

        return NGX_OK;
    }

    old = request_line ? r->request_start : r->header_name_start;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    if (r->state != 0
        && (size_t) (r->header_in->pos - old)
                                     >= cscf->large_client_header_buffers.size)
    {
        return NGX_DECLINED;
    }

    hc = r->http_connection;

    if (hc->free) {
        cl = hc->free;
        hc->free = cl->next;

        b = cl->buf;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http large header free: %p %uz",
                       b->pos, b->end - b->last);

    } else if (hc->nbusy < cscf->large_client_header_buffers.num) {

        b = ngx_create_temp_buf(r->connection->pool,
                                cscf->large_client_header_buffers.size);
        if (b == NULL) {
            return NGX_ERROR;
        }

        cl = ngx_alloc_chain_link(r->connection->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = b;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http large header alloc: %p %uz",
                       b->pos, b->end - b->last);

    } else {
        return NGX_DECLINED;
    }

    cl->next = hc->busy;
    hc->busy = cl;
    hc->nbusy++;

    if (r->state == 0) {
        /*
         * r->state == 0 means that a header line was parsed successfully
         * and we do not need to copy incomplete header line and
         * to relocate the parser header pointers
         */

        r->header_in = b;

        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http large header copy: %uz", r->header_in->pos - old);

    if (r->header_in->pos - old > b->end - b->start) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "too large header to copy");
        return NGX_ERROR;
    }

    new = b->start;

    ngx_memcpy(new, old, r->header_in->pos - old);

    b->pos = new + (r->header_in->pos - old);
    b->last = new + (r->header_in->pos - old);

    if (request_line) {
        r->request_start = new;

        if (r->request_end) {
            r->request_end = new + (r->request_end - old);
        }

        if (r->method_end) {
            r->method_end = new + (r->method_end - old);
        }

        if (r->uri_start) {
            r->uri_start = new + (r->uri_start - old);
        }

        if (r->uri_end) {
            r->uri_end = new + (r->uri_end - old);
        }

        if (r->schema_start) {
            r->schema_start = new + (r->schema_start - old);
            if (r->schema_end) {
                r->schema_end = new + (r->schema_end - old);
            }
        }

        if (r->host_start) {
            r->host_start = new + (r->host_start - old);
            if (r->host_end) {
                r->host_end = new + (r->host_end - old);
            }
        }

        if (r->uri_ext) {
            r->uri_ext = new + (r->uri_ext - old);
        }

        if (r->args_start) {
            r->args_start = new + (r->args_start - old);
        }

        if (r->http_protocol.data) {
            r->http_protocol.data = new + (r->http_protocol.data - old);
        }

    } else {
        r->header_name_start = new;

        if (r->header_name_end) {
            r->header_name_end = new + (r->header_name_end - old);
        }

        if (r->header_start) {
            r->header_start = new + (r->header_start - old);
        }

        if (r->header_end) {
            r->header_end = new + (r->header_end - old);
        }
    }

    r->header_in = b;

    return NGX_OK;
}


static ngx_int_t
ngx_http_process_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  **ph;

    ph = (ngx_table_elt_t **) ((char *) &r->headers_in + offset);

    while (*ph) { ph = &(*ph)->next; }

    *ph = h;
    h->next = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_process_unique_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  **ph;

    ph = (ngx_table_elt_t **) ((char *) &r->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
        h->next = NULL;
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "client sent duplicate header line: \"%V: %V\", "
                  "previous value: \"%V: %V\"",
                  &h->key, &h->value, &(*ph)->key, &(*ph)->value);

    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_process_host(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_int_t  rc;
    ngx_str_t  host;

    if (r->headers_in.host) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate host header: \"%V: %V\", "
                      "previous value: \"%V: %V\"",
                      &h->key, &h->value, &r->headers_in.host->key,
                      &r->headers_in.host->value);
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    r->headers_in.host = h;
    h->next = NULL;

    host = h->value;

    rc = ngx_http_validate_host(&host, r->pool, 0);

    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent invalid host header");
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    if (rc == NGX_ERROR) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    if (r->headers_in.server.len) {
        return NGX_OK;
    }

    if (ngx_http_set_virtual_server(r, &host) == NGX_ERROR) {
        return NGX_ERROR;
    }

    r->headers_in.server = host;

    return NGX_OK;
}


static ngx_int_t
ngx_http_process_connection(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    if (ngx_http_process_header_line(r, h, offset) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_strcasestrn(h->value.data, "close", 5 - 1)) {
        r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;

    } else if (ngx_strcasestrn(h->value.data, "keep-alive", 10 - 1)) {
        r->headers_in.connection_type = NGX_HTTP_CONNECTION_KEEP_ALIVE;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_process_user_agent(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    u_char  *user_agent, *msie;

    if (ngx_http_process_header_line(r, h, offset) != NGX_OK) {
        return NGX_ERROR;
    }

    /* check some widespread browsers while the header is in CPU cache */

    user_agent = h->value.data;

    msie = ngx_strstrn(user_agent, "MSIE ", 5 - 1);

    if (msie && msie + 7 < user_agent + h->value.len) {

        r->headers_in.msie = 1;

        if (msie[6] == '.') {

            switch (msie[5]) {
            case '4':
            case '5':
                r->headers_in.msie6 = 1;
                break;
            case '6':
                if (ngx_strstrn(msie + 8, "SV1", 3 - 1) == NULL) {
                    r->headers_in.msie6 = 1;
                }
                break;
            }
        }

#if 0
        /* MSIE ignores the SSL "close notify" alert */
        if (c->ssl) {
            c->ssl->no_send_shutdown = 1;
        }
#endif
    }

    if (ngx_strstrn(user_agent, "Opera", 5 - 1)) {
        r->headers_in.opera = 1;
        r->headers_in.msie = 0;
        r->headers_in.msie6 = 0;
    }

    if (!r->headers_in.msie && !r->headers_in.opera) {

        if (ngx_strstrn(user_agent, "Gecko/", 6 - 1)) {
            r->headers_in.gecko = 1;

        } else if (ngx_strstrn(user_agent, "Chrome/", 7 - 1)) {
            r->headers_in.chrome = 1;

        } else if (ngx_strstrn(user_agent, "Safari/", 7 - 1)
                   && ngx_strstrn(user_agent, "Mac OS X", 8 - 1))
        {
            r->headers_in.safari = 1;

        } else if (ngx_strstrn(user_agent, "Konqueror", 9 - 1)) {
            r->headers_in.konqueror = 1;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_process_request_header(ngx_http_request_t *r)
{
    // 检查服务器头部是否为空，并设置虚拟服务器
    if (r->headers_in.server.len == 0
        && ngx_http_set_virtual_server(r, &r->headers_in.server)
           == NGX_ERROR)
    {
        return NGX_ERROR; // 如果设置失败，返回错误
    }

    // 检查HTTP/1.1请求是否缺少Host头部
    if (r->headers_in.host == NULL && r->http_version > NGX_HTTP_VERSION_10) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                   "client sent HTTP/1.1 request without \"Host\" header");
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR; // 返回错误
    }

    // 处理Content-Length头部
    if (r->headers_in.content_length) {
        r->headers_in.content_length_n =
                            ngx_atoof(r->headers_in.content_length->value.data,
                                      r->headers_in.content_length->value.len);

        // 检查Content-Length值是否有效
        if (r->headers_in.content_length_n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid \"Content-Length\" header");
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return NGX_ERROR; // 返回错误
        }
    }

    // 处理Transfer-Encoding头部
    if (r->headers_in.transfer_encoding) {
        // 检查HTTP版本是否支持Transfer-Encoding
        if (r->http_version < NGX_HTTP_VERSION_11) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent HTTP/1.0 request with "
                          "\"Transfer-Encoding\" header");
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return NGX_ERROR; // 返回错误
        }

        // 检查Transfer-Encoding是否为chunked
        if (r->headers_in.transfer_encoding->value.len == 7
            && ngx_strncasecmp(r->headers_in.transfer_encoding->value.data,
                               (u_char *) "chunked", 7) == 0)
        {
            // 检查是否同时存在Content-Length头部
            if (r->headers_in.content_length) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "client sent \"Content-Length\" and "
                              "\"Transfer-Encoding\" headers "
                              "at the same time");
                ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                return NGX_ERROR; // 返回错误
            }

            r->headers_in.chunked = 1; // 设置chunked标志

        } else {
            // 处理未知的Transfer-Encoding
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent unknown \"Transfer-Encoding\": \"%V\"",
                          &r->headers_in.transfer_encoding->value);
            ngx_http_finalize_request(r, NGX_HTTP_NOT_IMPLEMENTED);
            return NGX_ERROR; // 返回错误
        }
    }

    // 处理Connection头部为Keep-Alive的情况
    if (r->headers_in.connection_type == NGX_HTTP_CONNECTION_KEEP_ALIVE) {
        if (r->headers_in.keep_alive) {
            r->headers_in.keep_alive_n =
                            ngx_atotm(r->headers_in.keep_alive->value.data,
                                      r->headers_in.keep_alive->value.len);
        }
    }

    // 检查请求方法是否为CONNECT
    if (r->method == NGX_HTTP_CONNECT) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent CONNECT method");
        ngx_http_finalize_request(r, NGX_HTTP_NOT_ALLOWED);
        return NGX_ERROR; // 返回错误
    }

    // 检查请求方法是否为TRACE
    if (r->method == NGX_HTTP_TRACE) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent TRACE method");
        ngx_http_finalize_request(r, NGX_HTTP_NOT_ALLOWED);
        return NGX_ERROR; // 返回错误
    }

    return NGX_OK; // 请求头处理成功
}



void
ngx_http_process_request(ngx_http_request_t *r)
{
    ngx_connection_t  *c;

    c = r->connection;  // 获取请求的连接

#if (NGX_HTTP_SSL)

    if (r->http_connection->ssl) {  // 如果连接使用SSL
        long                      rc;
        X509                     *cert;
        const char               *s;
        ngx_http_ssl_srv_conf_t  *sscf;

        if (c->ssl == NULL) {  // 如果连接没有SSL对象
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client sent plain HTTP request to HTTPS port");  // 记录错误日志
            ngx_http_finalize_request(r, NGX_HTTP_TO_HTTPS);  // 终止请求
            return;
        }

        sscf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module);  // 获取SSL模块的服务器配置

        if (sscf->verify) {  // 如果需要验证
            rc = SSL_get_verify_result(c->ssl->connection);  // 获取SSL验证结果

            if (rc != X509_V_OK
                && (sscf->verify != 3 || !ngx_ssl_verify_error_optional(rc)))
            {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));  // 记录SSL证书验证错误

                ngx_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));  // 移除缓存的SSL会话

                ngx_http_finalize_request(r, NGX_HTTPS_CERT_ERROR);  // 终止请求
                return;
            }

            if (sscf->verify == 1) {  // 如果需要客户端证书
                cert = SSL_get_peer_certificate(c->ssl->connection);  // 获取客户端证书

                if (cert == NULL) {  // 如果没有提供证书
                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                  "client sent no required SSL certificate");  // 记录错误日志

                    ngx_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));  // 移除缓存的SSL会话

                    ngx_http_finalize_request(r, NGX_HTTPS_NO_CERT);  // 终止请求
                    return;
                }

                X509_free(cert);  // 释放证书
            }

            if (ngx_ssl_ocsp_get_status(c, &s) != NGX_OK) {  // 获取OCSP状态
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client SSL certificate verify error: %s", s);  // 记录OCSP错误

                ngx_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));  // 移除缓存的SSL会话

                ngx_http_finalize_request(r, NGX_HTTPS_CERT_ERROR);  // 终止请求
                return;
            }
        }
    }

#endif

    if (c->read->timer_set) {  // 如果读事件设置了定时器
        ngx_del_timer(c->read);  // 删除定时器
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);  // 更新统计信息
    r->stat_reading = 0;  // 更新请求的读取状态
    (void) ngx_atomic_fetch_add(ngx_stat_writing, 1);  // 更新统计信息
    r->stat_writing = 1;  // 更新请求的写入状态
#endif

    /* read和write事件都设置为：ngx_http_request_handler，通过事件状态来判断*/
    c->read->handler = ngx_http_request_handler;  // 设置读事件处理函数
    c->write->handler = ngx_http_request_handler;  // 设置写事件处理函数
    r->read_event_handler = ngx_http_block_reading;  // 设置请求的读事件处理函数
    
    /* http处理分发核心函数,主要用于设置write事件回调函数 */
    ngx_http_handler(r);  // 处理HTTP请求
}


ngx_int_t
ngx_http_validate_host(ngx_str_t *host, ngx_pool_t *pool, ngx_uint_t alloc)
{
    u_char  *h, ch;
    size_t   i, dot_pos, host_len;

    enum {
        sw_usual = 0,
        sw_literal,
        sw_rest
    } state;

    dot_pos = host->len;
    host_len = host->len;

    h = host->data;

    state = sw_usual;

    for (i = 0; i < host->len; i++) {
        ch = h[i];

        switch (ch) {

        case '.':
            if (dot_pos == i - 1) {
                return NGX_DECLINED;
            }
            dot_pos = i;
            break;

        case ':':
            if (state == sw_usual) {
                host_len = i;
                state = sw_rest;
            }
            break;

        case '[':
            if (i == 0) {
                state = sw_literal;
            }
            break;

        case ']':
            if (state == sw_literal) {
                host_len = i + 1;
                state = sw_rest;
            }
            break;

        default:

            if (ngx_path_separator(ch)) {
                return NGX_DECLINED;
            }

            if (ch <= 0x20 || ch == 0x7f) {
                return NGX_DECLINED;
            }

            if (ch >= 'A' && ch <= 'Z') {
                alloc = 1;
            }

            break;
        }
    }

    if (dot_pos == host_len - 1) {
        host_len--;
    }

    if (host_len == 0) {
        return NGX_DECLINED;
    }

    if (alloc) {
        host->data = ngx_pnalloc(pool, host_len);
        if (host->data == NULL) {
            return NGX_ERROR;
        }

        ngx_strlow(host->data, h, host_len);
    }

    host->len = host_len;

    return NGX_OK;
}


ngx_int_t
ngx_http_set_virtual_server(ngx_http_request_t *r, ngx_str_t *host)
{
    ngx_int_t                  rc;
    ngx_http_connection_t     *hc;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

#if (NGX_SUPPRESS_WARN)
    cscf = NULL;
#endif

    hc = r->http_connection;

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

    if (hc->ssl_servername) {
        if (hc->ssl_servername->len == host->len
            && ngx_strncmp(hc->ssl_servername->data,
                           host->data, host->len) == 0)
        {
#if (NGX_PCRE)
            if (hc->ssl_servername_regex
                && ngx_http_regex_exec(r, hc->ssl_servername_regex,
                                          hc->ssl_servername) != NGX_OK)
            {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_ERROR;
            }
#endif
            return NGX_OK;
        }
    }

#endif

    rc = ngx_http_find_virtual_server(r->connection,
                                      hc->addr_conf->virtual_names,
                                      host, r, &cscf);

    if (rc == NGX_ERROR) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

    if (hc->ssl_servername) {
        ngx_http_ssl_srv_conf_t  *sscf;

        if (rc == NGX_DECLINED) {
            cscf = hc->addr_conf->default_server;
            rc = NGX_OK;
        }

        sscf = ngx_http_get_module_srv_conf(cscf->ctx, ngx_http_ssl_module);

        if (sscf->verify) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client attempted to request the server name "
                          "different from the one that was negotiated");
            ngx_http_finalize_request(r, NGX_HTTP_MISDIRECTED_REQUEST);
            return NGX_ERROR;
        }
    }

#endif

    if (rc == NGX_DECLINED) {
        return NGX_OK;
    }

    r->srv_conf = cscf->ctx->srv_conf;
    r->loc_conf = cscf->ctx->loc_conf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_set_connection_log(r->connection, clcf->error_log);

    return NGX_OK;
}


static ngx_int_t
ngx_http_find_virtual_server(ngx_connection_t *c,
    ngx_http_virtual_names_t *virtual_names, ngx_str_t *host,
    ngx_http_request_t *r, ngx_http_core_srv_conf_t **cscfp)
{
    ngx_http_core_srv_conf_t  *cscf;

    if (virtual_names == NULL) {
        return NGX_DECLINED;
    }

    cscf = ngx_hash_find_combined(&virtual_names->names,
                                  ngx_hash_key(host->data, host->len),
                                  host->data, host->len);

    if (cscf) {
        *cscfp = cscf;
        return NGX_OK;
    }

#if (NGX_PCRE)

    if (host->len && virtual_names->nregex) {
        ngx_int_t                n;
        ngx_uint_t               i;
        ngx_http_server_name_t  *sn;

        sn = virtual_names->regex;

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

        if (r == NULL) {
            ngx_http_connection_t  *hc;

            for (i = 0; i < virtual_names->nregex; i++) {

                n = ngx_regex_exec(sn[i].regex->regex, host, NULL, 0);

                if (n == NGX_REGEX_NO_MATCHED) {
                    continue;
                }

                if (n >= 0) {
                    hc = c->data;
                    hc->ssl_servername_regex = sn[i].regex;

                    *cscfp = sn[i].server;
                    return NGX_OK;
                }

                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                              ngx_regex_exec_n " failed: %i "
                              "on \"%V\" using \"%V\"",
                              n, host, &sn[i].regex->name);

                return NGX_ERROR;
            }

            return NGX_DECLINED;
        }

#endif /* NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME */

        for (i = 0; i < virtual_names->nregex; i++) {

            n = ngx_http_regex_exec(r, sn[i].regex, host);

            if (n == NGX_DECLINED) {
                continue;
            }

            if (n == NGX_OK) {
                *cscfp = sn[i].server;
                return NGX_OK;
            }

            return NGX_ERROR;
        }
    }

#endif /* NGX_PCRE */

    return NGX_DECLINED;
}


/**
 * HTTP请求事件处理函数
 * 负责处理连接上的读写事件，驱动请求处理流程
 * @param ev 触发的事件对象，包含连接和请求信息
 */
static void
ngx_http_request_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;  // 当前事件关联的连接对象
    ngx_http_request_t  *r;  // 当前处理的HTTP请求对象

    c = ev->data;       // 从事件对象获取关联的连接
    r = c->data;        // 从连接对象获取HTTP请求结构

    // 设置请求日志上下文，将请求与连接日志关联
    ngx_http_set_log_request(c->log, r);

    // 调试日志：记录正在处理的请求URI和参数
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http run request: \"%V?%V\"", &r->uri, &r->args);

    // 如果连接已标记关闭，则终止请求并处理后续队列
    if (c->close) {
        r->main->count++;  // 增加主请求的引用计数
        ngx_http_terminate_request(r, 0);  // 终止当前请求
        ngx_http_run_posted_requests(c);   // 运行已提交的后续请求
        return;
    }

    // 处理延迟超时事件：当事件同时标记为delayed和timedout时重置状态
    if (ev->delayed && ev->timedout) {
        ev->delayed = 0;   // 清除延迟标记
        ev->timedout = 0;  // 清除超时标记
    }

    // 根据事件类型调用对应的处理函数
    if (ev->write) {
        // 写事件处理：调用请求的写事件处理函数
        r->write_event_handler(r);
    } else {
        // 读事件处理：调用请求的读事件处理函数
        r->read_event_handler(r);
    }

    // 处理当前连接上已提交的后续请求
    ngx_http_run_posted_requests(c);
}


void
ngx_http_run_posted_requests(ngx_connection_t *c)
{
    ngx_http_request_t         *r;
    ngx_http_posted_request_t  *pr;

    for ( ;; ) {

        if (c->destroyed) {
            return;
        }

        r = c->data;
        pr = r->main->posted_requests;

        if (pr == NULL) {
            return;
        }

        r->main->posted_requests = pr->next;

        r = pr->request;

        ngx_http_set_log_request(c->log, r);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http posted request: \"%V?%V\"", &r->uri, &r->args);

        r->write_event_handler(r);
    }
}


ngx_int_t
ngx_http_post_request(ngx_http_request_t *r, ngx_http_posted_request_t *pr)
{
    ngx_http_posted_request_t  **p;

    if (pr == NULL) {
        pr = ngx_palloc(r->pool, sizeof(ngx_http_posted_request_t));
        if (pr == NULL) {
            return NGX_ERROR;
        }
    }

    pr->request = r;
    pr->next = NULL;

    for (p = &r->main->posted_requests; *p; p = &(*p)->next) { /* void */ }

    *p = pr;

    return NGX_OK;
}


void
ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t          *c;
    ngx_http_request_t        *pr;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http finalize request: %i, \"%V?%V\" a:%d, c:%d",
                   rc, &r->uri, &r->args, r == c->data, r->main->count);

    if (rc == NGX_DONE) {
        ngx_http_finalize_connection(r);
        return;
    }

    if (rc == NGX_OK && r->filter_finalize) {
        c->error = 1;
    }

    if (rc == NGX_DECLINED) {
        r->content_handler = NULL;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
        return;
    }

    if (r != r->main && r->post_subrequest) {
        rc = r->post_subrequest->handler(r, r->post_subrequest->data, rc);
    }

    if (rc == NGX_ERROR
        || rc == NGX_HTTP_REQUEST_TIME_OUT
        || rc == NGX_HTTP_CLIENT_CLOSED_REQUEST
        || c->error)
    {
        if (ngx_http_post_action(r) == NGX_OK) {
            return;
        }

        ngx_http_terminate_request(r, rc);
        return;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE
        || rc == NGX_HTTP_CREATED
        || rc == NGX_HTTP_NO_CONTENT)
    {
        if (rc == NGX_HTTP_CLOSE) {
            c->timedout = 1;
            ngx_http_terminate_request(r, rc);
            return;
        }

        if (r == r->main) {
            if (c->read->timer_set) {
                ngx_del_timer(c->read);
            }

            if (c->write->timer_set) {
                ngx_del_timer(c->write);
            }
        }

        c->read->handler = ngx_http_request_handler;
        c->write->handler = ngx_http_request_handler;

        ngx_http_finalize_request(r, ngx_http_special_response_handler(r, rc));
        return;
    }

    if (r != r->main) {

        if (r->buffered || r->postponed) {

            if (ngx_http_set_write_handler(r) != NGX_OK) {
                ngx_http_terminate_request(r, 0);
            }

            return;
        }

        pr = r->parent;

        if (r == c->data || r->background) {

            if (!r->logged) {

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

                if (clcf->log_subrequest) {
                    ngx_http_log_request(r);
                }

                r->logged = 1;

            } else {
                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                              "subrequest: \"%V?%V\" logged again",
                              &r->uri, &r->args);
            }

            r->done = 1;

            if (r->background) {
                ngx_http_finalize_connection(r);
                return;
            }

            r->main->count--;

            if (pr->postponed && pr->postponed->request == r) {
                pr->postponed = pr->postponed->next;
            }

            c->data = pr;

        } else {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http finalize non-active request: \"%V?%V\"",
                           &r->uri, &r->args);

            r->write_event_handler = ngx_http_request_finalizer;

            if (r->waited) {
                r->done = 1;
            }
        }

        if (ngx_http_post_request(pr, NULL) != NGX_OK) {
            r->main->count++;
            ngx_http_terminate_request(r, 0);
            return;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http wake parent request: \"%V?%V\"",
                       &pr->uri, &pr->args);

        return;
    }

    if (r->buffered || c->buffered || r->postponed) {

        if (ngx_http_set_write_handler(r) != NGX_OK) {
            ngx_http_terminate_request(r, 0);
        }

        return;
    }

    if (r != c->data) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "http finalize non-active request: \"%V?%V\"",
                      &r->uri, &r->args);
        return;
    }

    r->done = 1;

    r->read_event_handler = ngx_http_block_reading;
    r->write_event_handler = ngx_http_request_empty_handler;

    if (!r->post_action) {
        r->request_complete = 1;
    }

    if (ngx_http_post_action(r) == NGX_OK) {
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        c->write->delayed = 0;
        ngx_del_timer(c->write);
    }

    ngx_http_finalize_connection(r);
}


static void
ngx_http_terminate_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_cleanup_t    *cln;
    ngx_http_request_t    *mr;
    ngx_http_ephemeral_t  *e;

    mr = r->main;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate request count:%d", mr->count);

    mr->terminated = 1;

    if (rc > 0 && (mr->headers_out.status == 0 || mr->connection->sent == 0)) {
        mr->headers_out.status = rc;
    }

    cln = mr->cleanup;
    mr->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate cleanup count:%d blk:%d",
                   mr->count, mr->blocked);

    if (mr->write_event_handler) {

        if (mr->blocked) {
            r = r->connection->data;

            r->connection->error = 1;
            r->write_event_handler = ngx_http_request_finalizer;

            return;
        }

        e = ngx_http_ephemeral(mr);
        mr->posted_requests = NULL;
        mr->write_event_handler = ngx_http_terminate_handler;
        (void) ngx_http_post_request(mr, &e->terminal_posted_request);
        return;
    }

    ngx_http_close_request(mr, rc);
}


static void
ngx_http_terminate_handler(ngx_http_request_t *r)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate handler count:%d", r->count);

    r->count = 1;

    ngx_http_close_request(r, 0);
}


static void
ngx_http_finalize_connection(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t  *clcf;

#if (NGX_HTTP_V2)
    if (r->stream) {
        ngx_http_close_request(r, 0);
        return;
    }
#endif

#if (NGX_HTTP_V3)
    if (r->connection->quic) {
        ngx_http_close_request(r, 0);
        return;
    }
#endif

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->main->count != 1) {

        if (r->discard_body) {
            r->read_event_handler = ngx_http_discarded_request_body_handler;
            ngx_add_timer(r->connection->read, clcf->lingering_timeout);

            if (r->lingering_time == 0) {
                r->lingering_time = ngx_time()
                                      + (time_t) (clcf->lingering_time / 1000);
            }
        }

        ngx_http_close_request(r, 0);
        return;
    }

    r = r->main;

    if (r->connection->read->eof) {
        ngx_http_close_request(r, 0);
        return;
    }

    if (r->reading_body) {
        r->keepalive = 0;
        r->lingering_close = 1;
    }

    if (!ngx_terminate
         && !ngx_exiting
         && r->keepalive
         && clcf->keepalive_timeout > 0)
    {
        ngx_http_set_keepalive(r);
        return;
    }

    if (clcf->lingering_close == NGX_HTTP_LINGERING_ALWAYS
        || (clcf->lingering_close == NGX_HTTP_LINGERING_ON
            && (r->lingering_close
                || r->header_in->pos < r->header_in->last
                || r->connection->read->ready
                || r->connection->pipeline)))
    {
        ngx_http_set_lingering_close(r->connection);
        return;
    }

    ngx_http_close_request(r, 0);
}


static ngx_int_t
ngx_http_set_write_handler(ngx_http_request_t *r)
{
    ngx_event_t               *wev;
    ngx_http_core_loc_conf_t  *clcf;

    r->http_state = NGX_HTTP_WRITING_REQUEST_STATE;

    r->read_event_handler = r->discard_body ?
                                ngx_http_discarded_request_body_handler:
                                ngx_http_test_reading;
    r->write_event_handler = ngx_http_writer;

    wev = r->connection->write;

    if (wev->ready && wev->delayed) {
        return NGX_OK;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (!wev->delayed) {
        ngx_add_timer(wev, clcf->send_timeout);
    }

    if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
        ngx_http_close_request(r, 0);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_writer(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_event_t               *wev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    wev = c->write;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "http writer handler: \"%V?%V\"", &r->uri, &r->args);

    clcf = ngx_http_get_module_loc_conf(r->main, ngx_http_core_module);

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "client timed out");
        c->timedout = 1;

        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (wev->delayed || r->aio) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                       "http writer delayed");

        if (!wev->delayed) {
            ngx_add_timer(wev, clcf->send_timeout);
        }

        if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }

        return;
    }

    rc = ngx_http_output_filter(r, NULL);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http writer output filter: %i, \"%V?%V\"",
                   rc, &r->uri, &r->args);

    if (rc == NGX_ERROR) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (r->buffered || r->postponed || (r == r->main && c->buffered)) {

        if (!wev->delayed) {
            ngx_add_timer(wev, clcf->send_timeout);
        }

        if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }

        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "http writer done: \"%V?%V\"", &r->uri, &r->args);

    r->write_event_handler = ngx_http_request_empty_handler;

    ngx_http_finalize_request(r, rc);
}


static void
ngx_http_request_finalizer(ngx_http_request_t *r)
{
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http finalizer done: \"%V?%V\"", &r->uri, &r->args);

    ngx_http_finalize_request(r, 0);
}


void
ngx_http_block_reading(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http reading blocked");

    /* aio does not call this handler */

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT)
        && r->connection->read->active)
    {
        if (ngx_del_event(r->connection->read, NGX_READ_EVENT, 0) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }
    }
}


void
ngx_http_test_reading(ngx_http_request_t *r)
{
    int                n;
    char               buf[1];
    ngx_err_t          err;
    ngx_event_t       *rev;
    ngx_connection_t  *c;

    c = r->connection;
    rev = c->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http test reading");

#if (NGX_HTTP_V2)

    if (r->stream) {
        if (c->error) {
            err = 0;
            goto closed;
        }

        return;
    }

#endif

#if (NGX_HTTP_V3)

    if (c->quic) {
        if (rev->error) {
            c->error = 1;
            err = 0;
            goto closed;
        }

        return;
    }

#endif

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;
        err = rev->kq_errno;

        goto closed;
    }

#endif

#if (NGX_HAVE_EPOLLRDHUP)

    if ((ngx_event_flags & NGX_USE_EPOLL_EVENT) && ngx_use_epoll_rdhup) {
        socklen_t  len;

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(ngx_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        goto closed;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == 0) {
        rev->eof = 1;
        c->error = 1;
        err = 0;

        goto closed;

    } else if (n == -1) {
        err = ngx_socket_errno;

        if (err != NGX_EAGAIN) {
            rev->eof = 1;
            c->error = 1;

            goto closed;
        }
    }

    /* aio does not call this handler */

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && rev->active) {

        if (ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }
    }

    return;

closed:

    if (err) {
        rev->error = 1;
    }

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        c->ssl->no_send_shutdown = 1;
    }
#endif

    ngx_log_error(NGX_LOG_INFO, c->log, err,
                  "client prematurely closed connection");

    ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
}


static void
ngx_http_set_keepalive(ngx_http_request_t *r)
{
    int                        tcp_nodelay;
    ngx_buf_t                 *b, *f;
    ngx_chain_t               *cl, *ln;
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *c;
    ngx_http_connection_t     *hc;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "set http keepalive handler");

    c->log->action = "closing request";

    hc = r->http_connection;
    b = r->header_in;

    if (b->pos < b->last) {

        /* the pipelined request */

        if (b != c->buffer) {

            /*
             * If the large header buffers were allocated while the previous
             * request processing then we do not use c->buffer for
             * the pipelined request (see ngx_http_create_request()).
             *
             * Now we would move the large header buffers to the free list.
             */

            for (cl = hc->busy; cl; /* void */) {
                ln = cl;
                cl = cl->next;

                if (ln->buf == b) {
                    ngx_free_chain(c->pool, ln);
                    continue;
                }

                f = ln->buf;
                f->pos = f->start;
                f->last = f->start;

                ln->next = hc->free;
                hc->free = ln;
            }

            cl = ngx_alloc_chain_link(c->pool);
            if (cl == NULL) {
                ngx_http_close_request(r, 0);
                return;
            }

            cl->buf = b;
            cl->next = NULL;

            hc->busy = cl;
            hc->nbusy = 1;
        }
    }

    /* guard against recursive call from ngx_http_finalize_connection() */
    r->keepalive = 0;

    ngx_http_free_request(r, 0);

    c->data = hc;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_close_connection(c);
        return;
    }

    wev = c->write;
    wev->handler = ngx_http_empty_handler;

    if (b->pos < b->last) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "pipelined request");

        c->log->action = "reading client pipelined request line";

        r = ngx_http_create_request(c);
        if (r == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        r->pipeline = 1;

        c->data = r;

        c->sent = 0;
        c->destroyed = 0;
        c->pipeline = 1;

        if (rev->timer_set) {
            ngx_del_timer(rev);
        }

        rev->handler = ngx_http_process_request_line;
        ngx_post_event(rev, &ngx_posted_events);
        return;
    }

    /*
     * To keep a memory footprint as small as possible for an idle keepalive
     * connection we try to free c->buffer's memory if it was allocated outside
     * the c->pool.  The large header buffers are always allocated outside the
     * c->pool and are freed too.
     */

    b = c->buffer;

    if (ngx_pfree(c->pool, b->start) == NGX_OK) {

        /*
         * the special note for ngx_http_keepalive_handler() that
         * c->buffer's memory was freed
         */

        b->pos = NULL;

    } else {
        b->pos = b->start;
        b->last = b->start;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "hc free: %p",
                   hc->free);

    if (hc->free) {
        for (cl = hc->free; cl; /* void */) {
            ln = cl;
            cl = cl->next;
            ngx_pfree(c->pool, ln->buf->start);
            ngx_free_chain(c->pool, ln);
        }

        hc->free = NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "hc busy: %p %i",
                   hc->busy, hc->nbusy);

    if (hc->busy) {
        for (cl = hc->busy; cl; /* void */) {
            ln = cl;
            cl = cl->next;
            ngx_pfree(c->pool, ln->buf->start);
            ngx_free_chain(c->pool, ln);
        }

        hc->busy = NULL;
        hc->nbusy = 0;
    }

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        ngx_ssl_free_buffer(c);
    }
#endif

    rev->handler = ngx_http_keepalive_handler;

    if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }
    }

    c->log->action = "keepalive";

    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == -1) {
            ngx_connection_error(c, ngx_socket_errno, ngx_tcp_push_n " failed");
            ngx_http_close_connection(c);
            return;
        }

        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
        tcp_nodelay = ngx_tcp_nodelay_and_tcp_nopush ? 1 : 0;

    } else {
        tcp_nodelay = 1;
    }

    if (tcp_nodelay && clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
        ngx_http_close_connection(c);
        return;
    }

#if 0
    /* if ngx_http_request_t was freed then we need some other place */
    r->http_state = NGX_HTTP_KEEPALIVE_STATE;
#endif

    c->idle = 1;
    ngx_reusable_connection(c, 1);

    ngx_add_timer(rev, clcf->keepalive_timeout);

    if (rev->ready) {
        ngx_post_event(rev, &ngx_posted_events);
    }
}


static void
ngx_http_keepalive_handler(ngx_event_t *rev)
{
    size_t             size;
    ssize_t            n;
    ngx_buf_t         *b;
    ngx_connection_t  *c;

    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http keepalive handler");

    if (rev->timedout || c->close) {
        ngx_http_close_connection(c);
        return;
    }

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            c->log->handler = NULL;
            ngx_log_error(NGX_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %V closed "
                          "keepalive connection", &c->addr_text);
#if (NGX_HTTP_SSL)
            if (c->ssl) {
                c->ssl->no_send_shutdown = 1;
            }
#endif
            ngx_http_close_connection(c);
            return;
        }
    }

#endif

    b = c->buffer;
    size = b->end - b->start;

    if (b->pos == NULL) {

        /*
         * The c->buffer's memory was freed by ngx_http_set_keepalive().
         * However, the c->buffer->start and c->buffer->end were not changed
         * to keep the buffer size.
         */

        b->pos = ngx_palloc(c->pool, size);
        if (b->pos == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        b->start = b->pos;
        b->last = b->pos;
        b->end = b->pos + size;
    }

    /*
     * MSIE closes a keepalive connection with RST flag
     * so we ignore ECONNRESET here.
     */

    c->log_error = NGX_ERROR_IGNORE_ECONNRESET;
    ngx_set_socket_errno(0);

    n = c->recv(c, b->last, size);
    c->log_error = NGX_ERROR_INFO;

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }

        /*
         * Like ngx_http_set_keepalive() we are trying to not hold
         * c->buffer's memory for a keepalive connection.
         */

        if (ngx_pfree(c->pool, b->start) == NGX_OK) {

            /*
             * the special note that c->buffer's memory was freed
             */

            b->pos = NULL;
        }

        return;
    }

    if (n == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }

    c->log->handler = NULL;

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, ngx_socket_errno,
                      "client %V closed keepalive connection", &c->addr_text);
        ngx_http_close_connection(c);
        return;
    }

    b->last += n;

    c->log->handler = ngx_http_log_error;
    c->log->action = "reading client request line";

    c->idle = 0;
    ngx_reusable_connection(c, 0);

    c->data = ngx_http_create_request(c);
    if (c->data == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    c->sent = 0;
    c->destroyed = 0;

    ngx_del_timer(rev);

    rev->handler = ngx_http_process_request_line;
    ngx_http_process_request_line(rev);
}


static void
ngx_http_set_lingering_close(ngx_connection_t *c)
{
    ngx_event_t               *rev, *wev;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *clcf;

    r = c->data;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->lingering_time == 0) {
        r->lingering_time = ngx_time() + (time_t) (clcf->lingering_time / 1000);
    }

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        ngx_int_t  rc;

        c->ssl->shutdown_without_free = 1;

        rc = ngx_ssl_shutdown(c);

        if (rc == NGX_ERROR) {
            ngx_http_close_request(r, 0);
            return;
        }

        if (rc == NGX_AGAIN) {
            c->ssl->handler = ngx_http_set_lingering_close;
            return;
        }
    }
#endif

    rev = c->read;
    rev->handler = ngx_http_lingering_close_handler;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_close_request(r, 0);
        return;
    }

    wev = c->write;
    wev->handler = ngx_http_empty_handler;

    if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
            ngx_http_close_request(r, 0);
            return;
        }
    }

    if (ngx_shutdown_socket(c->fd, NGX_WRITE_SHUTDOWN) == -1) {
        ngx_connection_error(c, ngx_socket_errno,
                             ngx_shutdown_socket_n " failed");
        ngx_http_close_request(r, 0);
        return;
    }

    c->close = 0;
    ngx_reusable_connection(c, 1);

    ngx_add_timer(rev, clcf->lingering_timeout);

    if (rev->ready) {
        ngx_http_lingering_close_handler(rev);
    }
}


static void
ngx_http_lingering_close_handler(ngx_event_t *rev)
{
    ssize_t                    n;
    ngx_msec_t                 timer;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *clcf;
    u_char                     buffer[NGX_HTTP_LINGERING_BUFFER_SIZE];

    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http lingering close handler");

    if (rev->timedout || c->close) {
        ngx_http_close_request(r, 0);
        return;
    }

    timer = (ngx_msec_t) r->lingering_time - (ngx_msec_t) ngx_time();
    if ((ngx_msec_int_t) timer <= 0) {
        ngx_http_close_request(r, 0);
        return;
    }

    do {
        n = c->recv(c, buffer, NGX_HTTP_LINGERING_BUFFER_SIZE);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "lingering read: %z", n);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR || n == 0) {
            ngx_http_close_request(r, 0);
            return;
        }

    } while (rev->ready);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_close_request(r, 0);
        return;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    timer *= 1000;

    if (timer > clcf->lingering_timeout) {
        timer = clcf->lingering_timeout;
    }

    ngx_add_timer(rev, timer);
}


void
ngx_http_empty_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "http empty handler");

    return;
}


void
ngx_http_request_empty_handler(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http request empty handler");

    return;
}


ngx_int_t
ngx_http_send_special(ngx_http_request_t *r, ngx_uint_t flags)
{
    ngx_buf_t    *b;
    ngx_chain_t   out;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (flags & NGX_HTTP_LAST) {

        if (r == r->main && !r->post_action) {
            b->last_buf = 1;

        } else {
            b->sync = 1;
            b->last_in_chain = 1;
        }
    }

    if (flags & NGX_HTTP_FLUSH) {
        b->flush = 1;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_post_action(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->post_action.data == NULL) {
        return NGX_DECLINED;
    }

    if (r->post_action && r->uri_changes == 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "post action: \"%V\"", &clcf->post_action);

    r->main->count--;

    r->http_version = NGX_HTTP_VERSION_9;
    r->header_only = 1;
    r->post_action = 1;

    r->read_event_handler = ngx_http_block_reading;

    if (clcf->post_action.data[0] == '/') {
        ngx_http_internal_redirect(r, &clcf->post_action, NULL);

    } else {
        ngx_http_named_location(r, &clcf->post_action);
    }

    return NGX_OK;
}


void
ngx_http_close_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t  *c;

    r = r->main;
    c = r->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http request count:%d blk:%d", r->count, r->blocked);

    if (r->count == 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "http request count is zero");
    }

    r->count--;

    if (r->count || r->blocked) {
        return;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        ngx_http_v2_close_stream(r->stream, rc);
        return;
    }
#endif

    ngx_http_free_request(r, rc);
    ngx_http_close_connection(c);
}


void
ngx_http_free_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_t                 *log;
    ngx_pool_t                *pool;
    struct linger              linger;
    ngx_http_cleanup_t        *cln;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_core_loc_conf_t  *clcf;

    log = r->connection->log;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http close request");

    if (r->pool == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "http request already closed");
        return;
    }

    cln = r->cleanup;
    r->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

#if (NGX_STAT_STUB)

    if (r->stat_reading) {
        (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
    }

    if (r->stat_writing) {
        (void) ngx_atomic_fetch_add(ngx_stat_writing, -1);
    }

#endif

    if (rc > 0 && (r->headers_out.status == 0 || r->connection->sent == 0)) {
        r->headers_out.status = rc;
    }

    if (!r->logged) {
        log->action = "logging request";

        ngx_http_log_request(r);
    }

    log->action = "closing request";

    if (r->connection->timedout
#if (NGX_HTTP_V3)
        && r->connection->quic == NULL
#endif
       )
    {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->reset_timedout_connection) {
            linger.l_onoff = 1;
            linger.l_linger = 0;

            if (setsockopt(r->connection->fd, SOL_SOCKET, SO_LINGER,
                           (const void *) &linger, sizeof(struct linger)) == -1)
            {
                ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                              "setsockopt(SO_LINGER) failed");
            }
        }
    }

    /* the various request strings were allocated from r->pool */
    ctx = log->data;
    ctx->request = NULL;

    r->request_line.len = 0;

    r->connection->destroyed = 1;

    /*
     * Setting r->pool to NULL will increase probability to catch double close
     * of request since the request object is allocated from its own pool.
     */

    pool = r->pool;
    r->pool = NULL;

    ngx_destroy_pool(pool);
}


static void
ngx_http_log_request(ngx_http_request_t *r)
{
    ngx_uint_t                  i, n;
    ngx_http_handler_pt        *log_handler;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    log_handler = cmcf->phases[NGX_HTTP_LOG_PHASE].handlers.elts;
    n = cmcf->phases[NGX_HTTP_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](r);
    }
}


void
ngx_http_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "close http connection: %d", c->fd);

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_close_connection;
            return;
        }
    }

#endif

#if (NGX_HTTP_V3)
    if (c->quic) {
        ngx_http_v3_reset_stream(c);
    }
#endif

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


static u_char *
ngx_http_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_http_request_t  *r;
    ngx_http_log_ctx_t  *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", &ctx->connection->addr_text);
    len -= p - buf;

    r = ctx->request;

    if (r) {
        return r->log_handler(r, ctx->current_request, p, len);

    } else {
        p = ngx_snprintf(p, len, ", server: %V",
                         &ctx->connection->listening->addr_text);
    }

    return p;
}


static u_char *
ngx_http_log_error_handler(ngx_http_request_t *r, ngx_http_request_t *sr,
    u_char *buf, size_t len)
{
    char                      *uri_separator;
    u_char                    *p;
    ngx_http_upstream_t       *u;
    ngx_http_core_srv_conf_t  *cscf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    p = ngx_snprintf(buf, len, ", server: %V", &cscf->server_name);
    len -= p - buf;
    buf = p;

    if (r->request_line.data == NULL && r->request_start) {
        for (p = r->request_start; p < r->header_in->last; p++) {
            if (*p == CR || *p == LF) {
                break;
            }
        }

        r->request_line.len = p - r->request_start;
        r->request_line.data = r->request_start;
    }

    if (r->request_line.len) {
        p = ngx_snprintf(buf, len, ", request: \"%V\"", &r->request_line);
        len -= p - buf;
        buf = p;
    }

    if (r != sr) {
        p = ngx_snprintf(buf, len, ", subrequest: \"%V\"", &sr->uri);
        len -= p - buf;
        buf = p;
    }

    u = sr->upstream;

    if (u && u->peer.name) {

        uri_separator = "";

#if (NGX_HAVE_UNIX_DOMAIN)
        if (u->peer.sockaddr && u->peer.sockaddr->sa_family == AF_UNIX) {
            uri_separator = ":";
        }
#endif

        p = ngx_snprintf(buf, len, ", upstream: \"%V%V%s%V\"",
                         &u->schema, u->peer.name,
                         uri_separator, &u->uri);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.host) {
        p = ngx_snprintf(buf, len, ", host: \"%V\"",
                         &r->headers_in.host->value);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.referer) {
        p = ngx_snprintf(buf, len, ", referrer: \"%V\"",
                         &r->headers_in.referer->value);
        buf = p;
    }

    return buf;
}
