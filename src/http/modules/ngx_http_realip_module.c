
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_REALIP_XREALIP  0
#define NGX_HTTP_REALIP_XFWD     1
#define NGX_HTTP_REALIP_HEADER   2
#define NGX_HTTP_REALIP_PROXY    3


typedef struct {
    ngx_array_t       *from;     /* array of ngx_cidr_t */
    ngx_uint_t         type;
    ngx_uint_t         hash;
    ngx_str_t          header;
    ngx_flag_t         recursive;
} ngx_http_realip_loc_conf_t;


typedef struct {
    ngx_connection_t  *connection;
    struct sockaddr   *sockaddr;
    socklen_t          socklen;
    ngx_str_t          addr_text;
} ngx_http_realip_ctx_t;


static ngx_int_t ngx_http_realip_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_realip_set_addr(ngx_http_request_t *r,
    ngx_addr_t *addr);
static void ngx_http_realip_cleanup(void *data);
static char *ngx_http_realip_from(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_realip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_realip_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_realip_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_realip_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_realip_init(ngx_conf_t *cf);
static ngx_http_realip_ctx_t *ngx_http_realip_get_module_ctx(
    ngx_http_request_t *r);


static ngx_int_t ngx_http_realip_remote_addr_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_realip_remote_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_command_t  ngx_http_realip_commands[] = {

    { ngx_string("set_real_ip_from"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_realip_from,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("real_ip_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_realip,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("real_ip_recursive"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_realip_loc_conf_t, recursive),
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_realip_module_ctx = {
    ngx_http_realip_add_variables,         /* preconfiguration */
    ngx_http_realip_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_realip_create_loc_conf,       /* create location configuration */
    ngx_http_realip_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_realip_module = {
    NGX_MODULE_V1,
    &ngx_http_realip_module_ctx,           /* module context */
    ngx_http_realip_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_realip_vars[] = {

    { ngx_string("realip_remote_addr"), NULL,
      ngx_http_realip_remote_addr_variable, 0, 0, 0 },

    { ngx_string("realip_remote_port"), NULL,
      ngx_http_realip_remote_port_variable, 0, 0, 0 },

      ngx_http_null_variable
};


/* RealIP 模块核心处理函数，用于从请求头中提取真实客户端地址 */
static ngx_int_t
ngx_http_realip_handler(ngx_http_request_t *r)
{
    u_char                      *p;          // 临时指针，用于header匹配
    size_t                       len;        // header名称长度
    ngx_str_t                   *value;      // 存储找到的header值
    ngx_uint_t                   i, hash;    // 循环索引和预计算的header哈希值
    ngx_addr_t                   addr;       // 存储解析出的真实地址
    ngx_list_part_t             *part;       // 请求头链表分区指针
    ngx_table_elt_t             *header, *xfwd; // 请求头对象和X-Forwarded-For指针
    ngx_connection_t            *c;          // 当前连接对象
    ngx_http_realip_ctx_t       *ctx;        // realip模块上下文
    ngx_http_realip_loc_conf_t  *rlcf;       // 当前location配置

    /* 获取realip模块的location配置 */
    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_realip_module);

    /* 如果没有配置信任地址列表，直接返回不处理 */
    if (rlcf->from == NULL) {
        return NGX_DECLINED;
    }

    /* 检查是否已经设置过上下文（防止重复处理） */
    ctx = ngx_http_realip_get_module_ctx(r);
    if (ctx) {
        return NGX_DECLINED;
    }

    /* 根据配置类型处理不同来源的真实IP */
    switch (rlcf->type) {

    /* 处理 X-Real-IP 头 */
    case NGX_HTTP_REALIP_XREALIP:
        if (r->headers_in.x_real_ip == NULL) {
            return NGX_DECLINED;  // 没有X-Real-IP头则返回
        }
        value = &r->headers_in.x_real_ip->value;  // 获取头值
        xfwd = NULL;  // 不需要处理X-Forwarded-For链
        break;

    /* 处理 X-Forwarded-For 头 */
    case NGX_HTTP_REALIP_XFWD:
        xfwd = r->headers_in.x_forwarded_for;
        if (xfwd == NULL) {
            return NGX_DECLINED;  // 没有X-Forwarded-For头则返回
        }
        value = NULL;  // 特殊标记，表示需要处理整个代理链
        break;

    /* 处理 PROXY 协议 */
    case NGX_HTTP_REALIP_PROXY:
        if (r->connection->proxy_protocol == NULL) {
            return NGX_DECLINED;  // 没有PROXY协议则返回
        }
        value = &r->connection->proxy_protocol->src_addr;  // 直接从协议获取源地址
        xfwd = NULL;
        break;

    /* 处理自定义header（默认分支） */
    default: /* NGX_HTTP_REALIP_HEADER */
        part = &r->headers_in.headers.part;  // 获取请求头链表第一个分区
        header = part->elts;                 // 获取当前分区的元素数组

        /* 从配置获取预计算的header信息 */
        hash = rlcf->hash;       // header名称的哈希值
        len = rlcf->header.len;  // header名称长度
        p = rlcf->header.data;   // header名称字符串

        /* 遍历所有请求头寻找匹配项 */
        for (i = 0; ; i++) {
            if (i >= part->nelts) {          // 当前分区遍历完
                if (part->next == NULL) {    // 没有下一个分区则退出
                    break;
                }
                part = part->next;           // 移动到下一个分区
                header = part->elts;         // 获取新分区的元素数组
                i = 0;                       // 重置索引
            }

            /* 通过哈希和字符串比较快速匹配header */
            if (hash == header[i].hash
                && len == header[i].key.len
                && ngx_strncmp(p, header[i].lowcase_key, len) == 0)
            {
                value = &header[i].value;  // 找到匹配的header值
                xfwd = NULL;
                goto found;  // 跳转到处理逻辑
            }
        }
        return NGX_DECLINED;  // 没有找到匹配的header
    }

found:
    /* 获取当前连接对象 */
    c = r->connection;

    /* 保存原始地址信息 */
    addr.sockaddr = c->sockaddr;  // 原始socket地址
    addr.socklen = c->socklen;    // 地址结构长度
    /* addr.name = c->addr_text; */  // 原始地址文本（已注释）

    /* 调用核心函数解析真实地址 */
    if (ngx_http_get_forwarded_addr(r, &addr, xfwd, value, rlcf->from,
                                    rlcf->recursive)
        != NGX_DECLINED)
    {
        /* 特殊处理PROXY协议的端口 */
        if (rlcf->type == NGX_HTTP_REALIP_PROXY) {
            ngx_inet_set_port(addr.sockaddr, c->proxy_protocol->src_port);
        }

        /* 设置新的客户端地址 */
        return ngx_http_realip_set_addr(r, &addr);
    }

    return NGX_DECLINED;  // 没有找到有效的真实地址
}


static ngx_int_t
ngx_http_realip_set_addr(ngx_http_request_t *r, ngx_addr_t *addr)
{
    size_t                  len;
    u_char                 *p;
    u_char                  text[NGX_SOCKADDR_STRLEN];
    ngx_connection_t       *c;
    ngx_pool_cleanup_t     *cln;
    ngx_http_realip_ctx_t  *ctx;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_realip_ctx_t));
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = cln->data;

    c = r->connection;

    len = ngx_sock_ntop(addr->sockaddr, addr->socklen, text,
                        NGX_SOCKADDR_STRLEN, 0);
    if (len == 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_pnalloc(c->pool, len);
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(p, text, len);

    cln->handler = ngx_http_realip_cleanup;
    ngx_http_set_ctx(r, ctx, ngx_http_realip_module);

    ctx->connection = c;
    ctx->sockaddr = c->sockaddr;
    ctx->socklen = c->socklen;
    ctx->addr_text = c->addr_text;

    c->sockaddr = addr->sockaddr;
    c->socklen = addr->socklen;
    c->addr_text.len = len;
    c->addr_text.data = p;

    return NGX_DECLINED;
}


static void
ngx_http_realip_cleanup(void *data)
{
    ngx_http_realip_ctx_t *ctx = data;

    ngx_connection_t  *c;

    c = ctx->connection;

    c->sockaddr = ctx->sockaddr;
    c->socklen = ctx->socklen;
    c->addr_text = ctx->addr_text;
}


static char *
ngx_http_realip_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_realip_loc_conf_t *rlcf = conf;

    ngx_int_t             rc;
    ngx_str_t            *value;
    ngx_url_t             u;
    ngx_cidr_t            c, *cidr;
    ngx_uint_t            i;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    value = cf->args->elts;

    if (rlcf->from == NULL) {
        rlcf->from = ngx_array_create(cf->pool, 2,
                                      sizeof(ngx_cidr_t));
        if (rlcf->from == NULL) {
            return NGX_CONF_ERROR;
        }
    }

#if (NGX_HAVE_UNIX_DOMAIN)

    if (ngx_strcmp(value[1].data, "unix:") == 0) {
        cidr = ngx_array_push(rlcf->from);
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }

        cidr->family = AF_UNIX;
        return NGX_CONF_OK;
    }

#endif

    rc = ngx_ptocidr(&value[1], &c);

    if (rc != NGX_ERROR) {
        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[1]);
        }

        cidr = ngx_array_push(rlcf->from);
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }

        *cidr = c;

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.host = value[1];

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in set_real_ip_from \"%V\"",
                               u.err, &u.host);
        }

        return NGX_CONF_ERROR;
    }

    cidr = ngx_array_push_n(rlcf->from, u.naddrs);
    if (cidr == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(cidr, u.naddrs * sizeof(ngx_cidr_t));

    for (i = 0; i < u.naddrs; i++) {
        cidr[i].family = u.addrs[i].sockaddr->sa_family;

        switch (cidr[i].family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
            cidr[i].u.in6.addr = sin6->sin6_addr;
            ngx_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
            cidr[i].u.in.addr = sin->sin_addr.s_addr;
            cidr[i].u.in.mask = 0xffffffff;
            break;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_realip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_realip_loc_conf_t *rlcf = conf;

    ngx_str_t  *value;

    if (rlcf->type != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "X-Real-IP") == 0) {
        rlcf->type = NGX_HTTP_REALIP_XREALIP;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "X-Forwarded-For") == 0) {
        rlcf->type = NGX_HTTP_REALIP_XFWD;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "proxy_protocol") == 0) {
        rlcf->type = NGX_HTTP_REALIP_PROXY;
        return NGX_CONF_OK;
    }

    rlcf->type = NGX_HTTP_REALIP_HEADER;
    rlcf->hash = ngx_hash_strlow(value[1].data, value[1].data, value[1].len);
    rlcf->header = value[1];

    return NGX_CONF_OK;
}


static void *
ngx_http_realip_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_realip_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_realip_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->from = NULL;
     *     conf->hash = 0;
     *     conf->header = { 0, NULL };
     */

    conf->type = NGX_CONF_UNSET_UINT;
    conf->recursive = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_realip_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_realip_loc_conf_t  *prev = parent;
    ngx_http_realip_loc_conf_t  *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

    ngx_conf_merge_uint_value(conf->type, prev->type, NGX_HTTP_REALIP_XREALIP);
    ngx_conf_merge_value(conf->recursive, prev->recursive, 0);

    if (conf->header.len == 0) {
        conf->hash = prev->hash;
        conf->header = prev->header;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_realip_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_realip_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_realip_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_realip_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_realip_handler;

    return NGX_OK;
}


static ngx_http_realip_ctx_t *
ngx_http_realip_get_module_ctx(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t     *cln;
    ngx_http_realip_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_realip_module);

    if (ctx == NULL && (r->internal || r->filter_finalize)) {

        /*
         * if module context was reset, the original address
         * can still be found in the cleanup handler
         */

        for (cln = r->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == ngx_http_realip_cleanup) {
                ctx = cln->data;
                break;
            }
        }
    }

    return ctx;
}


static ngx_int_t
ngx_http_realip_remote_addr_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t              *addr_text;
    ngx_http_realip_ctx_t  *ctx;

    ctx = ngx_http_realip_get_module_ctx(r);

    addr_text = ctx ? &ctx->addr_text : &r->connection->addr_text;

    v->len = addr_text->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = addr_text->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_realip_remote_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t              port;
    struct sockaddr        *sa;
    ngx_http_realip_ctx_t  *ctx;

    ctx = ngx_http_realip_get_module_ctx(r);

    sa = ctx ? ctx->sockaddr : r->connection->sockaddr;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = ngx_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    port = ngx_inet_get_port(sa);

    if (port > 0 && port < 65536) {
        v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
    }

    return NGX_OK;
}
