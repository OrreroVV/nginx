
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_array_t  *mirror;
    ngx_flag_t    request_body;
} ngx_http_mirror_loc_conf_t;


typedef struct {
    ngx_int_t     status;
} ngx_http_mirror_ctx_t;


static ngx_int_t ngx_http_mirror_handler(ngx_http_request_t *r);
static void ngx_http_mirror_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_mirror_handler_internal(ngx_http_request_t *r);
static void *ngx_http_mirror_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_mirror_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_mirror(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_mirror_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_mirror_commands[] = {

    { ngx_string("mirror"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_mirror,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("mirror_request_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mirror_loc_conf_t, request_body),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_mirror_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_mirror_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_mirror_create_loc_conf,       /* create location configuration */
    ngx_http_mirror_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_mirror_module = {
    NGX_MODULE_V1,
    &ngx_http_mirror_module_ctx,           /* module context */
    ngx_http_mirror_commands,              /* module directives */
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


/**
 * HTTP镜像请求处理函数
 * 
 * 该函数在请求处理阶段被调用，主要功能：
 * 1. 检查当前请求是否为主请求（非子请求）
 * 2. 获取镜像模块的location配置，检查是否配置了镜像规则
 * 3. 处理请求体镜像：
 *    - 创建镜像上下文用于跟踪请求状态
 *    - 异步读取客户端请求体
 *    - 通过回调函数处理后续镜像逻辑
 * 4. 当不需要处理请求体时，直接执行内部镜像处理
 *
 * 返回值说明：
 * NGX_DECLINED   - 未处理请求，转交后续handler
 * NGX_ERROR      - 内存分配失败
 * NGX_DONE       - 请求已异步处理
 * 其他返回值     - HTTP错误状态码
 */
static ngx_int_t
ngx_http_mirror_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_http_mirror_ctx_t       *ctx;
    ngx_http_mirror_loc_conf_t  *mlcf;

    /* 仅处理主请求，子请求直接跳过 */
    if (r != r->main) {
        return NGX_DECLINED;
    }

    /* 获取镜像模块的location配置 */
    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mirror_module);

    /* 检查是否配置了镜像目标 */
    if (mlcf->mirror == NULL) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "mirror handler");

    /* 需要处理请求体的情况（当配置了mirror_request_body on时） */
    if (mlcf->request_body) {
        /* 尝试获取已存在的上下文 */
        ctx = ngx_http_get_module_ctx(r, ngx_http_mirror_module);

        /* 如果上下文已存在，直接返回当前状态 */
        if (ctx) {
            return ctx->status;
        }

        /* 分配新的上下文结构体 */
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_mirror_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        /* 初始化上下文状态为处理中 */
        ctx->status = NGX_DONE;

        /* 将上下文绑定到当前请求 */
        ngx_http_set_ctx(r, ctx, ngx_http_mirror_module);

        /* 异步读取客户端请求体，完成后调用ngx_http_mirror_body_handler */
        rc = ngx_http_read_client_request_body(r, ngx_http_mirror_body_handler);
        
        /* 处理立即错误（如客户端断开连接等） */
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        /* 暂停当前请求处理，等待请求体读取完成 */
        ngx_http_finalize_request(r, NGX_DONE);
        return NGX_DONE;
    }

    /* 不需要处理请求体时直接执行镜像逻辑 */
    return ngx_http_mirror_handler_internal(r);
}


static void
ngx_http_mirror_body_handler(ngx_http_request_t *r)
{
    ngx_http_mirror_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_mirror_module);

    ctx->status = ngx_http_mirror_handler_internal(r);

    r->preserve_body = 1;

    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
}


static ngx_int_t
ngx_http_mirror_handler_internal(ngx_http_request_t *r)
{
    ngx_str_t                   *name;
    ngx_uint_t                   i;
    ngx_http_request_t          *sr;
    ngx_http_mirror_loc_conf_t  *mlcf;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mirror_module);

    name = mlcf->mirror->elts;

    for (i = 0; i < mlcf->mirror->nelts; i++) {
        if (ngx_http_subrequest(r, &name[i], &r->args, &sr, NULL,
                                NGX_HTTP_SUBREQUEST_BACKGROUND)
            != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        sr->header_only = 1;
        sr->method = r->method;
        sr->method_name = r->method_name;
    }

    return NGX_DECLINED;
}


static void *
ngx_http_mirror_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_mirror_loc_conf_t  *mlcf;

    mlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mirror_loc_conf_t));
    if (mlcf == NULL) {
        return NULL;
    }

    mlcf->mirror = NGX_CONF_UNSET_PTR;
    mlcf->request_body = NGX_CONF_UNSET;

    return mlcf;
}


static char *
ngx_http_mirror_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_mirror_loc_conf_t *prev = parent;
    ngx_http_mirror_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->mirror, prev->mirror, NULL);
    ngx_conf_merge_value(conf->request_body, prev->request_body, 1);

    return NGX_CONF_OK;
}


static char *
ngx_http_mirror(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mirror_loc_conf_t *mlcf = conf;

    ngx_str_t  *value, *s;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        if (mlcf->mirror != NGX_CONF_UNSET_PTR) {
            return "is duplicate";
        }

        mlcf->mirror = NULL;
        return NGX_CONF_OK;
    }

    if (mlcf->mirror == NULL) {
        return "is duplicate";
    }

    if (mlcf->mirror == NGX_CONF_UNSET_PTR) {
        mlcf->mirror = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (mlcf->mirror == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    s = ngx_array_push(mlcf->mirror);
    if (s == NULL) {
        return NGX_CONF_ERROR;
    }

    *s = value[1];

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_mirror_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_mirror_handler;

    return NGX_OK;
}
