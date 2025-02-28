
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_REQUEST_H_INCLUDED_
#define _NGX_HTTP_REQUEST_H_INCLUDED_


#define NGX_HTTP_MAX_URI_CHANGES           10
#define NGX_HTTP_MAX_SUBREQUESTS           50

/* must be 2^n */
#define NGX_HTTP_LC_HEADER_LEN             32


#define NGX_HTTP_DISCARD_BUFFER_SIZE       4096
#define NGX_HTTP_LINGERING_BUFFER_SIZE     4096


#define NGX_HTTP_VERSION_9                 9
#define NGX_HTTP_VERSION_10                1000
#define NGX_HTTP_VERSION_11                1001
#define NGX_HTTP_VERSION_20                2000
#define NGX_HTTP_VERSION_30                3000

#define NGX_HTTP_UNKNOWN                   0x00000001
#define NGX_HTTP_GET                       0x00000002
#define NGX_HTTP_HEAD                      0x00000004
#define NGX_HTTP_POST                      0x00000008
#define NGX_HTTP_PUT                       0x00000010
#define NGX_HTTP_DELETE                    0x00000020
#define NGX_HTTP_MKCOL                     0x00000040
#define NGX_HTTP_COPY                      0x00000080
#define NGX_HTTP_MOVE                      0x00000100
#define NGX_HTTP_OPTIONS                   0x00000200
#define NGX_HTTP_PROPFIND                  0x00000400
#define NGX_HTTP_PROPPATCH                 0x00000800
#define NGX_HTTP_LOCK                      0x00001000
#define NGX_HTTP_UNLOCK                    0x00002000
#define NGX_HTTP_PATCH                     0x00004000
#define NGX_HTTP_TRACE                     0x00008000
#define NGX_HTTP_CONNECT                   0x00010000

#define NGX_HTTP_CONNECTION_CLOSE          1
#define NGX_HTTP_CONNECTION_KEEP_ALIVE     2


#define NGX_NONE                           1


#define NGX_HTTP_PARSE_HEADER_DONE         1

#define NGX_HTTP_CLIENT_ERROR              10
#define NGX_HTTP_PARSE_INVALID_METHOD      10
#define NGX_HTTP_PARSE_INVALID_REQUEST     11
#define NGX_HTTP_PARSE_INVALID_VERSION     12
#define NGX_HTTP_PARSE_INVALID_09_METHOD   13

#define NGX_HTTP_PARSE_INVALID_HEADER      14


/* unused                                  1 */
#define NGX_HTTP_SUBREQUEST_IN_MEMORY      2
#define NGX_HTTP_SUBREQUEST_WAITED         4
#define NGX_HTTP_SUBREQUEST_CLONE          8
#define NGX_HTTP_SUBREQUEST_BACKGROUND     16

#define NGX_HTTP_LOG_UNSAFE                1


#define NGX_HTTP_CONTINUE                  100
#define NGX_HTTP_SWITCHING_PROTOCOLS       101
#define NGX_HTTP_PROCESSING                102

#define NGX_HTTP_OK                        200
#define NGX_HTTP_CREATED                   201
#define NGX_HTTP_ACCEPTED                  202
#define NGX_HTTP_NO_CONTENT                204
#define NGX_HTTP_PARTIAL_CONTENT           206

#define NGX_HTTP_SPECIAL_RESPONSE          300
#define NGX_HTTP_MOVED_PERMANENTLY         301
#define NGX_HTTP_MOVED_TEMPORARILY         302
#define NGX_HTTP_SEE_OTHER                 303
#define NGX_HTTP_NOT_MODIFIED              304
#define NGX_HTTP_TEMPORARY_REDIRECT        307
#define NGX_HTTP_PERMANENT_REDIRECT        308

#define NGX_HTTP_BAD_REQUEST               400
#define NGX_HTTP_UNAUTHORIZED              401
#define NGX_HTTP_FORBIDDEN                 403
#define NGX_HTTP_NOT_FOUND                 404
#define NGX_HTTP_NOT_ALLOWED               405
#define NGX_HTTP_REQUEST_TIME_OUT          408
#define NGX_HTTP_CONFLICT                  409
#define NGX_HTTP_LENGTH_REQUIRED           411
#define NGX_HTTP_PRECONDITION_FAILED       412
#define NGX_HTTP_REQUEST_ENTITY_TOO_LARGE  413
#define NGX_HTTP_REQUEST_URI_TOO_LARGE     414
#define NGX_HTTP_UNSUPPORTED_MEDIA_TYPE    415
#define NGX_HTTP_RANGE_NOT_SATISFIABLE     416
#define NGX_HTTP_MISDIRECTED_REQUEST       421
#define NGX_HTTP_TOO_MANY_REQUESTS         429


/* Our own HTTP codes */

/* The special code to close connection without any response */
#define NGX_HTTP_CLOSE                     444

#define NGX_HTTP_NGINX_CODES               494

#define NGX_HTTP_REQUEST_HEADER_TOO_LARGE  494

#define NGX_HTTPS_CERT_ERROR               495
#define NGX_HTTPS_NO_CERT                  496

/*
 * We use the special code for the plain HTTP requests that are sent to
 * HTTPS port to distinguish it from 4XX in an error page redirection
 */
#define NGX_HTTP_TO_HTTPS                  497

/* 498 is the canceled code for the requests with invalid host name */

/*
 * HTTP does not define the code for the case when a client closed
 * the connection while we are processing its request so we introduce
 * own code to log such situation when a client has closed the connection
 * before we even try to send the HTTP header to it
 */
#define NGX_HTTP_CLIENT_CLOSED_REQUEST     499


#define NGX_HTTP_INTERNAL_SERVER_ERROR     500
#define NGX_HTTP_NOT_IMPLEMENTED           501
#define NGX_HTTP_BAD_GATEWAY               502
#define NGX_HTTP_SERVICE_UNAVAILABLE       503
#define NGX_HTTP_GATEWAY_TIME_OUT          504
#define NGX_HTTP_VERSION_NOT_SUPPORTED     505
#define NGX_HTTP_INSUFFICIENT_STORAGE      507


#define NGX_HTTP_LOWLEVEL_BUFFERED         0xf0
#define NGX_HTTP_WRITE_BUFFERED            0x10
#define NGX_HTTP_GZIP_BUFFERED             0x20
#define NGX_HTTP_SSI_BUFFERED              0x01
#define NGX_HTTP_SUB_BUFFERED              0x02
#define NGX_HTTP_COPY_BUFFERED             0x04


typedef enum {
    NGX_HTTP_INITING_REQUEST_STATE = 0,
    NGX_HTTP_READING_REQUEST_STATE,
    NGX_HTTP_PROCESS_REQUEST_STATE,

    NGX_HTTP_CONNECT_UPSTREAM_STATE,
    NGX_HTTP_WRITING_UPSTREAM_STATE,
    NGX_HTTP_READING_UPSTREAM_STATE,

    NGX_HTTP_WRITING_REQUEST_STATE,
    NGX_HTTP_LINGERING_CLOSE_STATE,
    NGX_HTTP_KEEPALIVE_STATE
} ngx_http_state_e;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
    ngx_http_header_handler_pt        handler;
} ngx_http_header_t;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
} ngx_http_header_out_t;


typedef struct {
    ngx_list_t                        headers;

    ngx_table_elt_t                  *host;
    ngx_table_elt_t                  *connection;
    ngx_table_elt_t                  *if_modified_since;
    ngx_table_elt_t                  *if_unmodified_since;
    ngx_table_elt_t                  *if_match;
    ngx_table_elt_t                  *if_none_match;
    ngx_table_elt_t                  *user_agent;
    ngx_table_elt_t                  *referer;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_range;
    ngx_table_elt_t                  *content_type;

    ngx_table_elt_t                  *range;
    ngx_table_elt_t                  *if_range;

    ngx_table_elt_t                  *transfer_encoding;
    ngx_table_elt_t                  *te;
    ngx_table_elt_t                  *expect;
    ngx_table_elt_t                  *upgrade;

#if (NGX_HTTP_GZIP || NGX_HTTP_HEADERS)
    ngx_table_elt_t                  *accept_encoding;
    ngx_table_elt_t                  *via;
#endif

    ngx_table_elt_t                  *authorization;

    ngx_table_elt_t                  *keep_alive;

#if (NGX_HTTP_X_FORWARDED_FOR)
    ngx_table_elt_t                  *x_forwarded_for;
#endif

#if (NGX_HTTP_REALIP)
    ngx_table_elt_t                  *x_real_ip;
#endif

#if (NGX_HTTP_HEADERS)
    ngx_table_elt_t                  *accept;
    ngx_table_elt_t                  *accept_language;
#endif

#if (NGX_HTTP_DAV)
    ngx_table_elt_t                  *depth;
    ngx_table_elt_t                  *destination;
    ngx_table_elt_t                  *overwrite;
    ngx_table_elt_t                  *date;
#endif

    ngx_table_elt_t                  *cookie;

    ngx_str_t                         user;
    ngx_str_t                         passwd;

    ngx_str_t                         server;
    off_t                             content_length_n;
    time_t                            keep_alive_n;

    unsigned                          connection_type:2;
    unsigned                          chunked:1;
    unsigned                          multi:1;
    unsigned                          multi_linked:1;
    unsigned                          msie:1;
    unsigned                          msie6:1;
    unsigned                          opera:1;
    unsigned                          gecko:1;
    unsigned                          chrome:1;
    unsigned                          safari:1;
    unsigned                          konqueror:1;
} ngx_http_headers_in_t;


typedef struct {
    ngx_list_t                        headers;
    ngx_list_t                        trailers;

    ngx_uint_t                        status;
    ngx_str_t                         status_line;

    ngx_table_elt_t                  *server;
    ngx_table_elt_t                  *date;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_encoding;
    ngx_table_elt_t                  *location;
    ngx_table_elt_t                  *refresh;
    ngx_table_elt_t                  *last_modified;
    ngx_table_elt_t                  *content_range;
    ngx_table_elt_t                  *accept_ranges;
    ngx_table_elt_t                  *www_authenticate;
    ngx_table_elt_t                  *expires;
    ngx_table_elt_t                  *etag;

    ngx_table_elt_t                  *cache_control;
    ngx_table_elt_t                  *link;

    ngx_str_t                        *override_charset;

    size_t                            content_type_len;
    ngx_str_t                         content_type;
    ngx_str_t                         charset;
    u_char                           *content_type_lowcase;
    ngx_uint_t                        content_type_hash;

    off_t                             content_length_n;
    off_t                             content_offset;
    time_t                            date_time;
    time_t                            last_modified_time;
} ngx_http_headers_out_t;


typedef void (*ngx_http_client_body_handler_pt)(ngx_http_request_t *r);

typedef struct {
    ngx_temp_file_t                  *temp_file;
    ngx_chain_t                      *bufs;
    ngx_buf_t                        *buf;
    off_t                             rest;
    off_t                             received;
    ngx_chain_t                      *free;
    ngx_chain_t                      *busy;
    ngx_http_chunked_t               *chunked;
    ngx_http_client_body_handler_pt   post_handler;
    unsigned                          filter_need_buffering:1;
    unsigned                          last_sent:1;
    unsigned                          last_saved:1;
} ngx_http_request_body_t;


typedef struct ngx_http_addr_conf_s  ngx_http_addr_conf_t;

typedef struct {
    ngx_http_addr_conf_t             *addr_conf;
    ngx_http_conf_ctx_t              *conf_ctx;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_str_t                        *ssl_servername;
#if (NGX_PCRE)
    ngx_http_regex_t                 *ssl_servername_regex;
#endif
#endif

    ngx_chain_t                      *busy;
    ngx_int_t                         nbusy;

    ngx_chain_t                      *free;

    unsigned                          ssl:1;
    unsigned                          proxy_protocol:1;
} ngx_http_connection_t;


typedef void (*ngx_http_cleanup_pt)(void *data);

typedef struct ngx_http_cleanup_s  ngx_http_cleanup_t;

struct ngx_http_cleanup_s {
    ngx_http_cleanup_pt               handler;
    void                             *data;
    ngx_http_cleanup_t               *next;
};


typedef ngx_int_t (*ngx_http_post_subrequest_pt)(ngx_http_request_t *r,
    void *data, ngx_int_t rc);

typedef struct {
    ngx_http_post_subrequest_pt       handler;
    void                             *data;
} ngx_http_post_subrequest_t;


typedef struct ngx_http_postponed_request_s  ngx_http_postponed_request_t;

struct ngx_http_postponed_request_s {
    ngx_http_request_t               *request;
    ngx_chain_t                      *out;
    ngx_http_postponed_request_t     *next;
};


typedef struct ngx_http_posted_request_s  ngx_http_posted_request_t;

struct ngx_http_posted_request_s {
    ngx_http_request_t               *request;
    ngx_http_posted_request_t        *next;
};


typedef ngx_int_t (*ngx_http_handler_pt)(ngx_http_request_t *r);
typedef void (*ngx_http_event_handler_pt)(ngx_http_request_t *r);


struct ngx_http_request_s {
    uint32_t                          signature;         /* "HTTP" 请求签名 */

    ngx_connection_t                 *connection;        /* 连接对象 */

    void                            **ctx;               /* 模块上下文 */
    void                            **main_conf;         /* main级别配置 */
    void                            **srv_conf;          /* server级别配置 */
    void                            **loc_conf;          /* location级别配置 */

    ngx_http_event_handler_pt         read_event_handler; /* 读事件处理函数 */
    ngx_http_event_handler_pt         write_event_handler; /* 写事件处理函数 */

#if (NGX_HTTP_CACHE)
    ngx_http_cache_t                 *cache;             /* 缓存对象 */
#endif

    ngx_http_upstream_t              *upstream;          /* 上游对象 */
    ngx_array_t                      *upstream_states;   /* 上游状态数组 */
                                         /* of ngx_http_upstream_state_t */

    ngx_pool_t                       *pool;              /* 内存池 */
    ngx_buf_t                        *header_in;         /* 输入头缓冲区 */

    ngx_http_headers_in_t             headers_in;        /* 输入头 */
    ngx_http_headers_out_t            headers_out;       /* 输出头 */

    ngx_http_request_body_t          *request_body;      /* 请求体 */

    time_t                            lingering_time;    /* 持续时间 */
    time_t                            start_sec;         /* 开始时间（秒） */
    ngx_msec_t                        start_msec;        /* 开始时间（毫秒） */

    ngx_uint_t                        method;            /* 请求方法 */
    ngx_uint_t                        http_version;      /* HTTP版本 */

    ngx_str_t                         request_line;      /* 请求行 */
    ngx_str_t                         uri;               /* URI */
    ngx_str_t                         args;              /* 参数 */
    ngx_str_t                         exten;             /* 扩展名 */
    ngx_str_t                         unparsed_uri;      /* 未解析的URI */

    ngx_str_t                         method_name;       /* 方法名 */
    ngx_str_t                         http_protocol;     /* HTTP协议 */
    ngx_str_t                         schema;            /* 协议方案 */

    ngx_chain_t                      *out;               /* 输出链 */
    ngx_http_request_t               *main;              /* 主请求 */
    ngx_http_request_t               *parent;            /* 父请求 */
    ngx_http_postponed_request_t     *postponed;         /* 延迟请求 */
    ngx_http_post_subrequest_t       *post_subrequest;   /* 子请求回调 */
    ngx_http_posted_request_t        *posted_requests;   /* 已发布请求 */

    ngx_int_t                         phase_handler;     /* 阶段处理器 */
    ngx_http_handler_pt               content_handler;   /* 内容处理器 */
    ngx_uint_t                        access_code;       /* 访问码 */

    ngx_http_variable_value_t        *variables;         /* 变量 */

#if (NGX_PCRE)
    ngx_uint_t                        ncaptures;         /* 捕获数量 */
    int                              *captures;          /* 捕获数组 */
    u_char                           *captures_data;     /* 捕获数据 */
#endif

    size_t                            limit_rate;        /* 限速 */
    size_t                            limit_rate_after;  /* 限速后 */

    /* 用于计算没有头部的Apache兼容响应长度 */
    size_t                            header_size;       /* 头部大小 */

    off_t                             request_length;    /* 请求长度 */

    ngx_uint_t                        err_status;        /* 错误状态 */

    ngx_http_connection_t            *http_connection;   /* HTTP连接 */
    ngx_http_v2_stream_t             *stream;            /* HTTP/2流 */
    ngx_http_v3_parse_t              *v3_parse;          /* HTTP/3解析 */

    ngx_http_log_handler_pt           log_handler;       /* 日志处理器 */

    ngx_http_cleanup_t               *cleanup;           /* 清理函数 */

    unsigned                          count:16;          /* 计数 */
    unsigned                          subrequests:8;     /* 子请求数量 */
    unsigned                          blocked:8;         /* 阻塞标志 */

    unsigned                          aio:1;             /* 异步I/O标志 */

    unsigned                          http_state:4;      /* HTTP状态 */

    /* URI包含"/."和在Win32上包含"//" */
    unsigned                          complex_uri:1;     /* 复杂URI */

    /* URI包含"%" */
    unsigned                          quoted_uri:1;      /* 引号URI */

    /* URI包含"+" */
    unsigned                          plus_in_uri:1;     /* URI中包含加号 */

    /* URI包含空路径 */
    unsigned                          empty_path_in_uri:1; /* URI中包含空路径 */

    unsigned                          invalid_header:1;  /* 无效头部 */

    unsigned                          add_uri_to_alias:1; /* 添加URI到别名 */
    unsigned                          valid_location:1;  /* 有效位置 */
    unsigned                          valid_unparsed_uri:1; /* 有效未解析URI */
    unsigned                          uri_changed:1;     /* URI已更改 */
    unsigned                          uri_changes:4;     /* URI更改次数 */

    unsigned                          request_body_in_single_buf:1; /* 请求体在单一缓冲区中 */
    unsigned                          request_body_in_file_only:1; /* 请求体仅在文件中 */
    unsigned                          request_body_in_persistent_file:1; /* 请求体在持久文件中 */
    unsigned                          request_body_in_clean_file:1; /* 请求体在干净文件中 */
    unsigned                          request_body_file_group_access:1; /* 请求体文件组访问 */
    unsigned                          request_body_file_log_level:3; /* 请求体文件日志级别 */
    unsigned                          request_body_no_buffering:1; /* 请求体无缓冲 */

    unsigned                          subrequest_in_memory:1; /* 子请求在内存中 */
    unsigned                          waited:1;          /* 等待标志 */

#if (NGX_HTTP_CACHE)
    unsigned                          cached:1;          /* 缓存标志 */
#endif

#if (NGX_HTTP_GZIP)
    unsigned                          gzip_tested:1;     /* GZIP测试标志 */
    unsigned                          gzip_ok:1;         /* GZIP可用标志 */
    unsigned                          gzip_vary:1;       /* GZIP变化标志 */
#endif

#if (NGX_PCRE)
    unsigned                          realloc_captures:1; /* 重新分配捕获 */
#endif

    unsigned                          proxy:1;           /* 代理标志 */
    unsigned                          bypass_cache:1;    /* 绕过缓存 */
    unsigned                          no_cache:1;        /* 无缓存 */

    /*
     * 代替在ngx_http_limit_conn_module和ngx_http_limit_req_module中使用请求上下文数据
     * 我们在请求结构中使用位字段
     */
    unsigned                          limit_conn_status:2; /* 连接限制状态 */
    unsigned                          limit_req_status:3;  /* 请求限制状态 */

    unsigned                          limit_rate_set:1;   /* 限速设置 */
    unsigned                          limit_rate_after_set:1; /* 限速后设置 */

#if 0
    unsigned                          cacheable:1;       /* 可缓存 */
#endif

    unsigned                          pipeline:1;        /* 管道标志 */
    unsigned                          chunked:1;         /* 分块传输标志 */
    unsigned                          header_only:1;     /* 仅头部标志 */
    unsigned                          expect_trailers:1; /* 期望尾部标志 */
    unsigned                          keepalive:1;       /* 保持连接标志 */
    unsigned                          lingering_close:1; /* 延迟关闭标志 */
    unsigned                          discard_body:1;    /* 丢弃请求体标志 */
    unsigned                          reading_body:1;    /* 读取请求体标志 */
    unsigned                          internal:1;        /* 内部请求标志 */
    unsigned                          error_page:1;      /* 错误页面标志 */
    unsigned                          filter_finalize:1; /* 过滤器完成标志 */
    unsigned                          post_action:1;     /* 后置动作标志 */
    unsigned                          request_complete:1; /* 请求完成标志 */
    unsigned                          request_output:1;  /* 请求输出标志 */
    unsigned                          header_sent:1;     /* 头部已发送标志 */
    unsigned                          response_sent:1;   /* 响应已发送标志 */
    unsigned                          expect_tested:1;   /* 期望测试标志 */
    unsigned                          root_tested:1;     /* 根测试标志 */
    unsigned                          done:1;            /* 完成标志 */
    unsigned                          logged:1;          /* 已记录标志 */
    unsigned                          terminated:1;      /* 终止标志 */

    unsigned                          buffered:4;        /* 缓冲标志 */

    unsigned                          main_filter_need_in_memory:1; /* 主过滤器需要在内存中 */
    unsigned                          filter_need_in_memory:1; /* 过滤器需要在内存中 */
    unsigned                          filter_need_temporary:1; /* 过滤器需要临时 */
    unsigned                          preserve_body:1;   /* 保留请求体 */
    unsigned                          allow_ranges:1;    /* 允许范围请求 */
    unsigned                          subrequest_ranges:1; /* 子请求范围 */
    unsigned                          single_range:1;    /* 单一范围请求 */
    unsigned                          disable_not_modified:1; /* 禁用未修改响应 */
    unsigned                          stat_reading:1;    /* 统计读取 */
    unsigned                          stat_writing:1;    /* 统计写入 */
    unsigned                          stat_processing:1; /* 统计处理 */

    unsigned                          background:1;      /* 后台请求 */
    unsigned                          health_check:1;    /* 健康检查 */

    /* 用于解析HTTP头部 */

    ngx_uint_t                        state;             /* 状态 */

    ngx_uint_t                        header_hash;       /* 头部哈希 */
    ngx_uint_t                        lowcase_index;     /* 小写索引 */
    u_char                            lowcase_header[NGX_HTTP_LC_HEADER_LEN]; /* 小写头部 */

    u_char                           *header_name_start; /* 头部名称开始 */
    u_char                           *header_name_end;   /* 头部名称结束 */
    u_char                           *header_start;      /* 头部开始 */
    u_char                           *header_end;        /* 头部结束 */

    /*
     * 解析请求行后可以重用的内存
     * 通过ngx_http_ephemeral_t
     */

    u_char                           *uri_start;         /* URI开始 */
    u_char                           *uri_end;           /* URI结束 */
    u_char                           *uri_ext;           /* URI扩展名 */
    u_char                           *args_start;        /* 参数开始 */
    u_char                           *request_start;     /* 请求开始 */
    u_char                           *request_end;       /* 请求结束 */
    u_char                           *method_end;        /* 方法结束 */
    u_char                           *schema_start;      /* 协议方案开始 */
    u_char                           *schema_end;        /* 协议方案结束 */
    u_char                           *host_start;        /* 主机开始 */
    u_char                           *host_end;          /* 主机结束 */

    unsigned                          http_minor:16;     /* HTTP次版本号 */
    unsigned                          http_major:16;     /* HTTP主版本号 */
};


typedef struct {
    ngx_http_posted_request_t         terminal_posted_request;
} ngx_http_ephemeral_t;


#define ngx_http_ephemeral(r)  (void *) (&r->uri_start)


extern ngx_http_header_t       ngx_http_headers_in[];
extern ngx_http_header_out_t   ngx_http_headers_out[];


#define ngx_http_set_log_request(log, r)                                      \
    ((ngx_http_log_ctx_t *) log->data)->current_request = r


#endif /* _NGX_HTTP_REQUEST_H_INCLUDED_ */
