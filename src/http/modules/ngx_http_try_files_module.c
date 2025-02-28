
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_array_t           *lengths;
    ngx_array_t           *values;
    ngx_str_t              name;

    unsigned               code:10;
    unsigned               test_dir:1;
} ngx_http_try_file_t;


typedef struct {
    ngx_http_try_file_t   *try_files;
} ngx_http_try_files_loc_conf_t;


static ngx_int_t ngx_http_try_files_handler(ngx_http_request_t *r);
static char *ngx_http_try_files(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_try_files_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_try_files_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_try_files_commands[] = {

    { ngx_string("try_files"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_try_files,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_try_files_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_try_files_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_try_files_create_loc_conf,    /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_try_files_module = {
    NGX_MODULE_V1,
    &ngx_http_try_files_module_ctx,        /* module context */
    ngx_http_try_files_commands,           /* module directives */
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
 * try_files指令的核心处理函数
 * 
 * 该函数在请求处理阶段被调用，主要功能：
 * 1. 按照配置顺序检查文件/目录是否存在
 * 2. 找到第一个存在的文件并处理：
 *    - 如果是常规文件：设置请求文件路径并返回成功
 *    - 如果是目录：自动添加结尾斜线并重定向
 * 3. 所有文件都不存在时：
 *    - 返回最后一个参数指定的错误码或默认404错误
 *
 * 工作流程：
 * 1. 获取try_files模块的location配置
 * 2. 初始化路径处理相关变量（分配内存、获取alias配置等）
 * 3. 循环处理每个try_files条目：
 *    a. 计算当前条目的路径长度（区分静态路径和包含变量的动态路径）
 *    b. 构建完整文件路径：
 *       - 处理alias和root路径转换
 *       - 合并URI路径和try_files条目
 *    c. 检查文件属性：
 *       - 通过ngx_http_core_try_file()测试文件可访问性
 *       - 处理目录自动补全逻辑
 *    d. 根据检查结果决定继续测试或返回
 * 4. 处理最终结果：
 *    - 找到有效文件：设置请求的filename字段并返回NGX_OK
 *    - 全部检查失败：返回配置的fallback错误码或默认404
 *
 * 关键参数说明：
 * @param r 当前HTTP请求对象，包含请求的所有上下文信息
 * @return 处理状态码：
 *         NGX_OK         - 找到有效文件并处理
 *         NGX_DECLINED   - 无有效配置或所有检查失败
 *         HTTP错误码     - 具体错误情况（如403, 404等）
 *
 * 注意事项：
 * - 路径构建时需要考虑alias和root指令的不同处理逻辑
 * - 动态路径（包含变量）需要通过脚本引擎计算实际值
 * - 目录检测需要处理结尾斜线自动补全和重定向
 */
static ngx_int_t
ngx_http_try_files_handler(ngx_http_request_t *r)
{
    size_t                          len, root, alias, reserve, allocated;
    u_char                         *p, *name;
    ngx_str_t                       path, args;
    ngx_uint_t                      test_dir;
    ngx_http_try_file_t            *tf;
    ngx_open_file_info_t            of;
    ngx_http_script_code_pt         code;
    ngx_http_script_engine_t        e;
    ngx_http_core_loc_conf_t       *clcf;
    ngx_http_script_len_code_pt     lcode;
    ngx_http_try_files_loc_conf_t  *tlcf;

    /* 获取try_files的location配置 */
    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_try_files_module);

    if (tlcf->try_files == NULL) {
        return NGX_DECLINED;  // 没有配置try_files指令则直接返回
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "try files handler");

    /* 初始化路径相关变量 */
    allocated = 0;     // 已分配的内存大小
    root = 0;          // URI到文件路径的root部分长度
    name = NULL;       // 当前测试的文件名指针
    /* suppress MSVC warning */
    path.data = NULL;  // 文件路径缓冲区

    tf = tlcf->try_files;  // 获取try_files配置数组

    /* 获取core模块的location配置 */
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    alias = clcf->alias;  // 获取alias配置值

    /* 循环处理每个try_files条目 */
    for ( ;; ) {

        /* 计算当前条目的路径长度 */
        if (tf->lengths) {
            /* 动态路径（包含变量）需要计算长度 */
            ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

            e.ip = tf->lengths->elts;  // 脚本长度计算代码
            e.request = r;

            /* 1 is for terminating '\0' as in static names */
            len = 1;  // 初始长度包含终止符

            /* 执行长度计算脚本 */
            while (*(uintptr_t *) e.ip) {
                lcode = *(ngx_http_script_len_code_pt *) e.ip;
                len += lcode(&e);  // 累加各个部分的长度
            }

        } else {
            /* 静态路径直接使用预计算长度 */
            len = tf->name.len;
        }

        /* 计算需要预留的缓冲区大小 */
        if (!alias) {
            // 没有alias时，预留长度差
            reserve = len > r->uri.len ? len - r->uri.len : 0;

        } else if (alias == NGX_MAX_SIZE_T_VALUE) {
            // 完全alias时，预留完整长度
            reserve = len;

        } else {
            // 部分alias时，计算差值
            reserve = len > r->uri.len - alias ? len - (r->uri.len - alias) : 0;
        }

        /* 分配或扩展路径缓冲区 */
        if (reserve > allocated || !allocated) {

            /* 16 bytes are preallocation */
            allocated = reserve + 16;  // 预分配额外16字节

            // 将URI映射到文件系统路径
            if (ngx_http_map_uri_to_path(r, &path, &root, allocated) == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            name = path.data + root;  // 获取是相对路径名
        }

        /* 构建完整文件路径 */
        if (tf->values == NULL) {
            /* 静态路径直接拷贝 */
            /* tf->name.len includes the terminating '\0' */

            ngx_memcpy(name, tf->name.data, tf->name.len);  // 复制文件名
            path.len = (name + tf->name.len - 1) - path.data;  // 计算总长度

        } else {
            /* 动态路径需要执行脚本生成 */
            /* 脚本引擎初始化 */
            e.ip = tf->values->elts;  // 设置脚本指令指针，指向动态路径生成的编译代码数组
            e.pos = name;             // 设置输出缓冲区起始位置，用于构建最终文件路径
            e.flushed = 1;            // 标记缓冲区已刷新，确保后续写入从pos开始

            /* 动态路径生成阶段 */
            // 循环执行预编译的脚本指令集，每个指令处理路径的不同组成部分
            // 指令可能包含：变量提取（如$uri）、字符串拼接、编码转换等操作
            while (*(uintptr_t *) e.ip) {
                code = *(ngx_http_script_code_pt *) e.ip;  // 获取当前指令的函数指针
                code((ngx_http_script_engine_t *) &e);      // 执行指令（如追加URI参数、添加静态字符串等）
            }

            /* 路径后处理 */
            path.len = e.pos - path.data;  // 计算生成路径的实际长度（当前写入位置 - 起始位置）
            *e.pos = '\0';                 // 确保路径字符串以NULL结尾，符合C字符串规范

            /* Alias替换处理逻辑 */
            // 当配置了alias且不是完全替换模式时（NGX_MAX_SIZE_T_VALUE表示完全替换的特殊标记）
            // 且生成的路径开头与请求URI的alias部分匹配时，执行路径替换
            if (alias && alias != NGX_MAX_SIZE_T_VALUE
                && ngx_strncmp(name, r->uri.data, alias) == 0)
            {
                // 内存块移动：将alias之后的部分前移，实现路径替换
                // 参数说明：目标地址，源地址（跳过alias部分），需要移动的字节数
                ngx_memmove(name, name + alias, len - alias);
                
                // 调整最终路径长度：减去被替换的alias部分的长度
                path.len -= alias;  
            }
        }

        test_dir = tf->test_dir;  // 获取是否测试目录的标记
        tf++;  // 移动到下一个条目

        /* 调试日志：当前测试的路径信息 */
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "trying to use %s: \"%s\" \"%s\"",
                       test_dir ? "dir" : "file", name, path.data);

        /* 检查是否是最后一个回退条目 */
        if (tf->lengths == NULL && tf->name.len == 0) {

            if (tf->code) {
                return tf->code;  // 直接返回指定状态码
            }

            /* 处理最终回退逻辑 */
            path.len -= root;  // 移除root部分
            path.data += root;

            if (path.data[0] == '@') {
                // 命名location跳转
                (void) ngx_http_named_location(r, &path);

            } else {
                // 普通内部跳转
                ngx_http_split_args(r, &path, &args);  // 分离路径和参数
                (void) ngx_http_internal_redirect(r, &path, &args);
            }

            ngx_http_finalize_request(r, NGX_DONE);
            return NGX_DONE;  // 请求处理完成
        }

        /**
         * @brief 找到文件后，查看文件是否存在
         */
        ngx_memzero(&of, sizeof(ngx_open_file_info_t));

        /* 设置文件打开参数 */
        of.read_ahead = clcf->read_ahead;
        of.directio = clcf->directio;
        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.test_only = 1;  // 仅测试文件是否存在
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;

        /* 检查符号链接设置 */
        if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* 尝试打开缓存文件 */
        if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
            != NGX_OK)
        {
            /* 处理打开失败情况 */
            if (of.err == 0) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;  // 未知错误
            }

            /* 忽略常见文件不存在错误 */
            if (of.err != NGX_ENOENT       // 文件不存在
                && of.err != NGX_ENOTDIR   // 不是目录
                && of.err != NGX_ENAMETOOLONG)  // 文件名过长
            {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, of.err,
                              "%s \"%s\" failed", of.failed, path.data);
            }

            continue;  // 继续尝试下一个条目
        }

        /* 检查文件类型是否匹配（目录/文件） */
        if (of.is_dir != test_dir) {
            continue;  // 类型不匹配则跳过
        }

        /* 成功找到有效文件，准备返回 */
        path.len -= root;  // 调整路径长度
        path.data += root;

        /* 根据alias设置更新请求URI */
        if (!alias) {
            r->uri = path;  // 无alias直接使用路径

        } else if (alias == NGX_MAX_SIZE_T_VALUE) {
            if (!test_dir) {  // 完全alias且不是目录
                r->uri = path;
                r->add_uri_to_alias = 1;  // 标记需要添加URI到alias
            }

        } else {
            /* 部分alias情况，拼接URI */
            name = r->uri.data;

            r->uri.len = alias + path.len;
            r->uri.data = ngx_pnalloc(r->pool, r->uri.len);
            if (r->uri.data == NULL) {
                r->uri.len = 0;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            p = ngx_copy(r->uri.data, name, alias);  // 复制alias部分
            ngx_memcpy(p, path.data, path.len);      // 追加路径部分
        }

        /* 设置文件扩展类型 */
        ngx_http_set_exten(r);

        /* 调试日志：最终使用的URI */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "try file uri: \"%V\"", &r->uri);

        return NGX_DECLINED;  // 交给后续handler处理
    }

    /* not reached */
}


/*
 * 功能：处理try_files指令的配置解析
 * 作用：将配置中的文件路径列表和fallback处理方式转换为可用的数据结构
 * 工作流程：
 * 1. 检查重复配置
 * 2. 分配内存存储文件检查项
 * 3. 遍历所有参数（最后一个参数是fallback处理）
 * 4. 处理每个路径参数：
 *    - 识别目录检查标记（结尾的/）
 *    - 处理变量表达式
 *    - 编译路径中的脚本（如果有变量）
 * 5. 解析最后的fallback状态码（如果有=前缀）
 */
static char *
ngx_http_try_files(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_try_files_loc_conf_t *tlcf = conf;  // 获取location配置结构

    ngx_str_t                  *value;    // 配置参数值数组
    ngx_int_t                   code;     // 解析后的状态码
    ngx_uint_t                  i, n;     // 循环计数器和临时变量
    ngx_http_try_file_t        *tf;       // 文件检查项数组
    ngx_http_script_compile_t   sc;       // 脚本编译结构

    /* 防止重复配置 */
    if (tlcf->try_files) {
        return "is duplicate";
    }

    /* 为所有参数分配内存（最后一个参数是fallback处理） */
    tf = ngx_pcalloc(cf->pool, cf->args->nelts * sizeof(ngx_http_try_file_t));
    if (tf == NULL) {
        return NGX_CONF_ERROR;
    }

    tlcf->try_files = tf;  // 将数组挂载到配置结构

    value = cf->args->elts;  // 获取所有配置参数

    /* 遍历所有参数（排除最后的fallback参数） */
    for (i = 0; i < cf->args->nelts - 1; i++) {

        /* 设置当前检查项的文件路径 */
        tf[i].name = value[i + 1];  // 第一个参数是命令名，从+1开始

        /* 处理目录检查标记：
         * 1. 路径以/结尾
         * 2. 不是最后一个检查项
         * 3. 后面还有参数
         */
        if (tf[i].name.len > 0
            && tf[i].name.data[tf[i].name.len - 1] == '/'
            && i + 2 < cf->args->nelts)
        {
            tf[i].test_dir = 1;  // 标记需要检查目录
            tf[i].name.len--;    // 去掉结尾的/
            tf[i].name.data[tf[i].name.len] = '\0';  // 添加字符串终结符
        }

        /* 处理路径中的变量 */
        n = ngx_http_script_variables_count(&tf[i].name);  // 计算变量数量

        if (n) {
            /* 编译包含变量的路径 */
            ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

            sc.cf = cf;                    // 配置上下文
            sc.source = &tf[i].name;       // 要编译的字符串
            sc.lengths = &tf[i].lengths;   // 存储长度信息
            sc.values = &tf[i].values;     // 存储值信息
            sc.variables = n;              // 变量数量
            sc.complete_lengths = 1;       // 需要完整长度信息
            sc.complete_values = 1;        // 需要完整值信息

            if (ngx_http_script_compile(&sc) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

        } else {
            /* 无变量时，为字符串添加结尾的\0（计入长度） */
            tf[i].name.len++;
        }
    }

    /* 处理fallback状态码（格式：=404） */
    if (tf[i - 1].name.data[0] == '=') {

        /* 解析状态码（跳过=号，长度-2因为要去掉=和结尾的\0） */
        code = ngx_atoi(tf[i - 1].name.data + 1, tf[i - 1].name.len - 2);

        /* 验证状态码有效性 */
        if (code == NGX_ERROR || code > 999) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid code \"%*s\"",
                               tf[i - 1].name.len - 1, tf[i - 1].name.data);
            return NGX_CONF_ERROR;
        }

        tf[i].code = code;  // 存储解析后的状态码
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_try_files_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_try_files_loc_conf_t  *tlcf;

    tlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_try_files_loc_conf_t));
    if (tlcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     tlcf->try_files = NULL;
     */

    return tlcf;
}


static ngx_int_t
ngx_http_try_files_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_try_files_handler;

    return NGX_OK;
}
