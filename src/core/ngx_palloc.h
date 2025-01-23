
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

#define NGX_POOL_ALIGNMENT       16
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)


typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;  // 清理回调函数
    void                 *data;     // 数据
    ngx_pool_cleanup_t   *next;     // 下一个链表数据
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;

struct ngx_pool_large_s {
    ngx_pool_large_t     *next;
    void                 *alloc;
};


typedef struct {
    u_char               *last;     /* 内存池中未使用内存的开始节点地址 */
    u_char               *end;      /* 内存池结束地址 */
    ngx_pool_t           *next;     /* 指向的下一个内存池 */
    ngx_uint_t            failed;   /* 失败次数 */
} ngx_pool_data_t;


struct ngx_pool_s {
    ngx_pool_data_t       d;        /* 记录内存池的信息 */
    size_t                max;      /* 线程池最大可分配内存 */
    ngx_pool_t           *current;  /* 指向当前的内存池指针地址。ngx_pool_t链表上最后一个缓存池结构*/
    ngx_chain_t          *chain;    /* 缓冲区链表, 管理和缓存已经清空（释放）但仍可重用的 ngx_chain_t 链表节点 */

    // 只有父节点才有这些信息large和cleanup
    ngx_pool_large_t     *large;    /* 存储大数据的链表 */
    ngx_pool_cleanup_t   *cleanup;  /* 可自定义回调函数，清除内存块分配的内存,链表 */

    ngx_log_t            *log;      /* 日志 */
};


typedef struct {
    ngx_fd_t              fd;
    u_char               *name;
    ngx_log_t            *log;
} ngx_pool_cleanup_file_t;


ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);

/**
 * @brief 清理内存池
 *      先清理回调链，再清理日志，再清理large链，最后清理内存池链表
 * @param pool 
 */
void ngx_destroy_pool(ngx_pool_t *pool);

/**
 * @brief 重置内存池，只需要清除large链，并且重置内存池信息
 * @param pool 
 */
void ngx_reset_pool(ngx_pool_t *pool);

/**
 * @brief 使用内存池分配一块内存 (主调用)
 * @param pool 父节点内存池
 * @param size 大小
 * @return void* 返回指针
 */
void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);

/**
 * @brief 从内存池中分配一个size大小的内存并都置为0 (主调用)
 * @param pool 
 * @param size 
 * @return void* 
 */
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);

/**
 * @brief 创建size大小内存，并且创建large块，头插到large链中
 * @param pool 
 * @param size 
 * @param alignment 
 * @return void* 
 */
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);

/**
 * @brief 释放large链中目标为p的large块内存
 * @param pool 
 * @param p 
 * @return ngx_int_t 
 */
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);

/**
 * @brief 创建一个清理回调函数，返回cleaup_t结构体，供附上回调函数和data数据，以便后续进行清理
 * @param p 
 * @param size 
 * @return ngx_pool_cleanup_t* 
 */
ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
