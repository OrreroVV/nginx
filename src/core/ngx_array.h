
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_ARRAY_H_INCLUDED_
#define _NGX_ARRAY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    void        *elts;      /* 指向数组第一个元素指针*/
    ngx_uint_t   nelts;     /* 数组已使用元素*/
    size_t       size;      /* 每个元素的大小，元素大小固定*/
    ngx_uint_t   nalloc;    /* 分配多少个元素 */
    ngx_pool_t  *pool;      /* 内存池*/
} ngx_array_t;


/**
 * @brief 通过内存池p创建容量为n，大小为size的数组
 * @param p 内存池
 * @param n 元素个数
 * @param size 元素大小
 * @return ngx_array_t* 
 */
ngx_array_t *ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size);

/**
 * @brief 销毁数组（不释放内存，只是内存块名义上释放）
 * @param a 
 */
void ngx_array_destroy(ngx_array_t *a);

/**
 * @brief 
 * @param a 
 * @return void* 返回该数组当前元素指针
 */
void *ngx_array_push(ngx_array_t *a);

/**
 * @brief 分配n个大小，如果内存块满了，则删掉该占用的内存，并且重新分配内存
 * @param a 
 * @param n 
 * @return void* 返回该数组分配后第一个元素指针
 */
void *ngx_array_push_n(ngx_array_t *a, ngx_uint_t n);


static ngx_inline ngx_int_t
ngx_array_init(ngx_array_t *array, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    /*
     * set "array->nelts" before "array->elts", otherwise MSVC thinks
     * that "array->nelts" may be used without having been initialized
     */

    // 数组只是初始化，分配内存，但未使用里面的值
    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->pool = pool;
    //分配n个size大小的数组内存
    array->elts = ngx_palloc(pool, n * size);
    if (array->elts == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


#endif /* _NGX_ARRAY_H_INCLUDED_ */
