
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


ngx_buf_t *
ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t *b;

    b = ngx_calloc_buf(pool);
    if (b == NULL) {
        return NULL;
    }

    b->start = ngx_palloc(pool, size);
    if (b->start == NULL) {
        return NULL;
    }

    /*
     * set by ngx_calloc_buf():
     *
     *     b->file_pos = 0;
     *     b->file_last = 0;
     *     b->file = NULL;
     *     b->shadow = NULL;
     *     b->tag = 0;
     *     and flags
     */

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;

    return b;
}


ngx_chain_t *
ngx_alloc_chain_link(ngx_pool_t *pool)
{
    ngx_chain_t  *cl;

    /* 被清空的ngx_chain_t结构都会放在pool->chain 缓冲链上 */
    cl = pool->chain;

    /* 取出pool->chain上的第一个节点 */
    if (cl) {
        pool->chain = cl->next;
        return cl;
    }

    /* 创建一个新的charin_t 结构，放置到poll->chain上 */
    cl = ngx_palloc(pool, sizeof(ngx_chain_t));
    if (cl == NULL) {
        return NULL;
    }
    //? cl->next = NULL;

    return cl;
}


ngx_chain_t *
ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs)
{
    u_char       *p;
    ngx_int_t     i;
    ngx_buf_t    *b;
    ngx_chain_t  *chain, *cl, **ll;

    // 先创建整个缓冲区大小需要的内存
    p = ngx_palloc(pool, bufs->num * bufs->size);
    if (p == NULL) {
        return NULL;
    }

    // 指向链的头，此时链为空
    ll = &chain;

    for (i = 0; i < bufs->num; i++) {
        
        // 创建buf头
        b = ngx_calloc_buf(pool);
        if (b == NULL) {
            return NULL;
        }

        /*
         * set by ngx_calloc_buf():
         *
         *     b->file_pos = 0;
         *     b->file_last = 0;
         *     b->file = NULL;
         *     b->shadow = NULL;
         *     b->tag = 0;
         *     and flags
         *
         */


        // 设置buf的参数
        b->pos = p;
        b->last = p;
        b->temporary = 1;

        b->start = p;
        p += bufs->size;
        b->end = p;

        // 创建一个chain链节点
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;

        // 指向的是链表当前末尾节点的 next 指针, 把cl赋值给*ll，把cl插入到链表尾部
        *ll = cl;

        // 更新ll，即指向链表的指针的指针指向cl->next
        ll = &cl->next;
    }

    *ll = NULL;

    return chain;
}


ngx_int_t
ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;

    ll = chain;

    // ll指向链表的尾部的指针的指针
    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {
        // 重新分配一个chain链节点
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            *ll = NULL;
            return NGX_ERROR;
        }

        // 赋值
        cl->buf = in->buf;

        // 插入到chain链表的尾部
        *ll = cl;
        ll = &cl->next;

        // 往下走
        in = in->next;
    }

    *ll = NULL;

    return NGX_OK;
}


ngx_chain_t *
ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free)
{
    ngx_chain_t  *cl;

    /* 取出free链表的头节点 */
    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;
        return cl;
    }

    /* 创建一个新的chain节点 */
    cl = ngx_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = ngx_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    return cl;
}


void
ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free, ngx_chain_t **busy,
    ngx_chain_t **out, ngx_buf_tag_t tag)
{
    ngx_chain_t  *cl;

    if (*out) {
        if (*busy == NULL) {
            *busy = *out;

        } else {
            for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

            cl->next = *out;
        }

        *out = NULL;
    }

    while (*busy) {
        cl = *busy;

        // 如果节点的 tag 不匹配，将节点从 busy 链表中移除，并放入内存池
        if (cl->buf->tag != tag) {
            *busy = cl->next;
            ngx_free_chain(p, cl);
            continue;
        }

        if (ngx_buf_size(cl->buf) != 0) {
            // 如果当前缓冲区还有数据未处理，停止处理
            break;
        }

        // 当前缓冲区已处理完，将其重置为可复用状态
        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

        // 从busy链中删掉cl
        *busy = cl->next;

        // 把cl放到free头部
        cl->next = *free;
        *free = cl;
    }
}


off_t
ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit)
{
    off_t         total, size, aligned, fprev;
    ngx_fd_t      fd;
    ngx_chain_t  *cl;

    total = 0;

    cl = *in;
    fd = cl->buf->file->fd;

    do {
        // 剩余大小
        size = cl->buf->file_last - cl->buf->file_pos;

        /* 如果合并范围超过limit限制 */
        if (size > limit - total) {
            size = limit - total;

            // 对齐到页大小（ngx_pagesize），保证读取范围是内存页的倍数（如果可以）
            aligned = (cl->buf->file_pos + size + ngx_pagesize - 1)
                       & ~((off_t) ngx_pagesize - 1);

            if (aligned <= cl->buf->file_last) {
                size = aligned - cl->buf->file_pos;
            }

            total += size;
            break;
        }

        
        total += size;
        fprev = cl->buf->file_pos + size;
        cl = cl->next;

    } while (cl
             && cl->buf->in_file
             && total < limit
             && fd == cl->buf->file->fd
             && fprev == cl->buf->file_pos);

    *in = cl;

    return total;
}


ngx_chain_t *
ngx_chain_update_sent(ngx_chain_t *in, off_t sent)
{
    off_t  size;

    for ( /* void */ ; in; in = in->next) {

        if (ngx_buf_special(in->buf)) {
            continue;
        }

        if (sent == 0) {
            break;
        }

        size = ngx_buf_size(in->buf);

        if (sent >= size) {
            sent -= size;

            if (ngx_buf_in_memory(in->buf)) {
                in->buf->pos = in->buf->last;
            }

            if (in->buf->in_file) {
                in->buf->file_pos = in->buf->file_last;
            }

            continue;
        }

        if (ngx_buf_in_memory(in->buf)) {
            in->buf->pos += (size_t) sent;
        }

        if (in->buf->in_file) {
            in->buf->file_pos += sent;
        }

        break;
    }

    return in;
}
