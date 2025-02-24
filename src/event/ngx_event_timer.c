
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_rbtree_t              ngx_event_timer_rbtree;
static ngx_rbtree_node_t  ngx_event_timer_sentinel;

/*
 * the event timer rbtree may contain the duplicate keys, however,
 * it should not be a problem, because we use the rbtree to find
 * a minimum timer value only
 */

ngx_int_t
ngx_event_timer_init(ngx_log_t *log)
{
    ngx_rbtree_init(&ngx_event_timer_rbtree, &ngx_event_timer_sentinel,
                    ngx_rbtree_insert_timer_value);

    return NGX_OK;
}


ngx_msec_t
ngx_event_find_timer(void)
{
    ngx_msec_int_t      timer;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    if (ngx_event_timer_rbtree.root == &ngx_event_timer_sentinel) {
        return NGX_TIMER_INFINITE;
    }

    root = ngx_event_timer_rbtree.root;
    sentinel = ngx_event_timer_rbtree.sentinel;

    node = ngx_rbtree_min(root, sentinel);

    timer = (ngx_msec_int_t) (node->key - ngx_current_msec);

    return (ngx_msec_t) (timer > 0 ? timer : 0);
}


/*
 * 处理定时器超时事件的函数
 * 遍历定时器红黑树,找出所有已经超时的事件并调用其处理函数
 */
void
ngx_event_expire_timers(void)
{
    ngx_event_t        *ev;         /* 事件结构体指针 */
    ngx_rbtree_node_t  *node, *root, *sentinel;  /* 红黑树节点指针 */

    /* 获取定时器红黑树的哨兵节点 */
    sentinel = ngx_event_timer_rbtree.sentinel;

    for ( ;; ) {
        /* 获取定时器红黑树的根节点 */
        root = ngx_event_timer_rbtree.root;

        /* 如果根节点是哨兵节点,说明红黑树为空,直接返回 */
        if (root == sentinel) {
            return;
        }

        /* 获取红黑树中最小的节点,即最早超时的定时器 */
        node = ngx_rbtree_min(root, sentinel);

        /* node->key > ngx_current_msec */

        /* 如果最小节点的超时时间大于当前时间,说明没有定时器超时,返回 */
        if ((ngx_msec_int_t) (node->key - ngx_current_msec) > 0) {
            return;
        }

        /* 获取定时器对应的事件结构体 */
        ev = ngx_rbtree_data(node, ngx_event_t, timer);

        /* 输出调试日志 */
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "event timer del: %d: %M",
                       ngx_event_ident(ev->data), ev->timer.key);

        /* 从红黑树中删除该定时器节点 */
        ngx_rbtree_delete(&ngx_event_timer_rbtree, &ev->timer);

#if (NGX_DEBUG)
        /* 调试模式下清空节点指针 */
        ev->timer.left = NULL;
        ev->timer.right = NULL;
        ev->timer.parent = NULL;
#endif

        /* 清除定时器标志 */
        ev->timer_set = 0;

        /* 设置超时标志 */
        ev->timedout = 1;

        /* 调用事件的处理函数 */
        ev->handler(ev);
    }
}


ngx_int_t
ngx_event_no_timers_left(void)
{
    ngx_event_t        *ev;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    sentinel = ngx_event_timer_rbtree.sentinel;
    root = ngx_event_timer_rbtree.root;

    if (root == sentinel) {
        return NGX_OK;
    }

    for (node = ngx_rbtree_min(root, sentinel);
         node;
         node = ngx_rbtree_next(&ngx_event_timer_rbtree, node))
    {
        ev = ngx_rbtree_data(node, ngx_event_t, timer);

        if (!ev->cancelable) {
            return NGX_AGAIN;
        }
    }

    /* only cancelable timers left */

    return NGX_OK;
}
