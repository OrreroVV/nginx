
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


// ngx_posted_accept_events 用于存储 accept 事件队列，主要处理新连接相关的事件
ngx_queue_t  ngx_posted_accept_events;

// ngx_posted_next_events 用于存放延迟处理的事件队列，先暂存后转入立即处理队列
ngx_queue_t  ngx_posted_next_events;

// ngx_posted_events 用于存储需要立即执行的事件队列
ngx_queue_t  ngx_posted_events;


void
ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;

    while (!ngx_queue_empty(posted)) {

        q = ngx_queue_head(posted);
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);

        ngx_delete_posted_event(ev);

        ev->handler(ev);
    }
}


void
ngx_event_move_posted_next(ngx_cycle_t *cycle)
{
    // 声明队列指针和事件指针，用于遍历延迟处理的事件队列
    ngx_queue_t  *q;
    ngx_event_t  *ev;

    // 遍历 ngx_posted_next_events 队列中的每个事件节点
    for (q = ngx_queue_head(&ngx_posted_next_events);
         q != ngx_queue_sentinel(&ngx_posted_next_events);
         q = ngx_queue_next(q))
    {
        // 从当前队列节点中获取事件结构体指针
        ev = ngx_queue_data(q, ngx_event_t, queue);

        // 输出调试日志，记录当前处理的事件地址
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted next event %p", ev);

        // 将事件状态设置为就绪，表示该事件可以立即处理
        ev->ready = 1;
        // 将事件的 available 字段设为 -1，通常用于标记等待状态或未确认状态
        ev->available = -1;
    }

    // 将所有延迟处理的事件从 ngx_posted_next_events 队列移动到立即处理的事件队列 ngx_posted_events 中
    ngx_queue_add(&ngx_posted_events, &ngx_posted_next_events);
    // 重新初始化 ngx_posted_next_events 队列，清空所有节点，准备下次使用
    ngx_queue_init(&ngx_posted_next_events);
}
