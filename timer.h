#ifndef TIMER_H
#define TIMER_H

#include "http_server.h"
#include <linux/rcupdate.h>

#define TIMEOUT_DEFAULT 8000 /* ms */

typedef int (*timer_callback)(struct socket *, enum sock_shutdown_cmd);
typedef struct {
    size_t key;
    size_t pos;  // the position of timer in queue
    timer_callback callback;
    struct socket *socket;
    struct rcu_head rcu; // 用于 RCU 保护和延迟删除
} rcu_timer_node_t;


void http_timer_init(void);
int http_find_timer(void);
void handle_expired_timers(void);
bool http_add_timer(struct http_request *req,
                    size_t timeout,
                    timer_callback cb);
void http_timer_update(rcu_timer_node_t *node, size_t timeout);
void http_free_timer(void);

#endif