#include "timer.h"
#include <linux/time64.h>

#define TIMER_INFINITE (-1)
#define PQ_DEFAULT_SIZE 500000

typedef int (*prio_queue_comparator)(void *pi, void *pj);
typedef struct {
    rcu_timer_node_t **priv;
    atomic_t nalloc;  // number of items in queue
    atomic_t size;
    prio_queue_comparator comp;
} rcu_prio_queue_t;

static bool prio_queue_init(rcu_prio_queue_t *ptr,
                            prio_queue_comparator comp,
                            int size)
{
    if (size <= 0 || !comp) {
        pr_err("init: invalid size or comparator");
        return false;
    }

    // 使用 kzalloc 确保内存零初始化
    ptr->priv = kzalloc(sizeof(rcu_timer_node_t *) * (size + 1), GFP_KERNEL);
    if (!ptr->priv) {
        pr_err("init: kzalloc failed");
        return false;
    }

    atomic_set(&ptr->nalloc, 0);
    atomic_set(&ptr->size, size + 1);
    ptr->comp = comp;
    return true;
}

static void prio_queue_free(rcu_prio_queue_t *ptr)
{
    kfree(ptr->priv);
}

static inline bool prio_queue_is_empty(rcu_prio_queue_t *ptr)
{
    return !atomic_read(&ptr->nalloc);
}

// return minimun member in queue
static inline void *prio_queue_min(rcu_prio_queue_t *ptr)
{
    return prio_queue_is_empty(ptr) ? NULL : rcu_dereference(ptr->priv[1]);
}



static inline void prio_queue_swap(rcu_prio_queue_t *ptr, size_t i, size_t j)
{
    // 保护指针的读取
    void *tmp = rcu_dereference(ptr->priv[i]);
    // 更新指针，确保写入操作的安全性
    rcu_assign_pointer(ptr->priv[i], rcu_dereference(ptr->priv[j]));
    rcu_assign_pointer(ptr->priv[j], tmp);
}


static size_t prio_queue_sink(rcu_prio_queue_t *ptr, size_t k)
{
    size_t nalloc = atomic_read(&ptr->nalloc);

    while ((k << 1) <= nalloc) {
        size_t j = k << 1;

        // 使用 RCU 保护指针访问
        rcu_read_lock();
        if (j + 1 <= nalloc && ptr->comp(rcu_dereference(ptr->priv[j + 1]), rcu_dereference(ptr->priv[j]))) {
            j++;
        }

        if (!ptr->comp(rcu_dereference(ptr->priv[j]), rcu_dereference(ptr->priv[k]))) {
            rcu_read_unlock();
            break;
        }

        prio_queue_swap(ptr, j, k);
        rcu_read_unlock();
        k = j;
    }
    return k;
}

void rcu_free_callback(struct rcu_head *head)
{
    // 使用 container_of 宏获取包含 rcu 成员的结构体指针，然后调用 kfree
    kfree(container_of(head, rcu_timer_node_t, rcu));
}

/* remove the item with minimum key value from the heap */
static bool prio_queue_delmin(rcu_prio_queue_t *ptr)
{
    size_t nalloc;
    rcu_timer_node_t *node;

    int retry_count = 0;
    const int max_retries = 10;

    do {
        if (prio_queue_is_empty(ptr))
            return true;

        nalloc = atomic_read(&ptr->nalloc);
        rcu_read_lock();
        prio_queue_swap(ptr, 1, nalloc);

        if (nalloc == atomic_read(&ptr->nalloc)) {
            node = rcu_dereference(ptr->priv[nalloc]);
            if (node) {
                atomic_set(&ptr->nalloc, nalloc - 1);
            }
            rcu_read_unlock();
            break;
        }
        rcu_read_unlock();
        // change again
        if (++retry_count > max_retries) {
            pr_err("Failed to delete min item after %d retries\n", retry_count);
            return false;
        }
    } while (1);

    prio_queue_sink(ptr, 1);
    if (node->callback)
        node->callback(node->socket, SHUT_RDWR);

    call_rcu(&node->rcu, rcu_free_callback);
    return true;
}

static inline bool prio_queue_cmpxchg(rcu_timer_node_t **var,
                                      long long *old,
                                      long long neu)
{
    bool ret;
    union u64 {
        struct {
            int low, high;
        } s;
        long long ui;
    } cmp = {.ui = *old}, with = {.ui = neu};

    /**
     * 1. cmp.s.hi:cmp.s.lo compare with *var
     * 2. if equall, set ZF and copy with.s.hi:with.s.lo to *var
     * 3. if not equall， clear ZF and copy *var to cmp.s.hi:cmp.s.lo
     */
    __asm__ __volatile__("lock cmpxchg8b %1\n\tsetz %0"
                         : "=q"(ret), "+m"(*var), "+d"(cmp.s.high),
                           "+a"(cmp.s.low)
                         : "c"(with.s.high), "b"(with.s.low)
                         : "cc", "memory");
    if (!ret)
        *old = cmp.ui;
    return ret;
}

/* add a new item to the heap */
static bool prio_queue_insert(rcu_prio_queue_t *ptr, void *item)
{
    rcu_timer_node_t **slot;  
    size_t old_nalloc;
    long long old;
    int retry_count = 0;
    const int max_retries = 10;

restart:
    old_nalloc = atomic_read(&ptr->nalloc);

    if (old_nalloc >= atomic_read(&ptr->size)) {
        pr_err("Priority queue is full\n");
        return false;
    }

    slot = (rcu_timer_node_t **) &ptr->priv[old_nalloc + 1];
    old = (long long) *slot;

    do {
        if (old_nalloc != atomic_read(&ptr->nalloc))
            if (++retry_count > max_retries) {
                pr_err("Failed to insert item after %d retries\n", retry_count);
                return false;
            } else {
                goto restart;
            }
    } while (!prio_queue_cmpxchg(slot, &old, (long long)item));

    atomic_inc(&ptr->nalloc);

    return true;
}

static int timer_comp(void *ti, void *tj)
{
    return ((rcu_timer_node_t *) ti)->key < ((rcu_timer_node_t *) tj)->key ? 1 : 0;
}

static rcu_prio_queue_t timer;
static atomic_t current_msec;

static void current_time_update(void)
{
    struct timespec64 tv;
    ktime_get_ts64(&tv);  // get current time
    atomic_set(&current_msec, tv.tv_sec * 1000 + tv.tv_nsec / 1000000);
}

void http_timer_init(void)
{
    if (!prio_queue_init(&timer, timer_comp, PQ_DEFAULT_SIZE))
        return;
    current_time_update();
}

void handle_expired_timers(void)
{
    while (!prio_queue_is_empty(&timer)) {
        rcu_timer_node_t *node;

        current_time_update();
        node = prio_queue_min(&timer);

        if (node->key > atomic_read(&current_msec))
            return;

        prio_queue_delmin(&timer);
    }
}

bool http_add_timer(struct http_request *req, size_t timeout, timer_callback cb)
{
    rcu_timer_node_t *node = kmalloc(sizeof(rcu_timer_node_t), GFP_KERNEL);

    if (!node)
        return false;

    current_time_update();
    req->timer_item = node;
    node->key = atomic_read(&current_msec) + timeout;
    node->pos = atomic_read(&timer.nalloc) + 1;
    node->callback = cb;
    node->socket = req->socket;

    prio_queue_insert(&timer, node);
    return true;
}

void http_timer_update(rcu_timer_node_t *node, size_t timeout)
{
    current_time_update();
    node->key = atomic_read(&current_msec) + timeout;
    // update new position
    node->pos = prio_queue_sink(&timer, node->pos);
}


void http_free_timer(void)
{
    int i;
    size_t nalloc = atomic_read(&timer.nalloc);
    for (i = 1; i <= nalloc; i++) {
            rcu_timer_node_t *node = rcu_dereference(timer.priv[i]);
            if (node) {
                call_rcu(&node->rcu, rcu_free_callback);
            }
        }
    prio_queue_free(&timer);
}