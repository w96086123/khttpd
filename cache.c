#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/rculist_bl.h>
#include "cache.h"
#include "memcache.h"

#define CACHE_MAX_ITEMS 100 // 定义缓存项的最大数量
DEFINE_HASHTABLE(cache_table, CACHE_HASH_BITS);

struct cache {
    struct memcache *cache_memcache;
    spinlock_t lock; // 自旋锁保护缓存
};

static struct cache my_cache;

static u32 hash_fn(const char *str)
{
    u32 hash = 0;
    while (*str) {
        hash = (hash << 5) + *str++;
    }
    return hash;
}

void cache_init(void)
{
    hash_init(cache_table);
    my_cache.cache_memcache = memcache_create(sizeof(struct cache_item), CACHE_MAX_ITEMS);
    if (!my_cache.cache_memcache) {
        pr_err("Failed to create memcache\n");
        return;
    }
    spin_lock_init(&my_cache.lock);
}

static void cache_rcu_free(struct rcu_head *rcu)
{
    struct cache_item *item = container_of(rcu, struct cache_item, rcu);
    memcache_free(my_cache.cache_memcache, item);
}

static void cache_remove_oldest(void)
{
    if (list_empty(&my_cache.cache_memcache->lru_list))
        return;

    struct cache_item *item;

    item = list_last_entry(&my_cache.cache_memcache->lru_list, struct cache_item, lru_node);
    spin_lock(&my_cache.lock);
    hash_del_rcu(&item->node);
    list_del_rcu(&item->lru_node);
    spin_unlock(&my_cache.lock);

    // 使用 RCU 回调延迟释放内存
    call_rcu(&item->rcu, cache_rcu_free);
    my_cache.cache_memcache->item_count--;
}

struct cache_item *cache_lookup(const char *url)
{
    struct cache_item *item;
    u32 key = hash_fn(url);

    rcu_read_lock(); // 保护读操作
    hash_for_each_possible_rcu(cache_table, item, node, key) {
        if (strcmp(item->request_url, url) == 0) {
            // 移动缓存项到 LRU 列表的头部
            list_del_rcu(&item->lru_node);
            list_add_rcu(&item->lru_node, &my_cache.cache_memcache->lru_list);
            rcu_read_unlock(); // 解除保护
            return item;
        }
    }
    rcu_read_unlock(); // 解除保护
    return NULL;
}

struct cache_item *cache_create_item(const char *url)
{
    struct cache_item *item = memcache_alloc(my_cache.cache_memcache);
    if (!item) {
        pr_err("Failed to allocate memory for cache_item\n");
        return NULL;
    }

    strncpy(item->request_url, url, sizeof(item->request_url) - 1);
    item->request_url[sizeof(item->request_url) - 1] = '\0'; // 确保字符串以 null 结尾
    memset(item->response_data, 0, sizeof(item->response_data));
    item->response_size = 0;
    item->max_size = sizeof(item->response_data);
    INIT_LIST_HEAD(&item->lru_node);
    list_add_rcu(&item->lru_node, &my_cache.cache_memcache->lru_list);
    my_cache.cache_memcache->item_count++;

    // 不需要初始化 RCU 头部，RCU 回调会自动处理
    // INIT_RCU_HEAD(&item->rcu);

    // 如果超过最大缓存项数量，移除最旧的缓存项
    if (my_cache.cache_memcache->item_count > CACHE_MAX_ITEMS) 
        cache_remove_oldest();

    return item;
}

int cache_insert(const char *url, const char *response_data)
{
    struct cache_item *item;
    u32 key = hash_fn(url);

    item = cache_lookup(url);
    if (item) {
        // RCU 安全的更新操作
        memset(item->response_data, 0, sizeof(item->response_data));
        strncat(item->response_data, response_data, sizeof(item->response_data));
        item->response_size = strlen(item->response_data);
        return 0;
    }

    item = cache_create_item(url);
    if (!item) {
        return -ENOMEM;
    }

    strncat(item->response_data, response_data, sizeof(item->response_data) - 1);
    item->response_size = strlen(item->response_data);

    // 使用 RCU 保护哈希表添加操作
    spin_lock(&my_cache.lock);
    hash_add_rcu(cache_table, &item->node, key);
    spin_unlock(&my_cache.lock);

    return 0;
}

void cache_clear(void)
{
    struct cache_item *item;
    struct hlist_node *tmp;
    int bkt;

    hash_for_each_safe(cache_table, bkt, tmp, item, node) {
        spin_lock(&my_cache.lock);
        hash_del_rcu(&item->node);
        list_del_rcu(&item->lru_node);
        spin_unlock(&my_cache.lock);

        call_rcu(&item->rcu, cache_rcu_free);
    }
    my_cache.cache_memcache->item_count = 0;
}

void cache_destroy(void)
{
    cache_clear();
    synchronize_rcu(); // 确保所有 RCU 回调完成
    memcache_destroy(my_cache.cache_memcache);
}
