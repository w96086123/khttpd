#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hashtable.h>
#include "cache.h"
#include "memcache.h"

#define CACHE_MAX_ITEMS 100 // 定义缓存项的最大数量
DEFINE_HASHTABLE(cache_table, CACHE_HASH_BITS);

struct memcache *cache_memcache;

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
    cache_memcache = memcache_create(sizeof(struct cache_item), CACHE_MAX_ITEMS);
    if (!cache_memcache)
        pr_err("Failed to create memcache\n");
}

static void cache_remove_oldest(void)
{
    if (list_empty(&cache_memcache->lru_list))
        return;

    struct cache_item *item;

    item = list_last_entry(&cache_memcache->lru_list, struct cache_item, lru_node);
    hash_del(&item->node);
    list_del(&item->lru_node);
    memcache_free(cache_memcache, item);
    cache_memcache->item_count--;
}

struct cache_item *cache_lookup(const char *url)
{
    struct cache_item *item;
    u32 key = hash_fn(url);

    hash_for_each_possible(cache_table, item, node, key) {
        if (strcmp(item->request_url, url) == 0) {
            // 移动缓存项到 LRU 列表的头部
            list_move(&item->lru_node, &cache_memcache->lru_list);
            return item;
        }
    }
    return NULL;
}

struct cache_item *cache_create_item(const char *url)
{
    struct cache_item *item = memcache_alloc(cache_memcache);
    if (!item) {
        pr_err("Failed to allocate memory for cache_item\n");
        return NULL;
    }

    strncpy(item->request_url, url, sizeof(item->request_url) - 1);
    item->request_url[sizeof(item->request_url) - 1] = '\0'; // 确保字符串以 null 结尾
    memset(item->response_data, 0, sizeof(item->response_data));
    item->response_size = 0;
    item->max_size = sizeof(item->response_data);

    // 初始化 LRU 节点并添加到 LRU 列表头部
    INIT_LIST_HEAD(&item->lru_node);
    list_add(&item->lru_node, &cache_memcache->lru_list);
    cache_memcache->item_count++;

    // 如果超过最大缓存项数量，移除最旧的缓存项
    if (cache_memcache->item_count > CACHE_MAX_ITEMS) {
        cache_remove_oldest();
    }

    return item;
}

int cache_insert(const char *url, const char *response_data)
{
    struct cache_item *item;
    u32 key = hash_fn(url);

    item = cache_lookup(url);
    if (item) {
        memset(item->response_data, 0, sizeof(item->response_data));
        strncat(item->response_data, response_data, sizeof(item->response_data) - 1);
        item->response_size = strlen(item->response_data);
        return 0;
    }

    item = cache_create_item(url);
    if (!item) {
        return -ENOMEM;
    }

    strncat(item->response_data, response_data, sizeof(item->response_data) - 1);
    item->response_size = strlen(item->response_data);
    hash_add(cache_table, &item->node, key);
    return 0;
}

void cache_clear(void)
{
    struct cache_item *item;
    struct hlist_node *tmp;
    int bkt;

    hash_for_each_safe(cache_table, bkt, tmp, item, node) {
        hash_del(&item->node);
        list_del(&item->lru_node);
        memcache_free(cache_memcache, item);
    }
    cache_memcache->item_count = 0;
}

void cache_destroy(void)
{
    cache_clear();
    memcache_destroy(cache_memcache);
}