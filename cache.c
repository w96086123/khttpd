#include <linux/slab.h>
#include <linux/string.h>
#include "cache.h"

DEFINE_HASHTABLE(cache_table, CACHE_HASH_BITS);

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
}

struct cache_item *cache_lookup(const char *url)
{
    struct cache_item *item;
    u32 key = hash_fn(url);

    hash_for_each_possible(cache_table, item, node, key) {
        if (strcmp(item->request_url, url) == 0) {
            return item;
        }
    }
    return NULL;
}

struct cache_item *cache_create_item(const char *url)
{
    struct cache_item *item = kmalloc(sizeof(struct cache_item), GFP_KERNEL);
    if (!item) {
        pr_err("Failed to allocate memory for cache_item\n");
        return NULL;
    }

    strncpy(item->request_url, url, sizeof(item->request_url));
    memset(item->response_data, 0, sizeof(item->response_data));
    item->response_size = 0;
    item->max_size = sizeof(item->response_data); // 设置最大缓存大小

    return item;
}

int cache_insert(const char *url, const char *response_data)
{
    struct cache_item *item;
    u32 key = hash_fn(url);

    // 先查找缓存项是否存在
    item = cache_lookup(url);
    if (item) {
        // 如果存在，更新缓存项数据
        memset(item->response_data, 0, sizeof(item->response_data));
        strncat(item->response_data, response_data, sizeof(item->response_data) - 1);
        item->response_size = strlen(item->response_data);
        return 0;
    }

    // 如果不存在，创建新的缓存项
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
        kfree(item);
    }
}
