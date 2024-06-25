#ifndef CACHE_H
#define CACHE_H

#include <linux/hashtable.h>
#include <linux/list.h>

#define CACHE_HASH_BITS 10 // 哈希表的位数

struct cache_item {
    char request_url[128];   // 缓存项的 URL
    char response_data[4096]; // 缓存的响应数据
    size_t response_size;    // 响应数据的大小
    size_t max_size;         // 响应数据的最大大小
    struct hlist_node node;  // 哈希表节点
    struct list_head lru_node; // 添加 lru_node 成员
};

void cache_init(void);
struct cache_item *cache_lookup(const char *url);
struct cache_item *cache_create_item(const char *url);
int cache_insert(const char *url, const char *response_data);
void cache_clear(void);

#endif // CACHE_H
