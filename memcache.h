#include <linux/list.h>

struct memcache {
    void **elements;
    size_t obj_size; /* object size */
    int cache_size;  /* pool size */
    int curr;        /* current available element count */
    struct list_head lru_list; // 用于维护 LRU 列表
    int item_count;            // 当前缓存项数量
};

struct memcache *memcache_create(size_t obj_size, int max_cache_size);
void memcache_destroy(struct memcache *cache);
void *memcache_alloc(struct memcache *cache);
void memcache_free(struct memcache *cache, void *element);
