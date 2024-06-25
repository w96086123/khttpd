#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include "memcache.h"

static inline void add_element(struct memcache *cache, void *element)
{
    if (cache->curr < cache->cache_size) {
        cache->elements[cache->curr++] = element;
        return;
    }

    kfree(element);
}

static inline void *remove_element(struct memcache *cache)
{
    return cache->elements[--cache->curr];
}

static void free_pool(struct memcache *cache)
{
    while (cache->curr) {
        void *element = remove_element(cache);
        kfree(element);
    }

    kfree(cache);
}

struct memcache *memcache_create(size_t obj_size, int max_cache_size)
{
    struct memcache *cache;
    size_t size;
    void *element;

    size = sizeof(struct memcache) + max_cache_size * sizeof(void *);
    cache = kmalloc(size, GFP_KERNEL);
    if (!cache)
        return NULL;

    cache->elements = (void **)((char *)cache + sizeof(struct memcache));
    cache->obj_size = obj_size;
    cache->cache_size = max_cache_size;
    cache->curr = 0;
    INIT_LIST_HEAD(&cache->lru_list);

    max_cache_size >>= 2;
    while (cache->curr < max_cache_size) {
        element = kmalloc(cache->obj_size, GFP_KERNEL);
        if (!element) {
            free_pool(cache);
            return NULL;
        }
        add_element(cache, element);
    }

    return cache;
}

void memcache_destroy(struct memcache *cache)
{
    free_pool(cache);
}

void *memcache_alloc(struct memcache *cache)
{
    return (cache->curr) ? remove_element(cache) : kmalloc(cache->obj_size, GFP_KERNEL);
}

void memcache_free(struct memcache *cache, void *element)
{
    add_element(cache, element);
}
