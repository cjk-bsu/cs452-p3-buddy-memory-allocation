#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif

#include "lab.h"

#define handle_error_and_die(msg)       \
    do {                                \
        perror(msg);                    \
        raise(SIGKILL);                 \
    } while (0)

/**
 * @brief Convert bytes to the smallest block size (power of two)
 *        such that block_size >= bytes, with a minimum of 2^SMALLEST_K.
 *
 * @param bytes the number of bytes required
 * @return size_t the block size (power-of-two value)
 */
 size_t btok(size_t bytes)
 {
    size_t k = 0;
    size_t block_size = 1;

    while (block_size < bytes && k < (8 * sizeof(size_t) - 1)) {
        block_size <<= 1;
        k++;
    }

    // Enforce minimum of SMALLEST_K
    if (k < SMALLEST_K)
        k = SMALLEST_K;

    return k;
 }

/**
 * @brief Given a block and its current kval, computes the address of its buddy.
 *
 * The buddy is calculated using XOR: the offset of the buddy from the base
 * is the offset of the block XOR 2^(kval). Bit shifting is used here.
 *
 * @param pool The memory pool containing the base address
 * @param buddy The block for which to compute the buddy
 * @return struct avail* Pointer to the buddy block
 */
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy)
{
    // Calculate current block size from the kval field: block size = 2^(kval)
    size_t block_size = ((size_t)1 << buddy->kval);
    // Compute offset from the beginning of the pool
    size_t offset = (size_t)((char *)buddy - (char *)pool->base);
    // Compute buddy's offset using XOR with the block size.
    size_t buddy_offset = offset ^ block_size;
    // Return the buddy pointer by adding the buddy offset to the pool base.
    return (struct avail *)((char *)pool->base + buddy_offset);
}

/**
 * @brief Allocates a block of size bytes from the buddy memory pool.
 *        Finds the smallest free block large enough, splitting larger blocks as needed.
 *
 * @param pool The memory pool to allocate from
 * @param size The number of bytes requested by the user
 * @return void* Pointer to the allocated block (includes header) or NULL on error.
 */
void *buddy_malloc(struct buddy_pool *pool, size_t size)
{
    if (pool == NULL || size == 0) {
        return NULL;
    }

    // Determine the required block size.
    // Here we assume that the header is stored within the block so that
    // the allocated block must be large enough to hold the requested size.
    size_t req_k = btok(size);
    if (req_k < SMALLEST_K)
        req_k = SMALLEST_K;

    // R1: Find a block in the free list at a level >= req_k.
    size_t i;
    for (i = req_k; i <= pool->kval_m; i++) {
        if (pool->avail[i].next != &pool->avail[i]) {
            break;
        }
    }
    if (i > pool->kval_m) {
        errno = ENOMEM;
        return NULL;
    }

    // R2: Remove the block from its free list.
    struct avail *block = pool->avail[i].next;
    block->prev->next = block->next;
    block->next->prev = block->prev;

    // R3 & R4: Split the block if it's larger than required.
    while (i > req_k) {
        // Decrement i to split block into two buddies.
        i--;
        // Compute the size for the split block: 2^(i)
        size_t split_size = ((size_t)1 << i);
        // The buddy block is the second half of the current block.
        struct avail *buddy = (struct avail *)((char *)block + split_size);
        // Set up the buddy block header.
        buddy->tag = BLOCK_AVAIL;
        buddy->kval = i;
        // Insert the buddy into the free list corresponding to level i.
        buddy->next = pool->avail[i].next;
        buddy->prev = &pool->avail[i];
        pool->avail[i].next->prev = buddy;
        pool->avail[i].next = buddy;

        // Update the current block's kval after splitting.
        block->kval = i;
    }

    // Mark the allocated block as reserved.
    block->tag = BLOCK_RESERVED;
    // Return the pointer to this block (which includes its header).
    return (void *)(block + 1);
}

/**
 * @brief Frees a previously allocated block, merging buddies if possible.
 *
 * When a block is freed, its buddy is computed. If the buddy is also free and
 * has the same size, the blocks are merged. This is repeated until no further
 * merging is possible.
 *
 * @param pool The memory pool from which the block was allocated.
 * @param ptr Pointer to the block to free.
 */
void buddy_free(struct buddy_pool *pool, void *ptr)
{
    if (ptr == NULL)
        return;

    // Get the block header from the pointer.
    struct avail *block = ((struct avail *)ptr) - 1;
    // Mark the block as available.
    block->tag = BLOCK_AVAIL;
    size_t k = block->kval;

    // Try to merge with buddies while possible.
    while (k < pool->kval_m) {
        // Calculate the buddy for the current block.
        struct avail *buddy = buddy_calc(pool, block);
        // If the buddy is not free or does not have the same block size, we cannot merge.
        if (buddy->tag != BLOCK_AVAIL || buddy->kval != k)
            break;

        // Remove buddy from its free list.
        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;

        // Choose the lower address as the start of the merged block.
        if (buddy < block)
            block = buddy;

        // Increase the block size level for the merged block.
        k++;
        block->kval = k;
    }

    // Insert the (possibly merged) block into the appropriate free list.
    block->next = pool->avail[k].next;
    block->prev = &pool->avail[k];
    pool->avail[k].next->prev = block;
    pool->avail[k].next = block;
}

/**
 * @brief Reallocates a previously allocated block to a new size.
 *        For a NULL pointer, this behaves like buddy_malloc.
 *        If size is zero and ptr is not NULL, free the block.
 *        Otherwise, a new block is allocated, the content is copied, and the old block is freed.
 *
 * @param pool The memory pool
 * @param ptr The pointer to the block to reallocate
 * @param size The new desired size
 * @return void* A pointer to the newly allocated (or resized) block.
 */
void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size)
{
    if (ptr == NULL)
        return buddy_malloc(pool, size);

    if (size == 0) {
        buddy_free(pool, ptr);
        return NULL;
    }

    // Get the header for the current block.
    struct avail *block = ((struct avail *)ptr) - 1;
    // Calculate the current block's size.
    size_t current_size = ((size_t)1 << block->kval);

    // Calculate the minimum kval required for the new size.
    size_t req_k = btok(size);
    if (req_k < SMALLEST_K)
        req_k = SMALLEST_K;
    size_t new_size = ((size_t)1 << req_k);

    // If the block sizes match, we can return the same pointer.
    if (new_size == current_size) {
        return ptr;
    } else if (new_size < current_size) {
        // Optionally, one could split the block and free the remainder.
        // For simplicity we leave the block as is.
        return ptr;
    } else {
        // Allocate a new block, copy the data, free the old block, and return the new pointer.
        void *new_ptr = buddy_malloc(pool, size);
        if (new_ptr) {
            // Copy the lesser of the old and new sizes.
            memcpy(new_ptr, ptr, current_size);
            buddy_free(pool, ptr);
        }
        return new_ptr;
    }
}

/**
 * @brief Initialize a new memory pool using the buddy algorithm.
 *        Rounds up the requested size to the nearest power of two.
 *
 * @param pool The pointer to the buddy_pool to initialize.
 * @param size The size of the pool in bytes. A value of 0 uses DEFAULT_K.
 */
void buddy_init(struct buddy_pool *pool, size_t size)
{
    size_t kval = 0;
    if (size == 0)
        kval = DEFAULT_K;
    else
        kval = btok(size);

    if (kval < MIN_K)
        kval = MIN_K;
    if (kval > MAX_K)
        kval = MAX_K - 1;

    // Clear the pool structure.
    memset(pool, 0, sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = ((size_t)1 << pool->kval_m);
    // Memory map a block of raw memory to manage.
    pool->base = mmap(
        NULL,                               /* addr to map to */
        pool->numbytes,                     /* length */
        PROT_READ | PROT_WRITE,             /* prot */
        MAP_PRIVATE | MAP_ANONYMOUS,        /* flags */
        -1,                                 /* fd (-1 for MAP_ANONYMOUS) */
        0                                   /* offset */
    );
    if (MAP_FAILED == pool->base)
    {
        handle_error_and_die("buddy_init avail array mmap failed");
    }

    // Initialize the free list array.
    for (size_t i = 0; i <= kval; i++)
    {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    // Insert the entire memory as one free block at the highest level.
    pool->avail[kval].next = pool->avail[kval].prev = (struct avail *)pool->base;
    struct avail *m = pool->avail[kval].next;
    m->tag = BLOCK_AVAIL;
    m->kval = kval;
    m->next = m->prev = &pool->avail[kval];
}

/**
 * @brief Destroys a buddy memory pool and frees the underlying mapped memory.
 *
 * @param pool The memory pool to destroy.
 */
void buddy_destroy(struct buddy_pool *pool)
{
    int rval = munmap(pool->base, pool->numbytes);
    if (-1 == rval)
    {
        handle_error_and_die("buddy_destroy avail array");
    }
    // Clear out the pool structure for reuse if needed.
    memset(pool, 0, sizeof(struct buddy_pool));
}

/* Utility function to print a 64-bit value in binary.
   Useful for debugging buddy_calc. */
int myMain(int argc, char** argv)
{
    // Example usage and test of buddy_malloc and buddy_free.
    struct buddy_pool pool;
    buddy_init(&pool, 0); // initialize with default size

    // Allocate 100 bytes.
    void *ptr = buddy_malloc(&pool, 100);
    if (ptr == NULL) {
        fprintf(stderr, "buddy_malloc failed\n");
        return 1;
    }
    printf("Allocated 100 bytes at %p\n", ptr);

    // Reallocate block to 200 bytes.
    void *new_ptr = buddy_realloc(&pool, ptr, 200);
    if (new_ptr == NULL) {
        fprintf(stderr, "buddy_realloc failed\n");
        return 1;
    }
    printf("Reallocated block to 200 bytes at %p\n", new_ptr);

    // Free the block.
    buddy_free(&pool, new_ptr);
    printf("Freed the block.\n");

    buddy_destroy(&pool);
    return 0;
}
