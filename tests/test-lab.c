#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include "harness/unity.h"
#include "../src/lab.h"


void setUp(void) 
{
  // set stuff up here
}

void tearDown(void) 
{
  // clean stuff up here
}


/**
 * Check the pool to ensure it is full.
 */
void check_buddy_pool_full(struct buddy_pool *pool)
{
  //A full pool should have all values 0-(kval-1) as empty
  for (size_t i = 0; i < pool->kval_m; i++)
    {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
    }

  //The avail array at kval should have the base block
  assert(pool->avail[pool->kval_m].next->tag == BLOCK_AVAIL);
  assert(pool->avail[pool->kval_m].next->next == &pool->avail[pool->kval_m]);
  assert(pool->avail[pool->kval_m].prev->prev == &pool->avail[pool->kval_m]);

  //Check to make sure the base address points to the starting pool
  //If this fails either buddy_init is wrong or we have corrupted the
  //buddy_pool struct.
  assert(pool->avail[pool->kval_m].next == pool->base);
}

/**
 * Check the pool to ensure it is empty.
 */
void check_buddy_pool_empty(struct buddy_pool *pool)
{
  //An empty pool should have all values 0-(kval) as empty
  for (size_t i = 0; i <= pool->kval_m; i++)
    {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
    }
}

/**
 * Test allocating 1 byte to make sure we split the blocks all the way down
 * to MIN_K size. Then free the block and ensure we end up with a full
 * memory pool again
 */
void test_buddy_malloc_one_byte(void)
{
  fprintf(stderr, "->Test allocating and freeing 1 byte\n");
  struct buddy_pool pool;
  int kval = MIN_K;
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);
  void *mem = buddy_malloc(&pool, 1);
  //Make sure correct kval was allocated
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests the allocation of one massive block that should consume the entire memory
 * pool and makes sure that after the pool is empty we correctly fail subsequent calls.
 */
void test_buddy_malloc_one_large(void)
{
  fprintf(stderr, "->Testing size will consume entire memory pool\n");
  struct buddy_pool pool;
  size_t bytes = UINT64_C(1) << MIN_K;
  buddy_init(&pool, bytes);

  //Ask for an exact K value to be allocated. This test makes assumptions on
  //the internal details of buddy_init.
  size_t ask = bytes - sizeof(struct avail);
  void *mem = buddy_malloc(&pool, ask);
  assert(mem != NULL);

  //Move the pointer back and make sure we got what we expected
  struct avail *tmp = (struct avail *)mem - 1;
  assert(tmp->kval == MIN_K);
  assert(tmp->tag == BLOCK_RESERVED);
  check_buddy_pool_empty(&pool);

  //Verify that a call on an empty tool fails as expected and errno is set to ENOMEM.
  void *fail = buddy_malloc(&pool, 5);
  assert(fail == NULL);
  assert(errno = ENOMEM);

  //Free the memory and then check to make sure everything is OK
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests to make sure that the struct buddy_pool is correct and all fields
 * have been properly set kval_m, avail[kval_m], and base pointer after a
 * call to init
 */
void test_buddy_init(void)
{
  fprintf(stderr, "->Testing buddy_init\n");
  //Loop through all kval MIN_k-DEFAULT_K and make sure we get the correct amount allocated.
  //We will check all the pointer offsets to ensure the pool is all configured correctly
  for (size_t i = MIN_K; i <= DEFAULT_K; i++)
    {
      size_t size = UINT64_C(1) << i;
      struct buddy_pool pool;
      buddy_init(&pool, size);
      check_buddy_pool_full(&pool);
      buddy_destroy(&pool);
    }
}

void test_btok(void)
{
  fprintf(stderr, "->Testing btok ddge cases\n");
  TEST_ASSERT_EQUAL(SMALLEST_K, btok(1));
  TEST_ASSERT_EQUAL(11, btok(1025));
  TEST_ASSERT_EQUAL(20, btok(1 << 20));
  TEST_ASSERT_EQUAL(21, btok((1 << 20) + 1));
}

void test_multiple_allocs_and_frees(void)
{
  fprintf(stderr, "->Testing multiple allocs & frees w/ merges\n");
  struct buddy_pool pool;
  buddy_init(&pool, UINT64_C(1) << (SMALLEST_K + 2)); // enough space for 4 small blocks

  void *a = buddy_malloc(&pool, 8);
  void *b = buddy_malloc(&pool, 8);
  void *c = buddy_malloc(&pool, 8);
  void *d = buddy_malloc(&pool, 8);

  TEST_ASSERT_NOT_NULL(a);
  TEST_ASSERT_NOT_NULL(b);
  TEST_ASSERT_NOT_NULL(c);
  TEST_ASSERT_NOT_NULL(d);

  // Free in different order to check merge logic
  buddy_free(&pool, b);
  buddy_free(&pool, a);
  buddy_free(&pool, d);
  buddy_free(&pool, c);

  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

void test_null_and_zero_cases(void)
{
  fprintf(stderr, "->Testing NULL and zero-size inputs\n");

  void *mem = buddy_malloc(NULL, 100);
  TEST_ASSERT_NULL(mem);

  struct buddy_pool pool;
  buddy_init(&pool, UINT64_C(1) << MIN_K);

  mem = buddy_malloc(&pool, 0);
  TEST_ASSERT_NULL(mem);

  buddy_free(&pool, NULL);

  void *r = buddy_realloc(&pool, NULL, 128);
  TEST_ASSERT_NOT_NULL(r);
  buddy_free(&pool, r);

  r = buddy_realloc(&pool, r, 0);
  TEST_ASSERT_NULL(r);

  buddy_destroy(&pool);
}

void test_realloc_resize_up_and_down(void)
{
  fprintf(stderr, "->Testing realloc resizing\n");
  struct buddy_pool pool;
  buddy_init(&pool, UINT64_C(1) << MIN_K);

  void *ptr = buddy_malloc(&pool, 16);
  TEST_ASSERT_NOT_NULL(ptr);

  void *larger = buddy_realloc(&pool, ptr, 1024);
  TEST_ASSERT_NOT_NULL(larger);

  void *smaller = buddy_realloc(&pool, larger, 8);
  TEST_ASSERT_NOT_NULL(smaller);

  buddy_free(&pool, smaller);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

void test_randomized_alloc_free(void)
{
  fprintf(stderr, "->Testing randomized allocs & frees\n");
  struct buddy_pool pool;
  buddy_init(&pool, UINT64_C(1) << (SMALLEST_K + 6)); // 4KB pool

  const int num_ptrs = 128;
  void *ptrs[num_ptrs];
  memset(ptrs, 0, sizeof(ptrs));

  for (int i = 0; i < num_ptrs; ++i) {
    size_t size = rand() % 128 + 1;
    ptrs[i] = buddy_malloc(&pool, size);
    if (ptrs[i]) {
      struct avail *block = ((struct avail *)ptrs[i]) - 1;
      size_t block_size = (1UL << block->kval);
      size_t usable_size = block_size - sizeof(struct avail);
      memset(ptrs[i], (int)i, usable_size);
    }
  }

  for (int i = 0; i < num_ptrs; ++i) {
    int idx = rand() % num_ptrs;
    if (ptrs[idx]) {
      buddy_free(&pool, ptrs[idx]);
      ptrs[idx] = NULL;
    }
  }

  for (int i = 0; i < num_ptrs; ++i) {
    if (ptrs[i]) {
      buddy_free(&pool, ptrs[i]);
    }
  }

  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

void test_fragmentation_and_reuse(void)
{
  fprintf(stderr, "->Testing fragmentation and reuse\n");
  struct buddy_pool pool;
  buddy_init(&pool, UINT64_C(1) << (SMALLEST_K + 4)); // Small pool

  void *a = buddy_malloc(&pool, 32);
  void *b = buddy_malloc(&pool, 64);
  void *c = buddy_malloc(&pool, 32);
  buddy_free(&pool, b); // Free middle
  void *d = buddy_malloc(&pool, 64); // Should reuse b's space
  TEST_ASSERT_EQUAL_PTR(b, d);
  buddy_free(&pool, a);
  buddy_free(&pool, c);
  buddy_free(&pool, d);

  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}
void test_randomized_realloc(void)
{
  fprintf(stderr, "->Testing randomized reallocs\n");
  struct buddy_pool pool;
  buddy_init(&pool, UINT64_C(1) << (SMALLEST_K + 6)); // 4KB pool

  const int n = 64;
  void *ptrs[n];
  size_t sizes[n];
  memset(ptrs, 0, sizeof(ptrs));
  memset(sizes, 0, sizeof(sizes));

  for (int i = 0; i < n; i++) {
    sizes[i] = rand() % 64 + 1;
    ptrs[i] = buddy_malloc(&pool, sizes[i]);
    if (ptrs[i]) {
      struct avail *block = ((struct avail *)ptrs[i]) - 1;
      size_t block_size = (1UL << block->kval);
      size_t usable_size = block_size - sizeof(struct avail);
      memset(ptrs[i], i, usable_size);
    }
  }

  for (int i = 0; i < n; i++) {
    if (!ptrs[i]) continue;
    size_t new_size = (rand() % 64 + 1) * 2;
    void *new_ptr = buddy_realloc(&pool, ptrs[i], new_size);
    if (new_ptr) {
      struct avail *block = ((struct avail *)new_ptr) - 1;
      size_t block_size = (1UL << block->kval);
      size_t usable_size = block_size - sizeof(struct avail);
      memset(new_ptr, i, usable_size);
      ptrs[i] = new_ptr;
      sizes[i] = new_size;
    }
  }

  for (int i = 0; i < n; i++) {
    if (ptrs[i]) buddy_free(&pool, ptrs[i]);
  }

  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

int main(void) {
  time_t t;
  unsigned seed = (unsigned)time(&t);
  fprintf(stderr, "Random seed:%d\n", seed);
  srand(seed);
  printf("Running memory tests.\n");

  UNITY_BEGIN();
  RUN_TEST(test_buddy_init);
  RUN_TEST(test_buddy_malloc_one_byte);
  RUN_TEST(test_buddy_malloc_one_large);
  RUN_TEST(test_btok);
  RUN_TEST(test_multiple_allocs_and_frees);
  RUN_TEST(test_null_and_zero_cases);
  RUN_TEST(test_realloc_resize_up_and_down);
  RUN_TEST(test_randomized_alloc_free);
  RUN_TEST(test_fragmentation_and_reuse);
  RUN_TEST(test_randomized_realloc);
  UNITY_END();
}