#include "path_tree.h"
#include <sys/mman.h>
#include <stdlib.h>

// struct _hsv_path_tree_init_sort_elem {
//   const char* path;
//   size_t path_len;
// };


#define SortElem hsv_block_handler

int _hsv_path_tree_data_array_elem_cmp(const void* _a, const void* _b) {
  const struct SortElem *a = (struct SortElem *)_a, *b = (struct SortElem *)_b; 
  size_t cmp_len = (a->path_len < b->path_len) ? a->path_len : b->path_len;
  return strncmp(a->path_str, b->path_str, cmp_len);
}

static size_t _hsv_get_largest_common_path_len(struct SortElem* sort_array, size_t sa_len) {
  const char* const lcp = sort_array[0].path;
  size_t lcp_len = sort_array[0].path_len;

  for (size_t i = 1; i < sa_len; ++i) {
    struct SortElem *se = sort_array + i;
    if (se->path_len < lcp_len) {
      lcp_len = se->path_len;
    }
    for (size_t indx = 0; i < lcp_len; ++indx) {
      if (lcp[indx] != se->path[i]) {
        lcp_len = indx;
        break;
      }
    }
  }
  
  return lcp_len;
}


int hsv_path_tree_init(struct hsv_path_tree* tree, struct hsv_block_handler* blocks, size_t blocks_nr) {
 
  size_t asize = blocks_nr * sizeof(struct SortElem);
  struct SortElem* sort_array = (struct SortElem*) mmap(NULL, asize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); 
  
  for (size_t i = 0; i < blocks_nr; ++i) {
    struct hsv_block_handler* block = blocks + i;
    const char*  path = block->path_str;
    const size_t len = block->path_len;
    *(sort_array+i) = (struct SortElem) {.path = path, .path_len = len};
  }

  qsort(sort_array, blocks_nr, sizeof(struct SortElem), _hsv_path_tree_data_array_elem_cmp);

  struct _hsv_path_tree_node *root = &tree->root;  
  struct _hsv_path_tree_node *node = root;

  size_t lcp_len = _hsv_get_largest_common_path_len(sort_array, blocks_nr);
  if (lcp_len > 1) {
    node->same_same_len = lcp_len;
  }

  

  return 0;
}

struct _hsv_path_tree_data_array_elem* hsv_path_tree_get(struct hsv_path_tree* tree, const char* const path, const size_t len) {
  
}

