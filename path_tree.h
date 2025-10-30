
#ifndef HSV_PATH_TREE_H
#define HSV_PATH_TREE_H

#include <unistd.h>
#include <stdint.h>
// #include "hserv.h"

struct hsv_block_handler;

#define HSV_PATH_TREE_ROOT_SIZE 16
#define HSV_PATH_TREE_INLINE_ARRAY_SIZE 4

struct _hsv_path_tree_data_array_elem {
  const char* str;
  const uint16_t len;
  const struct _hsv_path_tree_node* child;
};

struct hsv_path_tree_data_array {
  uint16_t len;
  uint16_t size;
  struct _hsv_path_tree_data_array_elem* arr;  
};

struct _hsv_path_tree_data_map_elem {
  uint64_t hash;
  struct _hsv_path_tree_data_map_elem* next;
  // struct _hsv_path_tree_data_array_elem;
};

struct hsv_path_tree_data_map {
  uint16_t arr_size;
  struct _hsv_path_tree_data_map_elem arr;
};


enum hsv_path_tree_node_type : uint8_t {
  HSV_PATH_TREE_NODE_TYPE_ARRAY = 0,
  HSV_PATH_TREE_NODE_TYPE_MAP,
  HSV_PATH_TREE_NODE_TYPE_INLINE_ARRAY,
};

struct _hsv_path_tree_node {
  const char* same_same;
  size_t same_same_len;
  union {
    struct hsv_path_tree_data_array array;
    struct hsv_path_tree_data_map map;  
  } data;
};

struct hsv_path_tree_data_inline_array {
  uint8_t len;
  uint8_t size;
  struct _hsv_path_tree_node arr[HSV_PATH_TREE_INLINE_ARRAY_SIZE];
};

struct _hsv_path_tree_data_map_aux_arr {
  struct _hsv_path_tree_data_map_elem* arr;
  size_t aux_len;
  size_t aux_size;
};

struct hsv_path_tree {
  uint32_t flags;
  uint32_t _pad1;
  struct _hsv_path_tree_node root;
  struct _hsv_path_tree_data_map_aux_arr _map_aux_array;
};

int hsv_path_tree_init(struct hsv_path_tree* tree, struct hsv_block_handler* blocs, size_t blocs_len);
struct _hsv_path_tree_data_array_elem* hsv_path_tree_get(struct hsv_path_tree* tree, const char* const path, const size_t len);

#endif
