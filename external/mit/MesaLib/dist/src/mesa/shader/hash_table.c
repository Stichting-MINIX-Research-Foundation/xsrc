/*
 * Copyright © 2008 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/**
 * \file hash_table.c
 * \brief Implementation of a generic, opaque hash table data type.
 *
 * \author Ian Romanick <ian.d.romanick@intel.com>
 */

#include "main/imports.h"
#include "main/simple_list.h"
#include "hash_table.h"

struct node {
   struct node *next;
   struct node *prev;
};

struct hash_table {
    hash_func_t    hash;
    hash_compare_func_t  compare;

    unsigned num_buckets;
    struct node buckets[1];
};


struct hash_node {
    struct node link;
    const void *key;
    void *data;
};


struct hash_table *
hash_table_ctor(unsigned num_buckets, hash_func_t hash,
                hash_compare_func_t compare)
{
    struct hash_table *ht;
    unsigned i;


    if (num_buckets < 16) {
        num_buckets = 16;
    }

    ht = malloc(sizeof(*ht) + ((num_buckets - 1) 
				     * sizeof(ht->buckets[0])));
    if (ht != NULL) {
        ht->hash = hash;
        ht->compare = compare;
        ht->num_buckets = num_buckets;

        for (i = 0; i < num_buckets; i++) {
            make_empty_list(& ht->buckets[i]);
        }
    }

    return ht;
}


void
hash_table_dtor(struct hash_table *ht)
{
   hash_table_clear(ht);
   free(ht);
}


void
hash_table_clear(struct hash_table *ht)
{
   struct node *node;
   struct node *temp;
   unsigned i;


   for (i = 0; i < ht->num_buckets; i++) {
      foreach_s(node, temp, & ht->buckets[i]) {
	 remove_from_list(node);
	 free(node);
      }

      assert(is_empty_list(& ht->buckets[i]));
   }
}


void *
hash_table_find(struct hash_table *ht, const void *key)
{
    const unsigned hash_value = (*ht->hash)(key);
    const unsigned bucket = hash_value % ht->num_buckets;
    struct node *node;

    foreach(node, & ht->buckets[bucket]) {
       struct hash_node *hn = (struct hash_node *) node;

       if ((*ht->compare)(hn->key, key) == 0) {
	  return hn->data;
       }
    }

    return NULL;
}


void
hash_table_insert(struct hash_table *ht, void *data, const void *key)
{
    const unsigned hash_value = (*ht->hash)(key);
    const unsigned bucket = hash_value % ht->num_buckets;
    struct hash_node *node;

    node = calloc(1, sizeof(*node));

    node->data = data;
    node->key = key;

    insert_at_head(& ht->buckets[bucket], & node->link);
}


unsigned
hash_table_string_hash(const void *key)
{
    const char *str = (const char *) key;
    unsigned hash = 5381;


    while (*str != '\0') {
        hash = (hash * 33) + *str;
        str++;
    }

    return hash;
}
