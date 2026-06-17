/*
 * Van GW Software, Copyright © 2019 COMMUNICATION INDUSTRY INSTITUTION.
 * 
 * The contents of this file are protected by copyright laws and international treaties.
 * Any reproduction or distribution of this file or any portion of this file, in any form by any means, 
 * without the prior written consent of COMMUNICATION INDUSTRY INSTITUTION is prohibited. 
 * Additionally, the contents of this file are protected by contractual confidentiality obligations.
 * All company, brand and product names are trade or service marks, or registered trade or service marks, 
 * of COMMUNICATION INDUSTRY INSTITUTION or of their respective owners.
 * This document is provided “as is”, and all express, implied, or statutory warranties, 
 * representations or conditions are disclaimed, including without limitation any implied warranty of merchantability, 
 * fitness for a particular purpose, title or non-infringement. 
 * COMMUNICATION INDUSTRY INSTITUTION and its licensor shall not be liable for damages 
 * resulting from the use of or reliance on the information contained herein.
 * COMMUNICATION INDUSTRY INSTITUTION or its licensor may have current or pending intellectual property rights or 
 * applications covering the subject matter of this file.
 *
 * ------------------------------------------------------------
 * Consultant
 * Please inform development team of all your questions and problems.
 * Address: Ryongnam Dong, Daesong District, Pyongyang
 * Tel No: 02-551-2832, Email: white_night@rns.edu.kp
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "triton.h"
#include "myhashtable.h"


//------------------------------------------------------------------------------
/*
   Default hash function
   def_hashfunc() is the default used by hashtable_create() when the user didn't specify one.
   This is a simple/naive hash function which adds the key's ASCII char values. It will probably generate lots of collisions on large hash tables.
*/

static uint64_t
def_hashfunc_obj (
  const void *const keyP,
  const int key_sizeP)
{
  uint64_t                  hash = 0;
  int                       key_size = key_sizeP;

  // may use MD4 ?
  while (key_size > 0) {
    uint64_t val = 0;
    int      size = sizeof(val);
    while ((size > 0) && (key_size > 0)) {
      val = val << 8;
      val |= ((uint8_t*)keyP)[key_size - 1];
      size--;
      key_size--;
    }
    hash ^= val;
  }

  return hash;
}

static inline int def_cmpfunc_obj(const void *const a, const void *const b, const int size)
{
	return memcmp(a, b, size);
}

//------------------------------------------------------------------------------
/*
   Default hash function
   def_hashfunc() is the default used by hashtable_ts_init() when the user didn't specify one.
   This is a simple/naive hash function which adds the key's ASCII char values. It will probably generate lots of collisions on large hash tables.
*/
static inline u32 def_hashfunc (const u32 keyP)
{
  return keyP;
}

static inline uint64_t def_hashfunc64 (const uint64_t keyP)
{
  return keyP;
}

static inline void def_freefunc(void **data)
{
	free(*data);
}

//------------------------------------------------------------------------------
void __export obj_hashtable_ts_init (obj_hash_table_t * hashtblP,
    const hash_size_t sizeP,
    uint64_t (*hashfuncP) (const void *, int),
    int (*cmpfuncP) (const void *, const void *, int),
    void (*freefuncP) (void **),
    char *tablename)
{
  hash_size_t size = sizeP;
  size--;
  size |= size >> 1;
  size |= size >> 2;
  size |= size >> 4;
  size |= size >> 8;
  size |= size >> 16;
  size++;
  
  memset(hashtblP, 0, sizeof(*hashtblP));

  if (!(hashtblP->nodes = calloc (size, sizeof (obj_hash_node_t *)))) {
    return;
  }

  if (!(hashtblP->lock_nodes = calloc (size, sizeof (pthread_mutex_t)))) {
    return;
  }

  for (int i = 0; i < size; i++) {
    pthread_mutex_init(&hashtblP->lock_nodes[i], NULL);
  }

  hashtblP->size = size;

  if (hashfuncP)
    hashtblP->hashfunc = hashfuncP;
  else
    hashtblP->hashfunc = def_hashfunc_obj;

  if (cmpfuncP)
    hashtblP->cmpfunc = cmpfuncP;
  else
    hashtblP->cmpfunc = def_cmpfunc_obj;

  if (freefuncP)
    hashtblP->freefunc = freefuncP;
  else
    hashtblP->freefunc = NULL;
  
  hashtblP->name = strdup(tablename);
}

//------------------------------------------------------------------------------
/*
   Adding a new element
   To make sure the hash value is not bigger than size, the result of the user provided hash function is used modulo size.
*/
hashtable_rc_t __export
obj_hashtable_ts_insert (
  obj_hash_table_t * hashtblP,
  const void *const keyP,
  const int key_sizeP,
  void *dataP)
{
  obj_hash_node_t                     *node = NULL;
  uint64_t                             hash = 0;

  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  if(keyP == NULL)
  	return HASH_TABLE_BAD_PARAMETER_HASHTABLE;

  hash = hashtblP->hashfunc(keyP, key_sizeP) % hashtblP->size;
  pthread_mutex_lock(&hashtblP->lock_nodes[hash]);
  node = hashtblP->nodes[hash];

  /*const u8 *k1 = (const u8*)keyP;
  fprintf(stderr, " ##(insert) keysize: %d, keyP : ", key_sizeP);
  for(int j = 0; j < 8; j++) {
    fprintf(stderr, "%02x%02x:", k1[j*2], k1[j*2+1]);
  }
  fprintf(stderr, "\n");*/

  while (node) {
    /*const u8* k2 = (const u8*)node->key;
    fprintf(stderr, " ##(insert) node->key_size: %d, node->key : ", node->key_size);
    for(int j = 0; j < 8; j++) {
      fprintf(stderr, "%02x%02x:", k2[j*2], k2[j*2+1]);
    }
    fprintf(stderr, "\n\n\n");*/
  	if ((node->key_size == key_sizeP) && (hashtblP->cmpfunc(node->key, keyP, key_sizeP) == 0) ){
      if ((node->data) && (node->data != dataP)) {
        //fprintf(stderr,"%s, %d, free(node->data);\n", __FILE__, __LINE__);
        if(hashtblP->freefunc) {
          hashtblP->freefunc(&node->data);
            node->data = dataP;
        }
        pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
        //fprintf(stderr,"%s(key %p data %p) return INSERT_OVERWRITTEN_DATA\n", __FUNCTION__, keyP, dataP);
        return HASH_TABLE_INSERT_OVERWRITTEN_DATA;
      }
      node->data = dataP;
      pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
      //fprintf(stderr,"%s(key %p data %p) return HASH_TABLE_OK\n", __FUNCTION__, keyP, dataP);
      return HASH_TABLE_OK;
  	}
	
    node = node->next;
  }
//  printf("%s, %d, node = malloc (sizeof (hash_node_t))\n", __FILE__, __LINE__);
  if (!(node = calloc (1, sizeof (obj_hash_node_t)))) {
  	pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
    return -1;
  }

  if (!(node->key = calloc (1, key_sizeP))) {
	  free(node);
	  pthread_mutex_unlock (&hashtblP->lock_nodes[hash]);
	  //fprintf(stderr,"%s(%s,key %p) hash %x return SYSTEM_ERROR\n", __FUNCTION__, hashtblP->name, keyP, hash);
	  return HASH_TABLE_SYSTEM_ERROR;
  }

  memcpy (node->key, keyP, key_sizeP);
  node->data = dataP;
  node->key_size = key_sizeP;

  if (hashtblP->nodes[hash]) {
    node->next = hashtblP->nodes[hash];
  } else {
    node->next = NULL;
  }

  hashtblP->nodes[hash] = node;
  hashtblP->num_elements++;
  pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
  //fprintf(stderr,"%s(hash %u key %p data %p) next %p return HASH_TABLE_OK\n", __FUNCTION__, hash, node->key, dataP, node->next);
  return HASH_TABLE_OK;
}

//------------------------------------------------------------------------------
/*
   To free_wrapper an element from the hash table, we just search for it in the linked list for that hash value,
   and free_wrapper it if it is found. If it was not found, it is an error and -1 is returned.
*/
hashtable_rc_t __export
obj_hashtable_ts_free (
  obj_hash_table_t * hashtblP,
  const void *const keyP,
  const int key_sizeP)
{
  obj_hash_node_t                     *node,
                                         *prevnode = NULL;
  uint64_t                                 hash = 0;

  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  hash = hashtblP->hashfunc(keyP, key_sizeP) % hashtblP->size;
  pthread_mutex_lock(&hashtblP->lock_nodes[hash]);
  node = hashtblP->nodes[hash];

  while (node) {
  	if ((node->key_size == key_sizeP) && (hashtblP->cmpfunc(node->key, keyP, key_sizeP) == 0) ){
      if (prevnode)
        prevnode->next = node->next;
      else
        hashtblP->nodes[hash] = node->next;

	  if (node->key) {
	  	free(node->key);
		node->key = NULL;
	  }
      if (node->data && hashtblP->freefunc) {
//	  	printf("%s, %d, free(node->data);\n", __FILE__, __LINE__);
        hashtblP->freefunc(&node->data);
        node->data = NULL;
      }
//	  printf("%s, %d, free(node);\n", __FILE__, __LINE__);
      free(node);
	  node=NULL;
      hashtblP->num_elements--;
      pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
      //printf("%s(key 0x%x) return OK\n", __FUNCTION__, keyP);
      return HASH_TABLE_OK;
    }

    prevnode = node;
    node = node->next;
  }

   pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
   //printf("%s(key 0x%x) return KEY_NOT_EXISTS\n", __FUNCTION__, keyP);
  return HASH_TABLE_KEY_NOT_EXISTS;
}

//------------------------------------------------------------------------------
/*
   Searching for an element is easy. We just search through the linked list for the corresponding hash value.
   NULL is returned if we didn't find it.
*/
hashtable_rc_t __export
obj_hashtable_ts_get (
  obj_hash_table_t * hashtblP,
  const void *const keyP,
  const int key_sizeP,
  void **dataP)
{
  obj_hash_node_t                 *node = NULL;
  uint64_t                             hash = 0;

  *dataP = NULL;
  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  hash = hashtblP->hashfunc(keyP, key_sizeP) % hashtblP->size;

  pthread_mutex_lock(&hashtblP->lock_nodes[hash]);
  node = hashtblP->nodes[hash];
  //printf("hash #@#: %d\n", hash);

  /*const u8 *k1 = (const u8*)keyP;
  fprintf(stderr, " ##(get) keysize: %d, keyP : ", key_sizeP);
  for(int j = 0; j < 8; j++) {
    fprintf(stderr, "%02x%02x:", k1[j*2], k1[j*2+1]);
  }
  fprintf(stderr, "\n");*/
  

  while (node) {
  	/*const u8* k2 = (const u8*)node->key;
    fprintf(stderr, " ##(get) node->key_size: %d, node->key : ", node->key_size);
    for(int j = 0; j < 8; j++) {
      fprintf(stderr, "%02x%02x:", k2[j*2], k2[j*2+1]);
    }
    fprintf(stderr, "\n");*/
  	if ( (node->key_size == key_sizeP) && (hashtblP->cmpfunc(node->key, keyP, key_sizeP) == 0) ){
      *dataP = node->data;
	  //printf("%s, key = %u, lock\n", hashtblP->name, keyP);
      //pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
      //printf("%s(key 0x%x data %p) return OK\n", __FUNCTION__, keyP, *dataP);
      return HASH_TABLE_OK;
    }

    node = node->next;
  }
  pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
  //fprintf(stderr,"%s(key %p) return KEY_NOT_EXISTS\n", __FUNCTION__, keyP);

  return HASH_TABLE_KEY_NOT_EXISTS;
}

//------------------------------------------------------------------------------
/*
   Searching for an element is easy. We just search through the linked list for the corresponding hash value.
   NULL is returned if we didn't find it.
*/
hashtable_rc_t __export
obj_hashtable_ts_get_no_mutex (
  obj_hash_table_t * hashtblP,
  const void *const keyP,
  const int key_sizeP,
  void **dataP)
{
  obj_hash_node_t                 *node = NULL;
  uint64_t                             hash = 0;

  *dataP = NULL;
  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  hash = hashtblP->hashfunc(keyP, key_sizeP) % hashtblP->size;

  node = hashtblP->nodes[hash];

  while (node) {
  	if ( (node->key_size == key_sizeP) && (hashtblP->cmpfunc(node->key, keyP, key_sizeP) == 0) ){
      *dataP = node->data;
      return HASH_TABLE_OK;
    }

    node = node->next;
  }

  return HASH_TABLE_KEY_NOT_EXISTS;
}

hashtable_rc_t __export
obj_hashtable_ts_nodes_lock (
  obj_hash_table_t * hashtblP,
  const void *const keyP,
  const int key_sizeP)
{
	uint64_t 							hash = 0;
  if(keyP == NULL)
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
	if (!hashtblP) {
	  return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
	}
	//printf("%s, key = %u, unlock\n", hashtblP->name, keyP);
	hash = hashtblP->hashfunc(keyP, key_sizeP) % hashtblP->size;
	pthread_mutex_lock(&hashtblP->lock_nodes[hash]);
	return HASH_TABLE_OK;
}  
	
hashtable_rc_t __export
obj_hashtable_ts_nodes_unlock (
  obj_hash_table_t * hashtblP,
  const void *const keyP,
  const int key_sizeP)
{
	uint64_t 							hash = 0;
  if(keyP == NULL)
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
	if (!hashtblP) {
	  return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
	}
	//printf("%s, key = %u, unlock\n", hashtblP->name, keyP);
	hash = hashtblP->hashfunc(keyP, key_sizeP) % hashtblP->size;
	pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
	return HASH_TABLE_OK;
}  
  
/*   Initialization
   hashtable_ts_init() sets up the initial structure of the thread safe hash table. The user specified size will be allocated and initialized to NULL.
   The user can also specify a hash function. If the hashfunc argument is NULL, a default hash function is used.
   If an error occurred, NULL is returned. All other values in the returned hash_table_t pointer should be released with hashtable_destroy().
*/
//------------------------------------------------------------------------------
/*
   Cleanup
   The hashtable_destroy() walks through the linked lists for each possible hash value, and releases the elements. It also releases the nodes array and the obj_hash_table_t.
*/
hashtable_rc_t __export
obj_hashtable_ts_destroy (
  obj_hash_table_t * const hashtblP)
{
  size_t                                 n;
  obj_hash_node_t                     *node,
                                         *oldnode;

  for (n = 0; n < hashtblP->num_elements; ++n) {
    pthread_mutex_lock (&hashtblP->lock_nodes[n]);
    node = hashtblP->nodes[n];

    while (node) {
      oldnode = node;
      node = node->next;
      //hashtblP->freekeyfunc (&oldnode->key);
      //hashtblP->freedatafunc (&oldnode->data);
      if (oldnode->key) {
        free (oldnode->key);
        oldnode->key = NULL;
      }
      if (oldnode->data && hashtblP->freefunc) {
        hashtblP->freefunc (&oldnode->data);
        oldnode->data = NULL;
      }
      free (oldnode);
    }
    pthread_mutex_unlock (&hashtblP->lock_nodes[n]);
    pthread_mutex_destroy (&hashtblP->lock_nodes[n]);
  }

  free (hashtblP->nodes);
  free(hashtblP->lock_nodes);
  
  if (hashtblP->name) {
    free(hashtblP->name);
    hashtblP->name = NULL;
  }
  
  //free (hashtblP);
  
  return HASH_TABLE_OK;
}

void __export hashtable_ts_init (hash_table_t * const hashtblP,
    const hash_size_t sizeP,
    u32 (*hashfuncP) (const u32), void (*freefuncP) (void **),
    char *tablename)
{
  hash_size_t size = sizeP;
  size--;
  size |= size >> 1;
  size |= size >> 2;
  size |= size >> 4;
  size |= size >> 8;
  size |= size >> 16;
  size++;
  
  memset(hashtblP, 0, sizeof(*hashtblP));

  if (!(hashtblP->nodes = calloc (size, sizeof (hash_node_t *)))) {
    return;
  }

  if (!(hashtblP->lock_nodes = calloc (size, sizeof (pthread_mutex_t)))) {
    return;
  }

  for (int i = 0; i < size; i++) {
    pthread_mutex_init(&hashtblP->lock_nodes[i], NULL);
  }

  hashtblP->size = size;

  if (hashfuncP)
    hashtblP->hashfunc = hashfuncP;
  else
    hashtblP->hashfunc = def_hashfunc;

  if (freefuncP)
    hashtblP->freefunc = freefuncP;
  else
    hashtblP->freefunc = NULL;

  hashtblP->name = strdup(tablename);
}
	
void __export hashtable64_ts_init (hash64_table_t * const hashtblP,
    const hash_size_t sizeP,
    u64 (*hashfuncP) (const u64), void (*freefuncP) (void **),
    char *tablename)
{
  hash_size_t size = sizeP;
  size--;
  size |= size >> 1;
  size |= size >> 2;
  size |= size >> 4;
  size |= size >> 8;
  size |= size >> 16;
  size++;
  
  memset(hashtblP, 0, sizeof(*hashtblP));

  if (!(hashtblP->nodes = calloc (size, sizeof (hash64_node_t *)))) {
    return;
  }

  if (!(hashtblP->lock_nodes = calloc (size, sizeof (pthread_mutex_t)))) {
    return;
  }

  for (int i = 0; i < size; i++) {
    pthread_mutex_init(&hashtblP->lock_nodes[i], NULL);
  }

  hashtblP->size = size;

  if (hashfuncP)
    hashtblP->hashfunc = hashfuncP;
  else
    hashtblP->hashfunc = def_hashfunc64;

  if (freefuncP)
    hashtblP->freefunc = freefuncP;
  else
    hashtblP->freefunc = NULL;
  
  hashtblP->name = strdup(tablename);
}

//------------------------------------------------------------------------------
/*
   Adding a new element
   To make sure the hash value is not bigger than size, the result of the user provided hash function is used modulo size.
*/
hashtable_rc_t __export
hashtable_ts_insert (
  hash_table_t * const hashtblP,
  u32 keyP,
  void *dataP)
{
  hash_node_t                     *node = NULL;
  u32                             hash = 0;

  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  hash = hashtblP->hashfunc(keyP) % hashtblP->size;
  pthread_mutex_lock(&hashtblP->lock_nodes[hash]);
  node = hashtblP->nodes[hash];

  while (node) {
  	if (node->key == keyP) {
      if ((node->data) && (node->data != dataP)) {
//		  printf("%s, %d, free(node->data);\n", __FILE__, __LINE__);
        if(hashtblP->freefunc) {
          hashtblP->freefunc(&node->data);
          node->data = dataP;
        }
        pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
        //printf("%s(key 0x%x data %p) return INSERT_OVERWRITTEN_DATA\n", __FUNCTION__, keyP, dataP;
        return HASH_TABLE_INSERT_OVERWRITTEN_DATA;
      }
      node->data = dataP;
      pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
      //printf("%s(key 0x%x data %p) return HASH_TABLE_OK\n", __FUNCTION__, keyP, dataP);
      return HASH_TABLE_OK;
  	}
	
    node = node->next;
  }
//  printf("%s, %d, node = malloc (sizeof (hash_node_t))\n", __FILE__, __LINE__);
  if (!(node = malloc (sizeof (hash_node_t)))) {
  	pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
    return -1;
  }

  node->key = keyP;
  node->data = dataP;

  if (hashtblP->nodes[hash]) {
    node->next = hashtblP->nodes[hash];
  } else {
    node->next = NULL;
  }

  hashtblP->nodes[hash] = node;
  hashtblP->num_elements++;
  pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
  //printf("%s(key 0x%x data %p) next %p return HASH_TABLE_OK\n", __FUNCTION__, keyP, dataP, node->next);
  return HASH_TABLE_OK;
}

hashtable_rc_t __export
hashtable64_ts_insert (
  hash64_table_t * const hashtblP,
  u64 keyP,
  void *dataP)
{
  hash64_node_t                     *node = NULL;
  u64                             hash = 0;

  //printf("hashtable64_ts_insert                  1\n");
  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  //printf("hashtable64_ts_insert                  2\n");

  hash = hashtblP->hashfunc(keyP) % hashtblP->size;
  pthread_mutex_lock(&hashtblP->lock_nodes[hash]);
  node = hashtblP->nodes[hash];

  //printf("hashtable64_ts_insert                  3\n");

  while (node) {
  	if (node->key == keyP) {
      if ((node->data) && (node->data != dataP)) {
//		printf("%s, %d, free(node->data);\n", __FILE__, __LINE__);
        if(hashtblP->freefunc) {
          hashtblP->freefunc(&node->data);
          node->data = dataP;
        }
        //printf("hashtable64_ts_insert                  4\n");
        pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
        //printf("%s(key 0x%x data %p) return INSERT_OVERWRITTEN_DATA\n", __FUNCTION__, keyP, dataP;
        return HASH_TABLE_INSERT_OVERWRITTEN_DATA;
      }
      node->data = dataP;
      //printf("hashtable64_ts_insert                  5\n");
      pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
      //printf("%s(key 0x%x data %p) return HASH_TABLE_OK\n", __FUNCTION__, keyP, dataP);
      return HASH_TABLE_OK;
  	}
	
    node = node->next;
  }
//  printf("%s, %d, node = malloc (sizeof (hash_node_t))\n", __FILE__, __LINE__);
  //printf("hashtable64_ts_insert                  6\n");

  if (!(node = malloc (sizeof (hash64_node_t)))) {
  	pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
    return -1;
  }
  //printf("hashtable64_ts_insert                  7\n");

  node->key = keyP;
  node->data = dataP;

  if (hashtblP->nodes[hash]) {
    node->next = hashtblP->nodes[hash];
  } else {
    node->next = NULL;
  }

  hashtblP->nodes[hash] = node;
  hashtblP->num_elements++;
  //printf("hashtable64_ts_insert                  8\n");
  pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
  //printf("%s(key 0x%x data %p) next %p return HASH_TABLE_OK\n", __FUNCTION__, keyP, dataP, node->next);
  //printf("hashtable64_ts_insert                  9\n");
  return HASH_TABLE_OK;
}

//------------------------------------------------------------------------------
/*
   To free_wrapper an element from the hash table, we just search for it in the linked list for that hash value,
   and free_wrapper it if it is found. If it was not found, it is an error and -1 is returned.
*/
hashtable_rc_t __export
hashtable_ts_free (
  hash_table_t * const hashtblP,
  const u32 keyP)
{
  hash_node_t                     *node,
                                         *prevnode = NULL;
  u32                                 hash = 0;

  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  hash = hashtblP->hashfunc(keyP) % hashtblP->size;
  pthread_mutex_lock(&hashtblP->lock_nodes[hash]);
  node = hashtblP->nodes[hash];

  while (node) {
    if (node->key == keyP) {
      if (prevnode)
        prevnode->next = node->next;
      else
        hashtblP->nodes[hash] = node->next;

      if (node->data && hashtblP->freefunc) {
//	  	printf("%s, %d, free(node->data);\n", __FILE__, __LINE__);
        hashtblP->freefunc(&node->data);
        node->data = NULL;
      }
//	  printf("%s, %d, free(node);\n", __FILE__, __LINE__);
      free(node);
	  node=NULL;
      hashtblP->num_elements--;
      pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
      //printf("%s(key 0x%x) return OK\n", __FUNCTION__, keyP);
      return HASH_TABLE_OK;
    }

    prevnode = node;
    node = node->next;
  }

   pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
   //printf("%s(key 0x%x) return KEY_NOT_EXISTS\n", __FUNCTION__, keyP);
  return HASH_TABLE_KEY_NOT_EXISTS;
}

hashtable_rc_t __export
hashtable64_ts_free (
  hash64_table_t * const hashtblP,
  const u64 keyP)
{
  hash64_node_t                     *node,
                                         *prevnode = NULL;
  u64                                 hash = 0;

  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  hash = hashtblP->hashfunc(keyP) % hashtblP->size;
  pthread_mutex_lock(&hashtblP->lock_nodes[hash]);
  node = hashtblP->nodes[hash];

  while (node) {
    if (node->key == keyP) {
      if (prevnode)
        prevnode->next = node->next;
      else
        hashtblP->nodes[hash] = node->next;

      if (node->data && hashtblP->freefunc) {
//	  	printf("%s, %d, free(node->data);\n", __FILE__, __LINE__);
        hashtblP->freefunc(&node->data);
        node->data = NULL;
      }
//	  printf("%s, %d, free(node);\n", __FILE__, __LINE__);
      free(node);
	  node=NULL;
      hashtblP->num_elements--;
      pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
      //printf("%s(key 0x%x) return OK\n", __FUNCTION__, keyP);
      return HASH_TABLE_OK;
    }

    prevnode = node;
    node = node->next;
  }

   pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
   //printf("%s(key 0x%x) return KEY_NOT_EXISTS\n", __FUNCTION__, keyP);
  return HASH_TABLE_KEY_NOT_EXISTS;
}

//------------------------------------------------------------------------------
/*
   Searching for an element is easy. We just search through the linked list for the corresponding hash value.
   NULL is returned if we didn't find it.
*/
hashtable_rc_t __export
hashtable_ts_get (
  hash_table_t * const hashtblP,
  const u32 keyP,
  void **dataP)
{
  hash_node_t                 *node = NULL;
  u32                             hash = 0;

  *dataP = NULL;
  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  hash = hashtblP->hashfunc(keyP) % hashtblP->size;

  pthread_mutex_lock(&hashtblP->lock_nodes[hash]);
  node = hashtblP->nodes[hash];

  while (node) {
    if (node->key == keyP) {
      *dataP = node->data;
	  //printf("%s, key = %u, lock\n", hashtblP->name, keyP);
      //pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
      //printf("%s(key 0x%x data %p) return OK\n", __FUNCTION__, keyP, *dataP);
      return HASH_TABLE_OK;
    }

    node = node->next;
  }
  pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
  //printf("%s(key 0x%x) return KEY_NOT_EXISTS\n", __FUNCTION__, keyP);

  return HASH_TABLE_KEY_NOT_EXISTS;
}

//------------------------------------------------------------------------------
/*
   Searching for an element is easy. We just search through the linked list for the corresponding hash value.
   NULL is returned if we didn't find it.
*/
hashtable_rc_t __export
hashtable_ts_get_no_mutex (
  hash_table_t * const hashtblP,
  const u32 keyP,
  void **dataP)
{
  hash_node_t                 *node = NULL;
  u32                             hash = 0;

  *dataP = NULL;
  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  hash = hashtblP->hashfunc(keyP) % hashtblP->size;

  node = hashtblP->nodes[hash];

  while (node) {
    if (node->key == keyP) {
      *dataP = node->data;
      return HASH_TABLE_OK;
    }

    node = node->next;
  }

  return HASH_TABLE_KEY_NOT_EXISTS;
}

hashtable_rc_t __export
hashtable64_ts_get (
  hash64_table_t * const hashtblP,
  const u64 keyP,
  void **dataP)
{
  hash64_node_t                 *node = NULL;
  u64                             hash = 0;

  *dataP = NULL;
  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  hash = hashtblP->hashfunc(keyP) % hashtblP->size;

  pthread_mutex_lock(&hashtblP->lock_nodes[hash]);
  node = hashtblP->nodes[hash];

  while (node) {
    if (node->key == keyP) {
      *dataP = node->data;
	  //printf("%s, key = %u, lock\n", hashtblP->name, keyP);
      //pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
      //printf("%s(key 0x%x data %p) return OK\n", __FUNCTION__, keyP, *dataP);
      return HASH_TABLE_OK;
    }

    node = node->next;
  }
  pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
  //printf("%s(key 0x%x) return KEY_NOT_EXISTS\n", __FUNCTION__, keyP);

  return HASH_TABLE_KEY_NOT_EXISTS;
}

hashtable_rc_t __export
hashtable64_ts_get_no_mutex (
  hash64_table_t * const hashtblP,
  const u64 keyP,
  void **dataP)
{
  hash64_node_t                 *node = NULL;
  u64                             hash = 0;

  *dataP = NULL;
  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  hash = hashtblP->hashfunc(keyP) % hashtblP->size;

  node = hashtblP->nodes[hash];

  while (node) {
    if (node->key == keyP) {
      *dataP = node->data;
      return HASH_TABLE_OK;
    }

    node = node->next;
  }

  return HASH_TABLE_KEY_NOT_EXISTS;
}

/*  
hashtable_rc_t
hashtable_part_ts_apply_callback_on_elements (
  hash_table_t * const hashtblP,
  int index,
  int funct_cb (int priv_len,
			   uint64_t keyP,
			   void * dataP,
			   void *parameterP, 
			   void ** resultP),
  void *parameterP,
  void** resultP)
{
  hash_node_t							 *node = NULL;
  unsigned int							  i = index * 50000;
  unsigned int							  num_elements = 0;
  unsigned int							  have = 0;
  int									  ret;
  if (!hashtblP) {
	return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }
  //printf("index=%d\n", index);

  while ((num_elements < hashtblP->num_elements) && (i < (index + 1) * 50000)) {
	pthread_mutex_lock(&hashtblP->lock_nodes[i]);
	if (hashtblP->nodes[i] != NULL) {
	  //printf("%d-th node is not empty\n", i);
	  node = hashtblP->nodes[i];

	  while (node) {
		num_elements++;
		ret = funct_cb (have, node->key, node->data, parameterP, resultP);
		//printf("ret=%d\n", ret);
		if (ret != -1)
			have = ret;

		node = node->next;
	  }
	}
	pthread_mutex_unlock(&hashtblP->lock_nodes[i]);
	i++;
  }

  return HASH_TABLE_OK;
}  
*/

hashtable_rc_t __export
hashtable_ts_nodes_unlock (
  hash_table_t * const hashtblP,
  const u32 keyP)
{
	size_t 							hash = 0;
	if (!hashtblP) {
	  return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
	}
	//printf("%s, key = %u, unlock\n", hashtblP->name, keyP);
	hash = hashtblP->hashfunc (keyP) % hashtblP->size;
	pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
	return HASH_TABLE_OK;
}  

hashtable_rc_t __export
hashtable64_ts_nodes_lock (
  hash64_table_t * const hashtblP,
  const u64 keyP)
{
	size_t 							hash = 0;
	if (!hashtblP) {
	  return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
	}
	//printf("%s, key = %u, unlock\n", hashtblP->name, keyP);
	hash = hashtblP->hashfunc (keyP) % hashtblP->size;
	pthread_mutex_lock(&hashtblP->lock_nodes[hash]);
	return HASH_TABLE_OK;
}  

hashtable_rc_t __export
hashtable64_ts_nodes_unlock (
  hash64_table_t * const hashtblP,
  const u64 keyP)
{
	size_t 							hash = 0;
	if (!hashtblP) {
	  return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
	}
	//printf("%s, key = %u, unlock\n", hashtblP->name, keyP);
	hash = hashtblP->hashfunc (keyP) % hashtblP->size;
	pthread_mutex_unlock(&hashtblP->lock_nodes[hash]);
	return HASH_TABLE_OK;
}  


//------------------------------------------------------------------------------
/*
   Cleanup
   The hashtable_destroy() walks through the linked lists for each possible hash value, and releases the elements. It also releases the nodes array and the hash_table_t.
*/
hashtable_rc_t __export
hashtable_ts_destroy (
  hash_table_t * hashtblP)
{
  size_t                                  n = 0;
  hash_node_t                         *node = NULL,
                                         *oldnode = NULL;

  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  for (n = 0; n < hashtblP->num_elements; ++n) {
    pthread_mutex_lock (&hashtblP->lock_nodes[n]);
    node = hashtblP->nodes[n];

    while (node) {
      oldnode = node;
      node = node->next;

      if (oldnode->data && hashtblP->freefunc) {
        hashtblP->freefunc(&oldnode->data);
      }
      free (oldnode);
    }

    pthread_mutex_unlock (&hashtblP->lock_nodes[n]);
    pthread_mutex_destroy (&hashtblP->lock_nodes[n]);
  }

  free(hashtblP->nodes);
  free(hashtblP->lock_nodes);
  
  if (hashtblP->name) {
    free(hashtblP->name);
    hashtblP->name = NULL;
  }
  
  //if (hashtblP->is_allocated_by_malloc) {
  //  free (hashtblP);
  //}
  
  return HASH_TABLE_OK;
}



//------------------------------------------------------------------------------
// may cost a lot CPU...
// Also useful if we want to find an element in the collection based on compare criteria different than the single key
// The compare criteria in implemented in the funct_cb function
hashtable_rc_t __export
hashtable_ts_apply_callback_on_elements (
  hash_table_t * const hashtblP,
  u32 funct_cb (const u32 keyP,
               void * const dataP,
               void *parameterP,
               void ** resultP),
  void *parameterP,
  void** resultP)
{
  hash_node_t                          *node = NULL;
  unsigned int                            i = 0;
  unsigned int                            num_elements = 0;

  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  while ((num_elements < hashtblP->num_elements) && (i < hashtblP->size)) {
    pthread_mutex_lock(&hashtblP->lock_nodes[i]);
    if (hashtblP->nodes[i] != NULL) {
      node = hashtblP->nodes[i];

      while (node) {
        num_elements++;
        if (funct_cb (node->key, node->data, parameterP, resultP)) {
          pthread_mutex_unlock(&hashtblP->lock_nodes[i]);
          return HASH_TABLE_OK;
        }
        node = node->next;
      }
    }
    pthread_mutex_unlock(&hashtblP->lock_nodes[i]);
    i++;
  }

  return HASH_TABLE_OK;
}


//------------------------------------------------------------------------------
// may cost a lot CPU...
// Also useful if we want to find an element in the collection based on compare criteria different than the single key
// The compare criteria in implemented in the funct_cb function
hashtable_rc_t __export
hashtable64_ts_apply_callback_on_elements (
  hash64_table_t * const hashtblP,
  u32 funct_cb (const u64 keyP,
               void * const dataP,
               void *parameterP,
               void ** resultP),
  void *parameterP,
  void** resultP)
{
  hash64_node_t                          *node = NULL;
  unsigned int                            i = 0;
  unsigned int                            num_elements = 0;

  if (!hashtblP) {
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;
  }

  while ((num_elements < hashtblP->num_elements) && (i < hashtblP->size)) {
    pthread_mutex_lock(&hashtblP->lock_nodes[i]);
    if (hashtblP->nodes[i] != NULL) {
      node = hashtblP->nodes[i];

      while (node) {
        num_elements++;
        if (funct_cb (node->key, node->data, parameterP, resultP)) {
          pthread_mutex_unlock(&hashtblP->lock_nodes[i]);
          return HASH_TABLE_OK;
        }
        node = node->next;
      }
    }
    pthread_mutex_unlock(&hashtblP->lock_nodes[i]);
    i++;
  }

  return HASH_TABLE_OK;
}


//------------------------------------------------------------------------------
/*
   Non-destructive statistics helpers for runtime diagnostics.
   They walk all buckets, count real nodes, and compare with num_elements.
   These helpers are intentionally read-only and only lock one bucket at a time.
*/
hashtable_rc_t __export
obj_hashtable_ts_get_stats (
  obj_hash_table_t * const hashtblP,
  myhashtable_stats_t * const statsP)
{
  size_t i;

  if (!hashtblP || !statsP)
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;

  memset(statsP, 0, sizeof(*statsP));
  statsP->size = hashtblP->size;
  statsP->declared_elements = hashtblP->num_elements;

  if (!hashtblP->nodes || !hashtblP->lock_nodes)
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;

  for (i = 0; i < hashtblP->size; i++) {
    uint32_t chain = 0;
    obj_hash_node_t *node;

    pthread_mutex_lock(&hashtblP->lock_nodes[i]);
    node = hashtblP->nodes[i];
    while (node) {
      chain++;
      node = node->next;
    }
    pthread_mutex_unlock(&hashtblP->lock_nodes[i]);

    if (chain) {
      statsP->used_buckets++;
      statsP->actual_elements += chain;
      if (chain > statsP->max_chain)
        statsP->max_chain = chain;
    }
  }

  statsP->empty_buckets = statsP->size - statsP->used_buckets;
  return HASH_TABLE_OK;
}

hashtable_rc_t __export
hashtable64_ts_get_stats (
  hash64_table_t * const hashtblP,
  myhashtable_stats_t * const statsP)
{
  size_t i;

  if (!hashtblP || !statsP)
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;

  memset(statsP, 0, sizeof(*statsP));
  statsP->size = hashtblP->size;
  statsP->declared_elements = hashtblP->num_elements;

  if (!hashtblP->nodes || !hashtblP->lock_nodes)
    return HASH_TABLE_BAD_PARAMETER_HASHTABLE;

  for (i = 0; i < hashtblP->size; i++) {
    uint32_t chain = 0;
    hash64_node_t *node;

    pthread_mutex_lock(&hashtblP->lock_nodes[i]);
    node = hashtblP->nodes[i];
    while (node) {
      chain++;
      node = node->next;
    }
    pthread_mutex_unlock(&hashtblP->lock_nodes[i]);

    if (chain) {
      statsP->used_buckets++;
      statsP->actual_elements += chain;
      if (chain > statsP->max_chain)
        statsP->max_chain = chain;
    }
  }

  statsP->empty_buckets = statsP->size - statsP->used_buckets;
  return HASH_TABLE_OK;
}
