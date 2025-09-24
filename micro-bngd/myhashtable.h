/*
 * VanGW (vgw) Software, Copyright © 2019 COMMUNICATION INDUSTRY INSTITUTION.
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


#ifndef _MYHASHTABLE_H_
#define _MYHASHTABLE_H_

#include <vppinfra/types.h>
#include <vppinfra/format.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

typedef size_t   hash_size_t;

typedef enum hashtable_return_code_e {
    HASH_TABLE_OK                  = 0,
    HASH_TABLE_INSERT_OVERWRITTEN_DATA,
    HASH_TABLE_KEY_NOT_EXISTS         ,
    HASH_TABLE_SEARCH_NO_RESULT       ,
    HASH_TABLE_KEY_ALREADY_EXISTS     ,
    HASH_TABLE_BAD_PARAMETER_HASHTABLE,
    HASH_TABLE_BAD_PARAMETER_KEY,
    HASH_TABLE_SYSTEM_ERROR           ,
    HASH_TABLE_CODE_MAX
} hashtable_rc_t;
typedef struct obj_hash_node_s
{
	int   key_size;
    void *key;
	void *data;
	struct obj_hash_node_s *next;
} obj_hash_node_t;

typedef struct obj_hash_table_s
{
  hash_size_t         size;
	pthread_mutex_t *lock_nodes;
	uint32_t num_elements;
	obj_hash_node_t **nodes;
	uint64_t      (*hashfunc)(const void*, int);
	int (*cmpfunc) (const void *, const void *, int);
  void              (*freefunc)(void**);
	char *name;
} obj_hash_table_t;

typedef struct hash_node_s
{
	u32 key;
	void *data;
	struct hash_node_s *next;
} hash_node_t;

typedef struct hash64_node_s
{
	u64 key;
	void *data;
	struct hash64_node_s *next;
} hash64_node_t;


typedef struct
{
  hash_size_t         size;
	pthread_mutex_t *lock_nodes;
	u32 num_elements;
	hash_node_t **nodes;
	u32      (*hashfunc)(const u32);
  void              (*freefunc)(void**);
	char *name;
} hash_table_t;

typedef struct
{
  hash_size_t         size;
	pthread_mutex_t *lock_nodes;
	u32 num_elements;
	hash64_node_t **nodes;
	u64      (*hashfunc)(const u64);
  void              (*freefunc)(void**);
	char *name;
} hash64_table_t;

void hashtable_ts_init (hash_table_t * const hashtblP, const hash_size_t sizeP, u32 (*hashfuncP) (const u32), void (*freefuncP) (void **),
	  char *tablename);
hashtable_rc_t hashtable_ts_insert (hash_table_t * const hashtblP,
	  u32 keyP, void *dataP);
hashtable_rc_t hashtable_ts_free (hash_table_t * const hashtblP, const u32 keyP);
hashtable_rc_t hashtable_ts_get (hash_table_t * const hashtblP,
	  const u32 keyP, void **dataP);
hashtable_rc_t hashtable_ts_get_no_mutex (hash_table_t * const hashtblP,
	  const u32 keyP, void **dataP);
hashtable_rc_t hashtable_ts_display (hash_table_t * const hashtblP);
hashtable_rc_t  hashtable_ts_apply_callback_on_elements (hash_table_t * const hashtbl,
                                                      u32 func_cb(const u32 key, void* const element, void* parameter, void**result),
                                                      void* parameter,
                                                      void**result);
hashtable_rc_t hashtable_ts_destroy (  hash_table_t * hashtblP);

void hashtable64_ts_init (hash64_table_t * const hashtblP, const hash_size_t sizeP, u64 (*hashfuncP) (const u64), void (*freefuncP) (void **),
	  char *tablename);
hashtable_rc_t hashtable64_ts_insert (hash64_table_t * const hashtblP,
	  u64 keyP, void *dataP);
hashtable_rc_t hashtable64_ts_free (hash64_table_t * const hashtblP, const u64 keyP);
hashtable_rc_t hashtable64_ts_get (hash64_table_t * const hashtblP,
	  const u64 keyP, void **dataP);
hashtable_rc_t hashtable64_ts_get_no_mutex (hash64_table_t * const hashtblP,
	  const u64 keyP, void **dataP);

hashtable_rc_t  hashtable64_ts_apply_callback_on_elements (hash64_table_t * const hashtbl,
                                                      u32 func_cb(const u64 key, void* const element, void* parameter, void**result),
                                                      void* parameter,
                                                      void**result);

hashtable_rc_t
hashtable64_ts_nodes_lock (
  hash64_table_t * const hashtblP,
  const u64 keyP);

hashtable_rc_t
hashtable64_ts_nodes_unlock (
  hash64_table_t * const hashtblP,
  const u64 keyP);

#if 0

#if CLIB_DEBUG > 0
#define always_inline static inline
#define static_always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#define static_always_inline static inline __attribute__ ((__always_inline__))
#endif

always_inline int ipv4_within_mask(u32 *addr, u32 *net, u8 prefixlen)
{
	struct in_addr netmask;

	netmask.s_addr = htonl(0xFFFFFFFF << (32 - prefixlen));
	if ((*addr & netmask.s_addr) == (*net & netmask.s_addr))
		return 1;
	else
		return 0;
}
#endif

/*
hashtable_rc_t
hashtable_part_ts_apply_callback_on_elements (hash_table_t * const hashtblP, int index, int funct_cb (int priv_len, uint64_t keyP, void *  dataP, void *parameterP, void ** resultP), void *parameterP, void** resultP);
*/

hashtable_rc_t hashtable_ts_nodes_unlock (
  hash_table_t * const hashtblP,
  const u32 keyP);

void obj_hashtable_ts_init (obj_hash_table_t * hashtblP,
    const hash_size_t sizeP,
    uint64_t (*hashfuncP) (const void *, int), 
    int (*cmpfuncP) (const void *, const void *, int), 
    void (*freefuncP) (void **),
    char *tablename);

hashtable_rc_t
obj_hashtable_ts_insert (
  obj_hash_table_t * hashtblP,
  const void *const keyP,
  const int key_sizeP,
  void *dataP);

hashtable_rc_t
obj_hashtable_ts_free (
  obj_hash_table_t * hashtblP,
  const void *const keyP,
  const int key_sizeP);

hashtable_rc_t
obj_hashtable_ts_get (
  obj_hash_table_t * hashtblP,
  const void *const keyP,
  const int key_sizeP,
  void **dataP);

hashtable_rc_t
obj_hashtable_ts_get_no_mutex (
  obj_hash_table_t * hashtblP,
  const void *const keyP,
  const int key_sizeP,
  void **dataP);

hashtable_rc_t
obj_hashtable_ts_nodes_lock (
  obj_hash_table_t * hashtblP,
  const void *const keyP,
  const int key_sizeP);

hashtable_rc_t
obj_hashtable_ts_nodes_unlock (
  obj_hash_table_t * hashtblP,
  const void *const keyP,
  const int key_sizeP);

hashtable_rc_t
obj_hashtable_ts_destroy (
  obj_hash_table_t * const hashtblP);

#endif /* _MYHASHTABLE_H_ */
