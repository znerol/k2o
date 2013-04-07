/*
 *  k2odata.h
 *  k2o
 *
 *  Created by Lorenz Schori on 13.09.05.
 *  Copyright 2005 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef K2OHASH_H
#define K2OHASH_H

#include "list.h"
#include "hash.h"

int hash_string(const char* str, const int hash_size);
int string_equal(const char* str1, const char* str2);

DECLARE_HASH(str_str, char*, char*)
DECLARE_HASH(str_ptr, char*, void*)
DECLARE_LIST(void*,ptr)
#endif