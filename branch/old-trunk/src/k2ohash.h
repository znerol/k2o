/*
 *  k2ohash.h
 *  k2o
 *
 *  Created by Lorenz Schori on 28.07.05.
 *  Copyright 2005 __MyCompanyName__. All rights reserved.
 *
 */

#include "hash.h"

#ifndef K2OHASH_H
#define K2OHASH_H

static inline int hash_string(const char* str, const int hash_size)
{
    int hash = 0;
    int i;
    for (i=0; str[i] != '\0'; i++)
    {
	char c = str[i];
	if (c >= 0140)
	    c -= 40;
	hash = (hash<<3) + (hash>>28) + c;
    }
    return (hash & 07777777777) % hash_size;
}

static inline int string_equal(const char* str1, const char* str2)
{
    return strcmp(str1, str2) == 0;
}

DECLARE_HASH(str_str, char*, char*)
DEFINE_HASH(str_str, char*, char*, hash_string, string_equal)

#endif