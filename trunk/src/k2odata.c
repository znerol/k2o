/*
 *  k2odata.c
 *  k2o
 *
 *  Created by Lorenz Schori on 13.09.05.
 *  Copyright 2005 __MyCompanyName__. All rights reserved.
 *
 */

#include <string.h>
#include "k2odata.h"

int hash_string(const char* str, const int hash_size)
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

int string_equal(const char* str1, const char* str2)
{
    return strcmp(str1, str2) == 0;
}

DEFINE_HASH(str_str, char*, char*, hash_string, string_equal)
DEFINE_HASH(str_ptr, char*,  void*, hash_string, string_equal)
DEFINE_LIST(void*,ptr)
