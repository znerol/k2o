/*
 *  k2olog.c
 *  k2o
 *
 *  Created by Lorenz Schori on 01.06.05.
 *  Copyright 2005 Lorenz Schori <lo@znerol.ch>. All rights reserved.
 *
 */

#include "k2olog.h"

int gLogLevel = kLogInfo;

char *gLogStings[] = {
	"ERROR",
	"WARNING",
	"INFO",
	"DEBUG",
	"DEBUG1"
};
