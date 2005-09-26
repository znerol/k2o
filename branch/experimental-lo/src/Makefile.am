# Copyright (C) 2005 Lorenz Schori <lo@znerol.ch>
#  
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without 
# modifications, as long as this notice is preserved.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

MAINTAINERCLEANFILES = Makefile.in

bin_PROGRAMS	 = k2orec k2oplay
AM_LIBS          = @PTHREAD_LIBS@
AM_CFLAGS        = @PTHREAD_CFLAGS@

k2orec_SOURCES	 = k2orec.cpp k2olog.c k2odata.c

k2oplay_SOURCES	 = k2oplay.c k2olog.c k2odata.c
