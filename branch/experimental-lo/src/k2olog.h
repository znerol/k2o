/*
 *  k2olog.h
 *  k2o
 *
 *  Created by Lorenz Schori on 01.06.05.
 *  Copyright 2005 Lorenz Schori <lo@znerol.ch>. All rights reserved.
 *
 */

extern int gLogLevel;
extern char *gLogStings[];

enum {
	kLogError,
	kLogWarning,
	kLogInfo,
	kLogDebug,
	kLogDebug1,
	kLogNumLevels
};

#ifdef NDEBUG
#define CLOG(_level, _format, _args...) \
if(_level <= gLogLevel) { \
	fprintf(stderr, "%s: " _format "\n", gLogStings[_level], ## _args); \
}
#else
#define CLOG(_level, _format, _args...) \
if(_level <= gLogLevel) { \
	fprintf(stderr, "%s: %s,%d: " _format "\n", gLogStings[_level], __FILE__, __LINE__, ## _args); \
}
#endif

#define ELOG(_format, _args...) CLOG(kLogError, _format, ## _args)
#define WLOG(_format, _args...) CLOG(kLogWarning, _format, ## _args)
#define ILOG(_format, _args...) CLOG(kLogInfo, _format, ## _args)
#define DLOG(_format, _args...) CLOG(kLogDebug, _format, ## _args)
#define DLOG1(_format, _args...) CLOG(kLogDebug1, _format, ## _args)
