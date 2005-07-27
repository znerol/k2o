/*
 ** Copyright (C) 2005 Lorenz Schori <lo@znerol.ch>
 **  
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation; either version 2 of the License, or
 ** (at your option) any later version.
 ** 
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 ** 
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software 
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/signal.h>
#include <getopt.h>
#include <time.h>
#include <pthread.h>
#include <limits.h>
#include <math.h>

#include "k2olog.h"

#include "lo/lo.h"

// message chain
typedef struct {
	struct timespec	time;
	char*			path;
	lo_message		msg;
	void*			next;
	void*			prev;
} timedMessage;

FILE*			infd;
pthread_t		fileIndexThread;

lo_server_thread	oscServerThread = NULL;

char pfxpath[255] = "/kismet";

pthread_mutex_t	schedulerMutex;
pthread_cond_t	rescheduleCondVar;
double			rate = 1.0;
int				follow = 1;

struct timespec		lasttime, lastpos = {0,0}, curpos = {0,0};

pthread_cond_t	mchainCondVar;
timedMessage*	mchain = NULL;
timedMessage*	mlast = NULL;

// timespec helper function
void timespec_now(struct timespec *ts)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec * 1000;
}

#define NANO 1000000000.0

double timespec_diff(struct timespec a, struct timespec b)
{
	return (((double)a.tv_sec - (double)b.tv_sec) + ((double)a.tv_nsec - (double)b.tv_nsec) / NANO);
}

struct timespec timespec_dadd(struct timespec a, double d)
{
	double	intpart;
	struct timespec r;
	r.tv_nsec = modf((double)a.tv_sec + (double)a.tv_sec / NANO + d,
					  &intpart) * NANO;
	r.tv_sec = intpart;
	return r;
}

// file reading thread
void*
fileIndexThreadEntry()
{
	char		lastLine[1024];
	int			c = 0;
	int			cpos = 0;
	timedMessage*	tm = NULL;

	ILOG("started filereader");
	while(1) {
		flockfile(infd);
		while((c = getc_unlocked(infd)))
		{
			if(c == EOF) {
				// exit loop if end of file is reached
				break;
			}
			if(cpos == 1023) {
				// FIXME: better error handlin here
				return;
			}
			lastLine[cpos] = c;
			
			if(c == '\n') {
				char*	ctx;
				
				// end and parse line
				lastLine[cpos] = '\0';
				
				// make new messsage
				tm = (timedMessage*)malloc(sizeof(timedMessage));
				tm->msg = lo_message_new();
				
				// read timestamp
				char *timestr = strtok_r(lastLine, " ", &ctx);
				double tsec;
				tm->time.tv_nsec = modf(strtod(timestr,NULL),&tsec) * NANO;
				tm->time.tv_sec = tsec;
				
				// read path
				char *path = strtok_r(NULL, " ", &ctx);
				tm->path = (char*)malloc(strlen(path) + 1);
				strcpy(tm->path, path);
				
				// read values
				int i;
				char *types = strtok_r(NULL, " ", &ctx);
				char *valstr;

				for(i=0; (valstr = strtok_r(NULL, " ", &ctx)) != NULL; i++) {
					if(!valstr[0])
						// ignore empty fields
						continue;
					
					switch(types[i]) {
						case LO_INT32:
						{
							int		v = (int)strtol(valstr,NULL,0);
							lo_message_add_int32(tm->msg,v);
							break;
						}
							
						case LO_FLOAT:
						{
							float	f = (float)strtod(valstr,NULL);
							lo_message_add_float(tm->msg,f);
							break;
						}
							
						case LO_STRING:
							lo_message_add_string(tm->msg,valstr);
							break;
							
						default:
							// FIXME: only int, float and string types are supported
							break;
					}
				}
				
				tm->next = NULL;
				
				// add message to chain
				pthread_mutex_lock(&schedulerMutex);
				DLOG1("filereader thread locked");
				
				tm->prev = mlast;
				
				if(mlast) {
					mlast->next = tm;
				}
				
				// first message
				if(!mchain) {
					mchain = tm;
					pthread_cond_signal(&mchainCondVar);
				}
				mlast = tm;
				pthread_cond_signal(&rescheduleCondVar);
				
				pthread_mutex_unlock(&schedulerMutex);
				DLOG1("filereader thread unlocked");
				
				cpos = 0;
			}
			cpos++;
		}
		funlockfile(infd);
		
		if(feof(infd)) {
			clearerr(infd);
			// sleep shortly (one millisecond) so we don't eat the whole cpu. 
			usleep(1000);
		}
	}
	pthread_exit(NULL);
}

void serverErrorHandler(int num, const char *msg, const char *where)
{
	ELOG("liblo server %s: %s (%d)", where, msg, num);
}

int setRateHandler(const char *path, const char *types, lo_arg **argv, int argc,
				   lo_message msg, void *user_data)
{
	if (types[0] == LO_FLOAT) {
		pthread_mutex_lock(&schedulerMutex);
		lastpos = curpos;
		timespec_now(&lasttime);
		follow = 0;
		rate = argv[0]->f;
		pthread_cond_signal(&rescheduleCondVar);
		ILOG("rate set to %f",rate);
		pthread_mutex_unlock(&schedulerMutex);
	}
}

int setPosHandler(const char *path, const char *types, lo_arg **argv, int argc,
				  lo_message msg, void *user_data)
{
	// pthread_mutex_lock(&schedulerMutex);

	// FIXME: IMPLEMENT THIS.
	WLOG("setpos not implemented yet");

	// pthread_mutex_unlock(&schedulerMutex);
}

void catchTerm(int sig) {
	ILOG("caught signal %d. terminating",sig);
	pthread_mutex_unlock(&schedulerMutex);
	pthread_mutex_destroy(&schedulerMutex);

	pthread_cond_destroy(&mchainCondVar);
	
	lo_server_thread_stop(oscServerThread);
	exit(sig);
}

void usage(char *executable){
	printf("Usage: %s file osc-targets, ...\n", executable);
	printf("\n"
" reads kismet output produced by k2orec from a logfile and\n"
" sends it to the osc-targets specified by a osc-url.\n\n"
" Options:\n"		
" -p, --port         start in replay mode and listen for osc control messages on\n"
"                    this port.\n"
" -r, --rate         start in replay mode and set rate. if no rate is given 1.0\n"
"                    is used\n"
" -f, --prefix       prefix path for received messages. standard is %s.\n"
" -d, --debug        set debug level to 0-%d. default is %d.\n"
" -v, --version      version information\n"
" -h, --help\n", pfxpath, kLogNumLevels-1, gLogLevel);
	exit(1);
}


int
main (int argc, char **argv)
{
	char *oscport = NULL;
	int	err;
	
	static struct option long_options[] = {
	{ "port",	required_argument, 0, 'p' },
	{ "rate",	optional_argument, 0, 'r' },
	{ "debug",	required_argument, 0, 'd' },
	{ "prefix",	required_argument, 0, 'f' },
	{ "version", no_argument, 0, 'v' },
	{ "help", no_argument, 0, 'h' },
	{ 0, 0, 0, 0 }
	};

	// Catch the interrupt handler to shut down
	signal(SIGINT, catchTerm);
	signal(SIGTERM, catchTerm);
	signal(SIGHUP, catchTerm);
	signal(SIGPIPE, SIG_IGN);

	while (1)
	{
		/* getopt_long stores the option index here. */
		int option_index = 0;
		
		int c = getopt_long (argc, argv, "vhp:r:d:f:", long_options, &option_index);
		
		/* Detect the end of the options. */
		if (c == -1)
			break;
		
		switch (c)
		{				
			case 'p':
			{
				follow = 0;
				oscport = optarg;
				DLOG("set oscport to %s", oscport);
				break;
			}
				
			case 'r':
			{
				follow = 0;
				if(optarg && optarg[0]) {
					rate = (float)strtod(optarg,(char **)NULL);
					DLOG("set rate to %f", rate);
				}
				break;
			}
				
			case 'd':
			{
				if(optarg && optarg[0]) {
					gLogLevel = strtol(optarg,NULL,0);
					DLOG("set debug level to %d (%s)", gLogLevel, gLogStings[gLogLevel]);
				}
				break;
			}
				
			case 'f':
			{
				if(optarg && optarg[0]) {
					strncpy(pfxpath,optarg,sizeof(pfxpath));
					DLOG("set osc prefix to %s", pfxpath);
				}
				break;
			}
				
			case 'h':
			case '?':
				usage(argv[0]);
				/* getopt_long already printed an error message. */
				break;
				
			default:
				abort ();
		}
	}
	
	// if we don't have minimum 2 more arguments, something is wrong
	int	ocount = argc - optind - 1;
	
	if(ocount < 1) {
		usage(argv[0]);
	}

	// open input file
	char		infilePath[PATH_MAX];
	strncpy(infilePath, argv[optind],sizeof(infilePath));
//	infilePath[PATH_MAX-1];
	infd = fopen(infilePath, "r");
	if(!infd) {
		ELOG("could not open file");
		catchTerm(0);
	}
	ILOG("file opened for reading %s", infilePath);
	optind++;
		
	// setup osc targets
	lo_address	*otargets;
	otargets = (lo_address*)malloc(ocount * sizeof(lo_address));

	int i;
	for(i = 0 ; i < ocount ; i++) {
		otargets[i] = lo_address_new_from_url(argv[optind+i]);
		if(!otargets[i]) {
			ELOG("failed to setup target for %s", argv[optind+i]);
			catchTerm(-1);
		}
		ILOG("setup target for %s", argv[optind+i]);
	}
	
	// setup scheduler thread stuff
	err = pthread_cond_init(&rescheduleCondVar, NULL);
	err = pthread_mutex_init(&schedulerMutex, NULL);
	
	// setup osc server
	if(oscport) {
		oscServerThread = lo_server_thread_new(oscport, &serverErrorHandler);
		if(!oscServerThread) {
			ELOG("failed to setup osc server thread");
			catchTerm(-1);
		}
		lo_server_thread_add_method(oscServerThread, "/k2o/setrate","f",
									&setRateHandler, NULL);
		lo_server_thread_add_method(oscServerThread, "/k2o/setpos","f",
									&setPosHandler, NULL);
		lo_server_thread_start(oscServerThread);
		ILOG("setup osc server thread started");
	}
	
	// detach filereader thread
//	err = pthread_mutex_init(&mchainMutex, NULL);
	err = pthread_cond_init(&mchainCondVar, NULL);
	err = pthread_create(&fileIndexThread, NULL, &fileIndexThreadEntry, NULL);
	
	// current and last sendt message
	timedMessage	*mcurrent = NULL, *mlastsendt = NULL;

	// wait for first message
	pthread_mutex_lock(&schedulerMutex);
	DLOG1("startup locked");
	if(!mchain) {
		DLOG("waiting for mchainCondVar");
		pthread_cond_wait(&mchainCondVar, &schedulerMutex);
		DLOG("got mchainCondVar");
	}
	mcurrent = mchain;
	
	// set lasttime to startup time. lastpos and curpos are set to {0,0}.
	timespec_now(&lasttime);

	pthread_mutex_unlock(&schedulerMutex);
	DLOG1("startup unlocked");
	
	ILOG("starting the send loop");
	
	int mline = 0;
	int state = 0;
	while(1) {
		// lock scheduler mutex for the whole loop. it will be unlocked by
		// several pthread_cond_wait calls.
		// only one message is processed per pass.
		pthread_mutex_lock(&schedulerMutex);
		DLOG1("scheduler thread locked");
		
		int		wait = 1;
		timedMessage* nmsg = NULL; // next sendable message

		while(wait) {
			// check here for send/move condition and wait for them.
			int					limited = 0;
			struct timespec		limit;
			
			// we are in following mode
			if(follow) {
				// wait infinitely if we are at the end of the q and state is
				// not sending state.
				if(!mcurrent->next && state == 1) {
					limited = 0;
				}
				// send message if we are not at the end.
				else {
					nmsg = mcurrent->next;
					// break out of the loop and send message
					break;
				}
			}
			
			// we are in interactive mode
			else {
				// wait forever if rate is 0
				if(rate == 0) {
					limited = 0;
				}
				else {
					struct timespec now;
					double dnsec;
					
					timespec_now(&now);
					dnsec = timespec_diff(now, lasttime);
					curpos = timespec_dadd(lastpos, dnsec * rate);
					
					double dnpos = timespec_diff(mcurrent->time, curpos);
					double dnwait = dnpos / rate;
					
					
					// if dnwait is positiv we have to wait for the next message
					if (dnwait > 0) {
						limited = 1;
						limit = timespec_dadd(now, dnwait);
					}
					// forward
					else if (rate > 0) {
						nmsg = mcurrent->next;
						
						// if we are just sending or we are moving but next
						// message is there. break.
						if(state == 0 || nmsg) {
							// break out of the loop and send message
							break;
						}
						else {
							// we reached the end of the chain. wait unlimited
							limited = 0;
							if(rate > 1) {
								// switch to following mode.
								follow = 1;
								rate = 0;
							}
						}
					}
					// backward
					else if (rate < 0) {
						// check if current message is first message and stop if 
						// appropriate.
						nmsg = mcurrent->prev;
						// if we are just sending or we are moving but next
						// message is there. break.
						if(state == 0 || nmsg) {
							// break out of the loop and send message
							break;
						}
						else {
							// stop if we are at the begin of the chain.
							rate = 0;
						}
					}
				}
			}
			
			// wait for signaled condition
			if (limited) {
				DLOG1("waiting for rescheduleCondVar.");
				pthread_cond_timedwait(&rescheduleCondVar, &schedulerMutex, &limit);
				DLOG1("got rescheduleCondVar.");
			}
			else {
				DLOG1("waiting for rescheduleCondVar. unlimited.");
				pthread_cond_wait(&rescheduleCondVar, &schedulerMutex);
				DLOG1("got rescheduleCondVar.");
			}
		}
		pthread_mutex_unlock(&schedulerMutex);
		DLOG1("scheduler thread unlocked");
		
		// send message if state is 0 (sendable)
		if(state == 0) {
			for(i = 0 ; i < ocount ; i++) {
				DLOG("sending message %s",mcurrent->path);
				int ret = lo_send_message(otargets[i], mcurrent->path, mcurrent->msg);
				if(ret < 0) {
					ELOG("%d, %s",ret,lo_address_errstr(otargets[i]));
				}
			}
			state = 1;
		}
		
		// move to next unsent message if we are moving. it's possible that we
		// can't move to the next message because we are at the beginning or the
		// end of the queue. in this case the state is left to 1, so we can this
		// after a conditional variable was signaled above.
		pthread_mutex_lock(&schedulerMutex);
		DLOG1("scheduler thread locked");
		if(state == 1 && nmsg) {
			mcurrent = nmsg;
			state = 0;
		}
		pthread_mutex_unlock(&schedulerMutex);
		DLOG1("scheduler thread unlocked");
	}
	catchTerm(0);
	return 0;
}
