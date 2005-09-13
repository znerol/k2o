// Copyright (C) 2005 Lorenz Schori <lo@znerol.ch>
//  
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software 
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/time.h>
#include <signal.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <ctype.h>

#include <lo/lo.h>

#include "k2olog.h"
#include "k2odata.h"

#define		kWriteBufLen 2048
char		writeBuf[kWriteBufLen];
#define		kReadBufLen 2048
char		readBuf[kReadBufLen];

int			kismValid = 0;
int			kismFD = 0;
FILE*		kismF = NULL;
short int	kismPort = 0;
struct hostent	*kismHost;
struct sockaddr_in	kismRemoteSock;
struct sockaddr_in	kismLocalSock;
char		kismHostname[MAXHOSTNAMELEN];
time_t		kismServerStart = 0;

char		kismPrefixPath[32] = "/kismet";

// field buffer structure
typedef struct k2oProtoField {
	char		name[32];
	char*		value;
	char		type;
} k2oProtoField;
DECLARE_LIST(k2oProtoField*,field)
DEFINE_LIST(k2oProtoField*,field)

// message template structure
typedef struct k2oMessageTemplate{
	char		pfx[64];
	int			types_set;
	char		types[32];
	field_list	fields;			// list of k2oProtoField structures
} k2oMessageTemplate;
DECLARE_LIST(k2oMessageTemplate*,mesg)
DEFINE_LIST(k2oMessageTemplate*,mesg)

// protocol structure
typedef struct k2oProtocol {
	char		name[32];
	char		pfx[64];		// the osc prefix
	int			(*pfx_func)(struct k2oProtocol*, char**, int);		
								// this can also be a function (k2oProtocol,value string)
	field_list	fields;			// fieldstruct
	mesg_list	messages;		// osctemplate
} k2oProtocol;
DECLARE_HASH(proto, char*, k2oProtocol*)
DEFINE_HASH(proto, char*, k2oProtocol*, hash_string, string_equal)
proto_hash		protocolMap;

// network and client struct types
typedef struct kismClient{
	int			index;
} kismClient;
DECLARE_HASH(client, char*, kismClient*)
DEFINE_HASH(client, char*, kismClient*, hash_string, string_equal)

typedef struct kismNetwork{
	int				index;
	int				clientCount;
	client_hash		clientMap;
} kismNetwork;
DECLARE_HASH(net, char*, kismNetwork*)
DEFINE_HASH(net, char*, kismNetwork*, hash_string, string_equal)
net_hash		networkMap;
int				netcount = 0;

void** kismNetworks = NULL;
void** kismClients = NULL;

struct timeval	startTime;

void usage(char *executable);
void kismetListCapability(const char* protocol);
void catchTerm(int sig);
int kismetConnect (short int port, char *host);
int kismetPerformNetIO(void);
int kismetParse(const char* data);
int kismetSend(const char* data);
void kismetListProtocols(void);
void kismetListCapability(const char* protocol);
void kismetEnableProtocol(const char* protocol);
//void* findProtocol(const char* protocol);
void strtolow(char** s);
char* propernextvaluetype(char** ctx, char* type, int addNullChar);
//void* insertIfNotContained(char* value, void* set, int size, int* idx);

double timeval_diff(struct timeval a, struct timeval b)
{
	return ((double)a.tv_sec - (double)b.tv_sec) + ((double)a.tv_usec - (double)b.tv_usec) / 1000000;
}

void usage(char *executable){
	printf("Usage: %s [OPTION] > somefile.txt\n", executable);
	printf("\n"
" connects to a kismet_server and writes osc messages to stdout.\n\n"
" Options:\n"
" -k, --kismethost   <host:port> address and tcp port of kismet server. default\n"
"                    is localhost:2501\n"
" -f, --prefix       prefix path for received messages. standard is %s.\n"
" -d, --debug        set debug level to 0-%d. default is %d.\n"
" -v, --version      version information\n"
" -h, --help\n", kismPrefixPath, kLogNumLevels-1, gLogLevel);
	exit(1);
}

void catchTerm(int sig) {
	exit(0);
}

int kismetConnect (short int port, char *host)
{
    kismPort = port;
	
    // Resolve
    if ((kismHost = gethostbyname(host)) == NULL) {
		ELOG("kismetConnect() could not resolve host \"%s\"",host);
        return (-1);
    }
	
    strncpy(kismHostname, host, MAXHOSTNAMELEN);
	
    // Set up our socket
    bzero(&kismRemoteSock, sizeof(kismRemoteSock));
    kismRemoteSock.sin_family = kismHost->h_addrtype;
    memcpy((char *) &kismRemoteSock.sin_addr.s_addr, kismHost->h_addr_list[0],
           kismHost->h_length);
    kismRemoteSock.sin_port = htons(kismPort);
	
    if ((kismFD = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		ELOG("socket() failed %d (%s)", errno, strerror(errno));
        return (-2);
    }
	
    // Bind to the local half of the pair
    kismLocalSock.sin_family = AF_INET;
    kismLocalSock.sin_addr.s_addr = htonl(INADDR_ANY);
    kismLocalSock.sin_port = htons(0);
	
    if (bind(kismFD, (struct sockaddr *) &kismLocalSock, sizeof(kismLocalSock)) < 0) {
 		ELOG("bind() failed %d (%s)", errno, strerror(errno));
        return (-3);
    }
	
    // Connect
    if (connect(kismFD, (struct sockaddr *) &kismRemoteSock, sizeof(kismRemoteSock)) < 0) {
 		ELOG("connect() failed %d (%s)", errno, strerror(errno));
        return (-4);
    }
	
    int save_mode = fcntl(kismFD, F_GETFL, 0);
    if (save_mode == -1) {
 		ELOG("connect() failed fcntl get %d (%s)", errno, strerror(errno));
        return (-5);
    }
    if (fcntl(kismFD, F_SETFL, save_mode | O_NONBLOCK) < 0) {
 		ELOG("connect() failed fcntl set %d (%s)", errno, strerror(errno));
        return (-6);
    }
	
    kismValid = 1;
	
    kismF = fdopen(kismFD, "r");
	
    return 1;
}

int networkPrefix(k2oProtocol* proto, char** outPrefix, int outPrefixLength)
{
	k2oProtoField*	bssid = (k2oProtoField*)field_list_first_data(proto->fields);
	if (strncmp(bssid->name,"bssid",sizeof(bssid->name) - sizeof(char)) ||
		bssid->value == NULL) {
		WLOG("could not get contents of bssid field of network\n");
		return -1;
	}
	
	kismNetwork*	net = (kismNetwork*)net_hash_get(networkMap,bssid->value);
	if(!net) {
		net = (kismNetwork*)calloc(1,sizeof(kismNetwork));
		net_hash_set(&networkMap,bssid->value,net);
		net->index = netcount;
		netcount++;
	}
	return snprintf(*outPrefix, outPrefixLength,
					"%s/network/%d", kismPrefixPath, net->index);
}

int clientPrefix(k2oProtocol* proto, char** outPrefix, int outPrefixLength)
{
	field_list_iterator fi = field_list_first(proto->fields);
	k2oProtoField*	bssid = (k2oProtoField*)field_list_value(fi);
	
	if (strncmp(bssid->name,"bssid",sizeof(bssid->name) - sizeof(char)) ||
		bssid->value == NULL) {
		WLOG("could not get contents of bssid field of client\n");
		return -1;
	}
	
	kismNetwork*	net = (kismNetwork*)net_hash_get(networkMap,bssid->value);
	if(!net) {
		WLOG("could not get network for this bssid\n");
		return -1;
	}
	
	field_list_next(&fi);
	k2oProtoField*	macaddr = (k2oProtoField*)field_list_value(fi);
	kismClient*		client = (kismClient*)client_hash_get(net->clientMap,macaddr->value);
	if (!client) {
		client = (kismClient*)calloc(1,sizeof(kismClient));
		client_hash_set(&net->clientMap,macaddr->value,client);
		client->index = net->clientCount;
		net->clientCount++;
	}
	
	return snprintf(*outPrefix, outPrefixLength,
					"%s/network/%d/client/%d",
					kismPrefixPath, net->index, client->index);
}

int packetPrefix(k2oProtocol* proto, char** outPrefix, int outPrefixLength)
{
	return -1;
}

int kismetPerformNetIO (void)
{
    if (!kismValid) {
		WLOG("kismetPerformNetIO() on an inactive connection.");
        return -1;
    }
	
    int selected;
    fd_set read_set;
    fd_set write_set;
	
    FD_ZERO(&read_set);
    FD_SET(kismFD, &read_set);
    FD_ZERO(&write_set);
    FD_SET(kismFD, &write_set);
	
    struct timeval tim;
	
    tim.tv_sec = 0;
    tim.tv_usec = 0;
	
    // Enter the select loop
    if ((selected = select(kismFD+1, &read_set, &write_set, NULL, &tim)) < 0) {
        if (errno != EINTR) {
            ELOG("select() returned %d (%s)", errno, strerror(errno));
            kismValid = 0;
            close(kismFD);
            return (-1);
        }
    }
	
	int writeBufLen = strlen(writeBuf);
    if (writeBufLen > 0 && FD_ISSET(kismFD, &write_set)) {
        int res = write(kismFD, writeBuf, writeBufLen);
		
        if (res <= 0) {
            if (res == 0 || (errno != EAGAIN && errno != EINTR)) {
                ELOG("Write error on socket (%d): %s", errno, strerror(errno));
                kismValid = 0;
                close(kismFD);
                return(-1);
            }
        } else {
            bzero(writeBuf,kWriteBufLen);
        }
    }
	
    if (!FD_ISSET(kismFD, &read_set))
        return 0;
	
    bzero(readBuf, kReadBufLen);
    if (fgets(readBuf, 2048, kismF) == NULL) {
        if (errno != 0 && errno != EAGAIN) {
			ELOG("Read error %d (%s), closing the connection.",
				 errno, strerror(errno));
            kismValid = 0;
            close(kismFD);
            return (-1);
        }
		
        if (feof(kismF)) {
			ELOG("socket returned EOF, server has closed the connection.");
            kismValid = 0;
            close(kismFD);
            return (-2);
        }
		
        return (0);
    }
	
    if (strlen(readBuf) < 2)
        return 0;
	
	// FIXME: parse data here
	
	int ret = kismetParse(readBuf);
	
    //return ret;
	return ret;
}

int kismetParse(const char* data) {
    char header[65];
	
    if (sscanf(data, "%64[^:]", header) < 1) {
        return 0;
    }
	
    unsigned int hdrlen = strlen(header) + 2;
    if (hdrlen >= strlen(data))
        return 0;
	
    if (!strncmp(header, "*TERMINATE", 64)) {
        kismValid = 0;
        ILOG("Server has terminated.\n");
        return -1;
    }
	else if (!strncmp(header, "*KISMET", 64)) {
		int		junkmajor, junkminor, junktiny;
		char	kismServername[32] = "";
		char	kismMajor[24] = "", kismMinor[24] = "", kismTiny[24] = "";
		char	build[24];
		int channel_hop;
        if (sscanf(data+hdrlen, "%d.%d.%d %d \001%32[^\001]\001 %24s %d "
                   "%24[^.].%24[^.].%24s",
                   &junkmajor, &junkminor, &junktiny, 
                   (int *) &kismServerStart, kismServername, 
                   build, &channel_hop,
                   kismMajor, kismMinor, kismTiny) < 7)
            return 0;
		ILOG("Connected to %s version %s.%s.%s",kismServername,kismMajor,kismMinor,kismTiny);
    }
	else if (!strncmp(header, "*PROTOCOLS", 64)) {
		char *last;
		char *proto;
		const char *sep = ",\n";

		// clear old protocol hash
		proto_hash_clear(&protocolMap);
		
		// list capabilities for each protocol
		for (proto = strtok_r((char*)data+hdrlen, sep, &last);
			 proto;
			 proto = strtok_r(NULL, sep, &last))
		{
			// list capabilities if protocol is interesting
			// if (findProtocol(proto)) {
				kismetListCapability(proto);
			// }
		}
	}
	else if (!strncmp(header, "*CAPABILITY", 64)) {		
		// return if we don't have a complete line
		char *fields = (char*)data+hdrlen;
		char* nl = strchr(fields,'\n');
		if(!nl)
			return 0;
		
		char *flast, *field;
		field = strtok_r(fields, " \n", &flast);
		k2oProtocol* proto = (k2oProtocol*)calloc(1,sizeof(k2oProtocol));
		strncpy(proto->name,field,sizeof(proto->name)-1);
		
		if (!strncmp(proto->name, "NETWORK", 64)) {
			proto->pfx_func = networkPrefix;
		}
		else if(!strncmp(proto->name, "CLIENT", 64)) {
			proto->pfx_func = clientPrefix;
		}
		else if(!strncmp(proto->name, "PACKET", 64)) {
			proto->pfx_func = packetPrefix;			
		}
		else {
			strtolow((char**)&proto->name);
			snprintf(proto->pfx,64,"%s/%s",kismPrefixPath,proto->name);
		}
		
		// create protocol fields
		field_list	fieldList = field_list_new();
		for (; field; field = strtok_r(NULL,",\n", &flast))
		{
			k2oProtoField* f = calloc(1,sizeof(k2oProtoField));
			strncpy(f->name,field,sizeof(f->name)-1);
			field_list_push_back(&fieldList,f);
		}
		proto->fields = fieldList;
		
		// create message templates
		mesg_list	messageList = mesg_list_new();
		
		// just create a message for each field for now
		field_list_iterator fi = field_list_first(fieldList);
		for( ; !field_list_done(fi); field_list_next(&fi)) {
			k2oProtoField* f = (k2oProtoField*)field_list_value(fi);
			k2oMessageTemplate* t = calloc(1,sizeof(k2oMessageTemplate));
			strncpy(t->pfx,f->name,sizeof(t->pfx)-1);
			t->fields = field_list_new();
			field_list_push_back(&t->fields,f);
		}

		proto->messages = messageList;

		// enable this protocol
		proto_hash_set(&protocolMap,proto->name,proto);
		kismetEnableProtocol(proto->name);
	}	
	else if (!strncmp(header, "*TIME", 64)) {
		time_t	serv_time;
        if (sscanf(data+hdrlen, "%d\n", (int *) &serv_time) < 1)
            return 0;
		
    }
	else if (!strncmp(header, "*STATUS", 64)) {
		char status[1024];
        if (sscanf(data+hdrlen, "%1023[^\n]\n", status) != 1)
           return 0;
		ILOG("%s", status);
    }
	else if (!strncmp(header, "*ERROR", 64)) {
        int discard;
		char status[1024];
        if (sscanf(data+hdrlen, "%d %1023[^\n]\n", &discard, status) != 2)
            return 0;
		ELOG("%s", status);
    }
	else if (!strncmp(header, "*ALERT", 64)) {
        char alrmstr[2048];
        char atype[128];
        long int in_tv_sec, in_tv_usec;
        if (sscanf(data+hdrlen, "%ld %ld %127s \001%2047[^\001]\001\n", &in_tv_sec,
                   &in_tv_usec, atype, alrmstr) < 3)
            return 0;
		WLOG("[%s] %s",atype,alrmstr);
    }
	else {
		// return if line is not complete
		char* fbuf = (char*)data+hdrlen;
		char* nl = strchr((char*)data+hdrlen,'\n');
		if(!nl) return 0;
		
		// check for the header without asterisk in the header map
		k2oProtocol *proto = (k2oProtocol*)proto_hash_get(protocolMap, &header[1]);
		if (!proto) {
			return 0;
		}
		
		// iterate thru field list of protocol and fill message template buffers
		field_list_iterator iter = field_list_first(proto->fields);
		for( ; !field_list_done(iter); field_list_next(&iter)) {
			k2oProtoField* f = (k2oProtoField*)field_list_value(iter);
			f->value = propernextvaluetype(&fbuf,&f->type,1);
		}

		// setup osc prefix path
		// this will either grab the value stored in a string member or compute
		// it with a function. e.g. for retreiving the correct value for net-
		// work and client messages
		char*	pfx = "";
		char	osc_pfx[64] = "";
		if (proto->pfx) {
			pfx = proto->pfx;
		}
		else if (proto->pfx_func) {
			(proto->pfx_func)(proto,(char**)&osc_pfx,sizeof(osc_pfx)-sizeof(char));
			pfx = osc_pfx;
		}
				
		// calculate timestamp
		struct timeval now;
		gettimeofday(&now,NULL);
		double dt = timeval_diff(now,startTime);

		// iterate thru message templates and output them
		mesg_list_iterator ti = mesg_list_first(proto->messages);
		for( ; !mesg_list_done(ti); mesg_list_next(&ti))
		{
			k2oMessageTemplate* t = (k2oMessageTemplate*)mesg_list_value(ti);
			
			// setup type string if nessesary
			if (!t->types_set) {
				int i = 0;
				LIST_ITERATE(field, t->fields, f,
					t->types[i] = ((k2oProtoField*)field_list_value(f))->type;
					i++;
				)
				t->types[i] = '\0';
			}
			
			// print osc prefix and types
			printf("%f %s/%s %s",dt,pfx,t->pfx,t->types);
			
			// iterate thru buffers
			LIST_ITERATE(field, t->fields, f,
				printf(" %s",((k2oProtoField*)field_list_value(f))->value);
			)
			printf("\n");
		}
    }	

    return 1;
}

int kismetSend(const char* data)
{
	if (!kismValid) {
		WLOG("kismetSend() on an inactive connection.");
        return -1;
    }
	
    strncat(writeBuf, data, kWriteBufLen - strlen(writeBuf) - 1);
	
    return 1;
}	

void kismetListProtocols(void) {
    char data[1024];
	
	snprintf(data, 1024, "!0 PROTOCOLS\n");
    kismetSend(data);
}

void kismetEnableProtocol(const char* protocol) {
    char data[1024];

	snprintf(data, 1024, "!0 ENABLE %s *\n", protocol);
    kismetSend(data);
}

void kismetListCapability(const char* protocol) {
    char data[1024];
	
	snprintf(data, 1024, "!0 CAPABILITY %s\n", protocol);
	DLOG("data: %s",data);
    kismetSend(data);
}

void strtolow(char** s) 
{
	char	*c;
	for(c = *s; *c; c++) {
		*c = tolower(*c);
	}
}

char* propernextvaluetype(char** ctx, char* type, int addNullChar)
{
	if((**ctx) == '\0') {
		return NULL;
	}
	
	int		quoted = 0;
	int		stringyness = 0; // 0-integer, 1-float, >1string
	char*	field = *ctx;
	char*	fchar;
	char	done = 0;
	
	// scan characters. 
	for (fchar = *ctx; *fchar && !done; fchar++) {
		switch(*fchar) {
			case '\001':
				quoted = 1 - quoted;
				(*fchar) = '"';
				stringyness = 2;
				break;
				
			case ' ':
				if(!quoted) {
					// close string and break if we found an unqouted space
					if (addNullChar) {
						*fchar = '\0';
					}
					done = 1;
				}
				break;
				
			case '.':
				// increment stringyness by one (float value and ip addresses)
				stringyness++;
				break;
				
			case ':':
				// mac addresses
				stringyness = 2;
				break;
				
			default:
				// increment stringyness
				if(!(isdigit(*fchar) || (fchar == *ctx && *fchar == '-')))
					stringyness = 2;
				break;
		}
	}
		
	// assign typechar
	if(type) {
		if(stringyness == 0) {
			*type = 'i';
		} else if (stringyness == 1) {
			*type = 'f';
		} else {
			*type = 's';
		}
	}
	
	// move context forward
	*ctx = fchar;
	
	// return read field
	return field;
}

int main (int argc, char **argv)
{
	char *kismethost = "localhost";
	int kismetport = 2501; // FIXME - DEFAULT PORT NUMBER
	
	static struct option long_options[] = {
	{ "kismethost",	required_argument, 0, 'k' },
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
		
		int c = getopt_long (argc, argv, "k:d:f:", long_options, &option_index);
		
		/* Detect the end of the options. */
		if (c == -1)
			break;
		
		switch (c)
		{				
			case 'k':
			{
				char *tmphost = NULL;
				int tmpport = 0;
				
				tmphost = strsep(&optarg,":");
				if(tmphost && tmphost[0])
					kismethost = tmphost;
				
				if(optarg && optarg[0]) {
					tmpport = (int)strtol(optarg, (char **)NULL, 0);
					if(tmpport) kismetport = tmpport;
				}
				break;
			}
				
			case 'f':
			{
				if(optarg && optarg[0]) {
					strncpy(kismPrefixPath,optarg,sizeof(kismPrefixPath)-1);
					DLOG("set osc message prefix to %s", kismPrefixPath);
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
			
			case 'h':
			case '?':
				usage(argv[0]);
				/* getopt_long already printed an error message. */
				break;
				
			default:
				abort ();
		}
	}
	
	// this command takes not command beside the options
	if(argc != optind)
		usage(argv[0]);
	
	// create server connection and wait for startup
	int err = kismetConnect(kismetport,kismethost);
	if(err < 1) {
		ELOG("Could not connect to %s:%d", kismethost, kismetport);
		catchTerm(-1);
	}
	ILOG("Connected to %s:%d", kismethost, kismetport);

	// Spin for 20 seconds until we get a header from the server, or die
	int header_count = 0;
	DLOG("Waiting for startup info ...");
	while (kismServerStart == 0) {
		if (kismValid)
			kismetPerformNetIO();
		
		if (header_count++ >= 20) {
			ELOG("did not get startup info from %s:%d within 20 seconds.",
					kismethost, kismetport);
			catchTerm(-1);
		}
		sleep(1);
	}
	ILOG("Got startup info from %s:%d",kismethost, kismetport);

	gettimeofday(&startTime,NULL);
	
	while(1) {
		int ret = kismetPerformNetIO();
		if(ret < 0)
			break;
		usleep(1000);
	}
	
	catchTerm(0);
	return 0;
}
