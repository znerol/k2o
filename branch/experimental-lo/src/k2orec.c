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

// from kismet
enum crypt_type {
    crypt_none = 0,
    crypt_unknown = 1,
    crypt_wep = 2,
    crypt_layer3 = 4,
    // Derived from WPA headers
    crypt_wep40 = 8,
    crypt_wep104 = 16,
    crypt_tkip = 32,
    crypt_wpa = 64,
    crypt_psk = 128,
    crypt_aes_ocb = 256,
    crypt_aes_ccm = 512,
    // Derived from data traffic
    crypt_leap = 1024,
    crypt_ttls = 2048,
    crypt_tls = 4096,
    crypt_peap = 8192,
    crypt_isakmp = 16384,
    crypt_pptp = 32768
};
// constants
static const double torad = 2 * 3.1415927 / 360;

// types
typedef struct k2oProtoField k2oProtoField;
typedef struct k2oProtocol k2oProtocol;
typedef struct k2oMessageTemplate k2oMessageTemplate;

// callbacks
typedef int(*val_func_cb)(k2oProtocol*, k2oProtoField*);
typedef int(*pfx_func_cb)(k2oProtocol*, char*, int);

// field buffer structure
struct k2oProtoField {
	char		name[32];
	char*		value;
	val_func_cb	val_func;
	int			val_length;
	char		type;
};
DECLARE_LIST(k2oProtoField*,field)
DEFINE_LIST(k2oProtoField*,field)
DECLARE_HASH(field, char*, k2oProtoField*)
DEFINE_HASH(field, char*, k2oProtoField*, hash_string, string_equal)

// message template structure
struct k2oMessageTemplate{
	char		pfx[64];
	int			types_set;
	char		types[32];
	field_list	fields;			// list of k2oProtoField structures
};
DECLARE_LIST(k2oMessageTemplate*,mesg)
DEFINE_LIST(k2oMessageTemplate*,mesg)


// protocol structure
struct k2oProtocol {
	char		name[32];
	char		pfx[64];		// the osc prefix
	pfx_func_cb	pfx_func;       // this can also be a function (k2oProtocol,value string,lenght of value string)
	field_list	fields;			// fieldstruct
	field_hash	prepared;		// prepared fields
	field_list	functions;		// function fields. evaluated after numbers are 
								// read into fields list and before templates 
								// get processed.
	mesg_list	messages;		// osctemplate
};
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
DECLARE_LIST(kismNetwork*,net)
DEFINE_LIST(kismNetwork*,net)
DECLARE_HASH(net, char*, kismNetwork*)
DEFINE_HASH(net, char*, kismNetwork*, hash_string, string_equal)
net_hash		networkMap;
int				netcount = 0;

net_list		netDataRank;
net_list		netLlcRank;
net_list		netNoiseRank;

void** kismNetworks = NULL;
void** kismClients = NULL;

// gps data
double lat = 0.0, lon = 0.0, heading = 0.0;

// osc targets
#define maxotargets 10
int ocount = 0;
lo_address	otargets[maxotargets];

// outfile
FILE* outputfile =  NULL;

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
	fprintf(stderr,"Usage: %s [OPTION]\n", executable);
	fprintf(stderr,"\n"
" connects to a kismet_server and writes osc messages to stdout.\n\n"
" Options:\n"
" -k, --kismethost   <host:port> address and tcp port of kismet server. default\n"
"                    is localhost:2501\n"
" -f, --prefix       prefix path for received messages. standard is %s.\n"
" -o, --outfile      specify file to write osc messages to. use \"-\" for stdout\n"
" -t, --target       specify a target to send osc messages to it. multiple targets\n"
"                    are allowed\n"
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

int networkPrefix(k2oProtocol* proto, char* outPrefix, int outPrefixLength)
{
	k2oProtoField*	netidx = *field_hash_get(proto->prepared,"net_index");
	
	return snprintf(outPrefix, outPrefixLength,
					"%s/network/%s/", kismPrefixPath, netidx->value);
}

int clientPrefix(k2oProtocol* proto, char* outPrefix, int outPrefixLength)
{
	k2oProtoField*	netidx = NULL;
	k2oProtoField*	cliidx = NULL;
	if (!field_hash_contains_key(proto->prepared,"net_index") ||
		!(netidx = *field_hash_get(proto->prepared,"net_index")) ||
		!(netidx->value[0]) ||
		!(strcmp(netidx->value,"-1")) ||
		!field_hash_contains_key(proto->prepared,"client_index") ||
		!(cliidx = *field_hash_get(proto->prepared,"client_index")) ||
		!(cliidx->value[0]) ||
		!(strcmp(cliidx->value,"-1")) )
	{
		return snprintf(outPrefix, outPrefixLength,
						"%s/client/", kismPrefixPath);
	}
	else {
		return snprintf(outPrefix, outPrefixLength,
						"%s/network/%s/client/%s/",
						kismPrefixPath, netidx->value, cliidx->value);
	}
}

int packetPrefix(k2oProtocol* proto, char* outPrefix, int outPrefixLength)
{
	k2oProtoField*	netidx = NULL;
	if (!field_hash_contains_key(proto->prepared,"net_index") ||
		!(netidx = *field_hash_get(proto->prepared,"net_index")) ||
		!(netidx->value[0]) ||
		!(strcmp(netidx->value,"-1")) )
	{
		return snprintf(outPrefix, outPrefixLength,
						"%s/packet/", kismPrefixPath);
	}
	else {
		return snprintf(outPrefix, outPrefixLength,
						"%s/network/%s/packet/",
						kismPrefixPath, netidx->value);
	}
}

int cardPrefix(k2oProtocol* proto, char* outPrefix, int outPrefixLength)
{
	field_list_iterator fi = field_list_first(proto->fields);
	k2oProtoField*	cardid = NULL;
	
	char*			cid = "";
	for( ; !field_list_done(fi); field_list_next(&fi)) {
		cardid = *field_list_value(fi);
		if (strncmp(cardid->name,"id",sizeof(cardid->name) - 1)) {
			continue;
		}
		cid = cardid->value;
		break;
	}
	return snprintf(outPrefix, outPrefixLength,
						"%s/card/%s/",
						kismPrefixPath, cid);
}

int
packetRank(k2oProtocol* proto, k2oProtoField* field)
{
	// this is called from within a "network" protocol event.
	net_list	nlist;
	int			listfound = 0;
	
	if(!strncmp(field->name,"get_datarank",sizeof(field->name)-1)) {
		nlist = netDataRank;
		listfound = 1;
	}
	else if(!strncmp(field->name,"get_llcrank",sizeof(field->name)-1)) {
		nlist = netLlcRank;
		listfound = 1;
	}
	else if(!strncmp(field->name,"get_noiserank",sizeof(field->name)-1)) {
		nlist = netNoiseRank;
		listfound = 1;
	}
	
	if (listfound) {
		int i = 0;
		k2oProtoField *f = NULL;
		if (!field_hash_contains_key(proto->prepared,"net_index") ||
			!(f = *field_hash_get(proto->prepared,"net_index")) ) {
			return -1;
		}
		int netnum = atoi(f->value);
		LIST_ITERATE(net, nlist, n,
			if((*net_list_value(n))->index != netnum) {
				i++;
				continue;
			}
			break;
		)
		snprintf(field->value,sizeof(field->value)-1,"%d",i);
	}
	return 0;
}

int
netIndex(k2oProtocol* proto, k2oProtoField* field)
{
	k2oProtoField*	bssid = NULL;

	if (!field_hash_contains_key(proto->prepared,"bssid") ||
		!(bssid = *field_hash_get(proto->prepared,"bssid")) ) {
		return -1;
	}
	
	if (!strncmp(bssid->value,"00:00:00:00:00:00",18)) {
		// if bssid is not set then clear field value.
		return sprintf(field->value,"-1");
	}
	
	kismNetwork*	net = NULL;
	if(!net_hash_contains_key(networkMap,bssid->value)) {
		// copy key (!!!)
		char *key = calloc(1,strlen(bssid->value)+1);
		strncpy(key,bssid->value,strlen(bssid->value));
		// prepare value
		net = (kismNetwork*)calloc(1,sizeof(kismNetwork));
		net->index = netcount;
		net->clientCount = 0;
		net->clientMap = client_hash_new();
		// insert into hash and incrase netcount
		net_hash_set(&networkMap,key,net);
		net_list_push_back(&netDataRank,net);
		net_list_push_back(&netLlcRank,net);
		net_list_push_back(&netNoiseRank,net);
		netcount++;
	}
	else {
		net = *net_hash_get(networkMap,bssid->value);
	}
	return snprintf(field->value, field->val_length-1,"%d", net->index);
}

int
clientIndex(k2oProtocol* proto, k2oProtoField* field)
{
	k2oProtoField*	bssid = NULL;
	kismNetwork* net = NULL;
	k2oProtoField* mac = NULL;
	
	if (!field_hash_contains_key(proto->prepared,"bssid") ||
		!(bssid = *field_hash_get(proto->prepared,"bssid")) ||
		!net_hash_contains_key(networkMap,bssid->value) ||
		!(net = *net_hash_get(networkMap,bssid->value)) ||
		
		!field_hash_contains_key(proto->prepared,"mac") ||
		!(mac = *field_hash_get(proto->prepared,"mac")) ||
		!(mac->value[0]) )
	{
		return sprintf(field->value,"-1");
	}
	
	kismClient*	client = NULL;
	if (!client_hash_contains_key(net->clientMap,mac->value)) {
		// copy key (!!!)
		char *key = calloc(1,(strlen(mac->value)+1)*sizeof(char));
		strncpy(key,mac->value,strlen(mac->value));
		// prepare value
		client = (kismClient*)calloc(1,sizeof(kismClient));
		client->index = net->clientCount;
		// insert client into hash and incrase count
		client_hash_set(&net->clientMap,key,client);
		net->clientCount++;
	}
	else {
		client = *client_hash_get(net->clientMap,mac->value);
	}
	return snprintf(field->value, field->val_length-1,"%d", client->index);
}

int
setPacketRank(k2oProtocol* proto, k2oProtoField* field)
{
	// this is called from within a "network" protocol event with the type field.
	net_list*	nlist;
	
	switch(atoi(field->value)) {
		case -2: // noise
		case -1: // unknown
		{
			nlist = &netNoiseRank;
			break;
		}
		
		case 0: // management (llc)
		{
			nlist = &netLlcRank;
			break;
		}
		
		case 1: // phy
		case 2: // data
		{
			nlist = &netDataRank;
			break;
		}
		default:
			return -1;
			break;
	}
	
	int i = 0;
	k2oProtoField *f = NULL;
	if (!field_hash_contains_key(proto->prepared,"net_index") ||
		!(f = *field_hash_get(proto->prepared,"net_index")) ||
		!(f->value[0]) )
	{
		return -1;
	}
	int netnum = atoi(f->value);
	
	LIST_ITERATE(net, *nlist, n,
		if((*net_list_value(n))->index != netnum) {
			i++;
			continue;
		}
		kismNetwork *net = *net_list_value(n);
		net_list_remove(nlist,&n);
		net_list_push_front(nlist,net);
		break;
	)
	return 0;
}

int
setLocation(k2oProtocol* proto, k2oProtoField* field)
{
	k2oProtoField *latf,*lonf,*headf;
	if (!field_hash_contains_key(proto->prepared,"lat") ||
		!(latf = *field_hash_get(proto->prepared,"lat")) ||
		!(latf->value[0]) ||
		!field_hash_contains_key(proto->prepared,"lon") ||
		!(lonf = *field_hash_get(proto->prepared,"lon")) ||
		!(lonf->value[0]) ||
		!field_hash_contains_key(proto->prepared,"heading") ||
		!(headf = *field_hash_get(proto->prepared,"heading")) ||
		!(headf->value[0]) )
	{
		return -1;
	}
	lat = atof(latf->value);
	lon = atof(lonf->value);
	
	double h = atof(headf->value);
	if (h != 0.0) {
		heading = h * torad;
	}
	return 0;
}

int
localPosition(k2oProtocol* proto, k2oProtoField* field)
{
	k2oProtoField *locxf,*locyf,*locaf, *locdf,*agglatf,*agglonf,*aggpointsf;
	double agglat,agglon;
	int	aggpts;
	
	if (!field_hash_contains_key(proto->prepared,"local_x") ||
		!(locxf = *field_hash_get(proto->prepared,"local_x")) ||
		!field_hash_contains_key(proto->prepared,"local_y") ||
		!(locyf = *field_hash_get(proto->prepared,"local_y")) ||
		!field_hash_contains_key(proto->prepared,"local_a") ||
		!(locaf = *field_hash_get(proto->prepared,"local_a")) ||
		!field_hash_contains_key(proto->prepared,"local_d") ||
		!(locdf = *field_hash_get(proto->prepared,"local_d")) )
	{
		return -1;
	}
	
	if (!lat || !lon ||
		!field_hash_contains_key(proto->prepared,"aggpoints") ||
		!(aggpointsf = *field_hash_get(proto->prepared,"aggpoints")) ||
		!(aggpointsf->value[0]) || atoi(aggpointsf->value) == 0 ||
		
		!field_hash_contains_key(proto->prepared,"agglat") ||
		!(agglatf = *field_hash_get(proto->prepared,"agglat")) ||
		!field_hash_contains_key(proto->prepared,"agglon") ||
		!(agglonf = *field_hash_get(proto->prepared,"agglon")) )
	{
		sprintf(locxf->value,"0.0");
		sprintf(locyf->value,"0.0");
		sprintf(locaf->value,"0.0");
		sprintf(locdf->value,"0.0");
		return -1;
	}
	
	agglat = atof(agglatf->value);
	agglon = atof(agglonf->value);

	int x, y, a, d;
	
	static const double ue = 111195.0; // FIXME ????
	
	// calculate local distance, angle and relative position to viewer (gps).
	a = heading;
	y = (agglat - lat) * ue * cos(a);
	x = (agglon - lon) * ue * cos(lat*torad) * -sin(a);
	d = sqrt(pow(x,2) + pow(y,2));
	
	sprintf(locxf->value,"%f",x);
	sprintf(locyf->value,"%f",y);
	sprintf(locaf->value,"%f",a);
	return sprintf(locdf->value,"%f",d);
}

int
distRank(k2oProtocol* proto, k2oProtoField* field)
{
	return sprintf(field->value,"-1");
}

int
getInnocence(k2oProtocol* proto, k2oProtoField* field)
{
	k2oProtoField	*llcf,*datf,*cptf;
	int	llcv,datv,cptv;
	
	// calculates the innocence of a network
	if (!field_hash_contains_key(proto->prepared,"datapackets") ||
		!(datf = *field_hash_get(proto->prepared,"datapackets")) ||
		!(datf->value[0]) ||
		!field_hash_contains_key(proto->prepared,"llcpackets") ||
		!(llcf = *field_hash_get(proto->prepared,"llcpackets")) ||
		!(llcf->value[0]) ||
		!field_hash_contains_key(proto->prepared,"wep") ||
		!(cptf = *field_hash_get(proto->prepared,"wep")) ||
		!(cptf->value[0]) )
	{
		return -1;
	}
	
	datv = atoi(datf->value);
	llcv = atoi(llcf->value);
	
	int innoidx = 0;
	
	// 50% of innocent value is determined by the balance of management vs. data
	// packets
	if(llcv) {
		innoidx += 50.0*llcv/(llcv + datv);
	}
	
	cptv = atoi(cptf->value);
	if(!(cptv & crypt_wep)) {
		innoidx += 50;
	}
	else if(!(cptv & crypt_wpa)) {
		innoidx += 25;
	}
	
	return snprintf(field->value,field->val_length,"%d",innoidx);
}

k2oProtocol* protocol(char* name)
{
	// get proto from protocol map structure if it's contained
	k2oProtocol* proto = NULL;
	if (proto_hash_contains_key(protocolMap,name)) {
		proto = *proto_hash_get(protocolMap,name);
		return proto;
	}
	
	// create new protocol in protocol map otherwise
	proto = (k2oProtocol*)calloc(1,sizeof(k2oProtocol));
	strncpy(proto->name,name,sizeof(proto->name)-1);
	proto_hash_set(&protocolMap,proto->name,proto);

	if (!strncmp(proto->name, "NETWORK", 64)) {
		proto->pfx_func = networkPrefix;
	}
	else if(!strncmp(proto->name, "CLIENT", 64)) {
		proto->pfx_func = clientPrefix;
	}
	else if(!strncmp(proto->name, "PACKET", 64)) {
		proto->pfx_func = packetPrefix;			
	}
	else if(!strncmp(proto->name, "CARD", 64)) {
		proto->pfx_func = cardPrefix;
	}
	else {
		snprintf(proto->pfx,64,"%s/%s/",kismPrefixPath,proto->name);
		char* pfxname = &proto->pfx[strlen(kismPrefixPath)];
		strtolow(&pfxname);
	}
	
	// create protocol fields
	proto->fields = field_list_new();
	proto->messages = mesg_list_new();
	proto->prepared = field_hash_new();
	proto->functions = field_list_new();
	
	return proto;
}

void outputProtocolData(char* protocol,char* fieldbuffer)
{
	// check for the header without asterisk in the header map
	if (!proto_hash_contains_key(protocolMap,protocol)) {
		return;
	}
	k2oProtocol *proto = *proto_hash_get(protocolMap, protocol);
	
	// iterate thru field list of protocol and fill message template buffers
	field_list_iterator iter = field_list_first(proto->fields);
	k2oProtoField* ff = NULL;
	for( ; !field_list_done(iter); field_list_next(&iter)) {
		ff = *field_list_value(iter);
		ff->value = propernextvaluetype(&fieldbuffer,&ff->type,1);
	}

	// iterate thru protocol functions. functions store the result in the value 
	// variable of the field.
	LIST_ITERATE(field, proto->functions, f,
		k2oProtoField*	fld = *field_list_value(f);
		if (fld->val_func != NULL) {
			(fld->val_func)(proto,fld);
		}
	)
		
	// setup osc prefix path
	// this will either grab the value stored in a string member or compute
	// it with a function. e.g. for retreiving the correct value for net-
	// work, packet, card and client messages
	char*	pfx = "";
	char	osc_pfx[64] = "";
	if (proto->pfx_func != NULL) {
		(proto->pfx_func)(proto,osc_pfx,sizeof(osc_pfx)-1);
		pfx = osc_pfx;
	}
	else {
		pfx = proto->pfx;
	}
			
	// calculate timestamp
	struct timeval now;
	gettimeofday(&now,NULL);
	double dt = timeval_diff(now,startTime);

	// iterate thru message templates and output them
	mesg_list_iterator ti = mesg_list_first(proto->messages);
	for( ; !mesg_list_done(ti); mesg_list_next(&ti))
	{
		k2oMessageTemplate* t = *mesg_list_value(ti);
				
		// setup type string if nessesary
		if (!t->types_set) {
			int i = 0;
			LIST_ITERATE(field, t->fields, f,
				t->types[i] = (*field_list_value(f))->type;
				i++;
			)
			t->types[i] = '\0';
		}
		
		// setup prefix path
		char	pathprefix[128];
		strncpy(pathprefix,pfx,sizeof(pathprefix)-1);
		strncat(pathprefix,t->pfx,sizeof(pathprefix)-strlen(pathprefix));
		
		// iterate thru messages and output them to osc destinations
		if(ocount != 0) {
			lo_message*	m = NULL;
			m = lo_message_new();
			LIST_ITERATE(field, t->fields, f,
				char *val = (*field_list_value(f))->value;
				if (!val) {
					continue;
				}
				switch((*field_list_value(f))->type) {
					case LO_INT32:
					{
						int		v = (int)strtol(val,NULL,0);
						lo_message_add_int32(m,v);
						break;
					}
					case LO_FLOAT:
					{
						float	f = (float)strtod(val,NULL);
						lo_message_add_float(m,f);
						break;
					}
					case LO_STRING:
						lo_message_add_string(m,val);
						break;
				}
			)
			int i;
			for(i = 0 ; i < ocount ; i++) {
				DLOG("sending message %s",pathprefix);
				int ret = lo_send_message(otargets[i], pathprefix, m);
				if(ret < 0) {
					ELOG("%d, %s",ret,lo_address_errstr(otargets[i]));
				}
			}
			lo_message_free(m);
		}
		
		// print osc prefix and types
		if(outputfile) {
			fprintf(outputfile,"%f %s %s",dt,pathprefix,t->types);
		
			// iterate thru buffers
			LIST_ITERATE(field, t->fields, f,
				fprintf(outputfile," %s",(*field_list_value(f))->value);
			)
			fprintf(outputfile,"\n");
		}
	}
	
	char	bangpath[128];
	strncpy(bangpath,pfx,sizeof(bangpath)-1);
	strcat(bangpath,"bang");

	int i;
	for(i = 0 ; i < ocount ; i++) {
		DLOG("sending message %s",bangpath);
		lo_send(otargets[i],bangpath,"");
	}

	if(outputfile) {
		fprintf(outputfile,"%f %s\n",dt,bangpath);
	}
	fflush(outputfile);

}

void setupCapability(char* fieldbuffer)
{
	char *flast, *field;
	field = strtok_r(fieldbuffer, " \n", &flast);
	
	// get proto from protocol map structure if it's contained
	k2oProtocol* proto = protocol(field);

	// populate protocol field list
	while((field = strtok_r(NULL,",\n", &flast)))
	{
		k2oProtoField* f = NULL;
		if(field_hash_contains_key(proto->prepared,field)) {
			f = *field_hash_get(proto->prepared,field);
		}
		else {
			f = calloc(1,sizeof(k2oProtoField));
			strncpy(f->name,field,sizeof(f->name)-1);
		}
		field_list_push_back(&proto->fields,f);
	}
	
	// populate remaining message templates
	field_list_iterator fi = field_list_first(proto->fields);
	for( ; !field_list_done(fi); field_list_next(&fi)) {
		k2oProtoField* f = *field_list_value(fi);
		if (field_hash_contains_key(proto->prepared,f->name)) {
			continue;
		}
		
		k2oMessageTemplate* t = calloc(1,sizeof(k2oMessageTemplate));
		strncpy(t->pfx,f->name,sizeof(t->pfx)-1);
		t->fields = field_list_new();
		field_list_push_back(&t->fields,f);
		
		mesg_list_push_back(&proto->messages,t);
	}

	// enable the protocol
	kismetEnableProtocol(proto->name);
}

k2oProtoField*
addNewPreparedFieldBuffer(char* name, k2oMessageTemplate* t, k2oProtocol* p, int type, int bufferlen)
{
	k2oProtoField*	f = NULL;
	if (field_hash_contains_key(p->prepared,name)) {
		return NULL;
	}
	
	f = (k2oProtoField*)calloc(1,sizeof(k2oProtoField));
	strncpy(f->name,name,sizeof(f->name)-1);
	field_list_push_back(&t->fields,f);
	field_hash_set(&p->prepared,f->name,f);
	
	if (type) {
		f->type = type;
	}
	
	if(bufferlen) {
		f->value = calloc(1,bufferlen);
		f->val_length = bufferlen;
	}
	return f;
}

k2oProtoField*
addNewPreparedField(char* name, k2oMessageTemplate* t, k2oProtocol* p)
{
	return addNewPreparedFieldBuffer(name,t,p,0,0);
}

k2oProtoField*
addNewPreparedFunctionBuffer(char* name, val_func_cb func, k2oMessageTemplate* t, k2oProtocol* p, int type, int bufferlen)
{
	k2oProtoField*	f = addNewPreparedFieldBuffer(name,t,p,type,bufferlen);
	if (f) {
		f->val_func = func;
		field_list_push_back(&p->functions,f);
	}
	return f;
}

k2oProtoField*
addNewPreparedFunction(char* name, val_func_cb func, k2oMessageTemplate* t, k2oProtocol* p)
{
	return addNewPreparedFunctionBuffer(name,func,t,p,0,0);
}

k2oMessageTemplate*
addNewTemplate(char* pfx,k2oProtocol* p)
{
	k2oMessageTemplate* t = NULL;
	t = calloc(1,sizeof(k2oMessageTemplate));
	strncpy(t->pfx,pfx,sizeof(t->pfx)-1);
	t->fields = field_list_new();
	mesg_list_push_back(&p->messages,t);
	return t;
}

void prepareProtocolMap(void)
{
	protocolMap = proto_hash_new();
	
	k2oProtocol* p = NULL;
	k2oMessageTemplate* t = NULL;
	
	// GPS
	p = protocol("GPS");
	
	// message template for "/gps/pos fff lat lon alt"
	t = addNewTemplate("pos",p);
	addNewPreparedField("lat",t,p);
	addNewPreparedField("lon",t,p);
	addNewPreparedField("heading",t,p);
	addNewPreparedFunction("alt",setLocation,t,p);
		
	// NETWORK
	p = protocol("NETWORK");
	
	// add bssid to prepared fields, so the network number can be calculated
	t = addNewTemplate("bssid",p);
	addNewPreparedField("bssid",t,p);
	
	// calculate network index number
	t = addNewTemplate("net_index",p);
	addNewPreparedFunctionBuffer("net_index",netIndex,t,p,LO_INT32,8);
	
	// message template for "/network/x/minpos fff lat lon alt"
	t = addNewTemplate("minpos",p);
	addNewPreparedField("minlat",t,p);
	addNewPreparedField("minlon",t,p);
	addNewPreparedField("minalt",t,p);
	
	// message template for "/network/x/maxpos fff lat lon alt"
	t = addNewTemplate("maxpos",p);
	addNewPreparedField("maxlat",t,p);
	addNewPreparedField("maxlon",t,p);
	addNewPreparedField("maxalt",t,p);
	
	// message template for "/network/x/bestpos fff lat lon alt"
	t = addNewTemplate("bestpos",p);
	addNewPreparedField("bestlat",t,p);
	addNewPreparedField("bestlon",t,p);
	addNewPreparedField("bestalt",t,p);
	
	// message template for "/network/x/aggpos fffi lat lon alt points"
	t = addNewTemplate("aggpos",p);
	addNewPreparedField("agglat",t,p);
	addNewPreparedField("agglon",t,p);
	addNewPreparedField("aggalt",t,p);
	addNewPreparedField("aggpoints",t,p);
	
	// message template for calculated local position (x y angle distance)
	t = addNewTemplate("localpos",p);
	addNewPreparedFieldBuffer("local_x",t,p,LO_FLOAT,16);
	addNewPreparedFieldBuffer("local_y",t,p,LO_FLOAT,16);
	addNewPreparedFieldBuffer("local_a",t,p,LO_FLOAT,16);
	addNewPreparedFunctionBuffer("local_d",localPosition,t,p,LO_FLOAT,16);

	// message templates for packet counters
	t = addNewTemplate("packets/data",p);
	addNewPreparedField("datapackets",t,p);
	t = addNewTemplate("packets/llc",p);
	addNewPreparedField("llcpackets",t,p);
	t = addNewTemplate("packets/crypt",p);
	addNewPreparedField("cryptpackets",t,p);
	t = addNewTemplate("packets/weak",p);
	addNewPreparedField("weakpackets",t,p);
	t = addNewTemplate("packets/dupeiv",p);
	addNewPreparedField("dupeivpackets",t,p);
	
	// message templates for signal meter
	t = addNewTemplate("signal/quality",p);
	addNewPreparedField("quality",t,p);
	t = addNewTemplate("signal/power",p);
	addNewPreparedField("signal",t,p);
	t = addNewTemplate("signal/noise",p);
	addNewPreparedField("noise",t,p);
	t = addNewTemplate("bestsignal/quality",p);
	addNewPreparedField("bestquality",t,p);
	t = addNewTemplate("bestsignal/power",p);
	addNewPreparedField("bestsignal",t,p);
	t = addNewTemplate("bestsignal/noise",p);
	addNewPreparedField("bestnoise",t,p);
	
	// message templates calculated statistic functions
	t = addNewTemplate("wep",p);	// wep is needed by innocence
	addNewPreparedField("wep",t,p);
	t = addNewTemplate("stat/innocence",p);
	addNewPreparedFunctionBuffer("get_innocence",getInnocence,t,p,LO_INT32,8);
	
	t = addNewTemplate("stat/distrank",p);
	addNewPreparedFunctionBuffer("get_distrank",distRank,t,p,LO_INT32,8);
	t = addNewTemplate("stat/datarank",p);
	addNewPreparedFunctionBuffer("get_datarank",packetRank,t,p,LO_INT32,8);
	t = addNewTemplate("stat/llcrank",p);
	addNewPreparedFunctionBuffer("get_llcrank",packetRank,t,p,LO_INT32,8);
	t = addNewTemplate("stat/noiserank",p);
	addNewPreparedFunctionBuffer("get_noiserank",packetRank,t,p,LO_INT32,8);
	
	// same for CLIENT here
	p = protocol("CLIENT");
	// add bssid to prepared fields, so the network number can be calculated
	t = addNewTemplate("bssid",p);
	addNewPreparedField("bssid",t,p);
	
	// add a net index value, so we can match packets to networks
	t = addNewTemplate("net_index",p);
	addNewPreparedFunctionBuffer("net_index",netIndex,t,p,LO_INT32,8);
	
	// add a client index value, so we can match things to clients
	t = addNewTemplate("client_index",p);
	addNewPreparedFunctionBuffer("client_index",clientIndex,t,p,LO_INT32,8);
	
	// message template for "/client/x/minpos fff lat lon alt"
	t = addNewTemplate("minpos",p);
	addNewPreparedField("minlat",t,p);
	addNewPreparedField("minlon",t,p);
	addNewPreparedField("minalt",t,p);
	
	// message template for "/client/x/maxpos fff lat lon alt"
	t = addNewTemplate("maxpos",p);
	addNewPreparedField("maxlat",t,p);
	addNewPreparedField("maxlon",t,p);
	addNewPreparedField("maxalt",t,p);
	
	// message template for "/client/x/bestpos fff lat lon alt"
	t = addNewTemplate("bestpos",p);
	addNewPreparedField("bestlat",t,p);
	addNewPreparedField("bestlon",t,p);
	addNewPreparedField("bestalt",t,p);
	
	// message template for "/client/x/aggpos fffi lat lon alt points"
	t = addNewTemplate("aggpos",p);
	addNewPreparedField("agglat",t,p);
	addNewPreparedField("agglon",t,p);
	addNewPreparedField("aggalt",t,p);
	addNewPreparedField("aggpoints",t,p);
	
	// message templates for packet counters
	t = addNewTemplate("packets/data",p);
	addNewPreparedField("datapackets",t,p);
	// no llc counter for client
	t = addNewTemplate("packets/crypt",p);
	addNewPreparedField("cryptpackets",t,p);
	t = addNewTemplate("packets/weak",p);
	addNewPreparedField("weakpackets",t,p);
	// no dupeiv for client
	
	// message templates for signal meter
	t = addNewTemplate("signal/quality",p);
	addNewPreparedField("quality",t,p);
	t = addNewTemplate("signal/power",p);
	addNewPreparedField("signal",t,p);
	t = addNewTemplate("signal/noise",p);
	addNewPreparedField("noise",t,p);
	t = addNewTemplate("bestsignal/quality",p);
	addNewPreparedField("bestquality",t,p);
	t = addNewTemplate("bestsignal/power",p);
	addNewPreparedField("bestsignal",t,p);
	t = addNewTemplate("bestsignal/noise",p);
	addNewPreparedField("bestnoise",t,p);
	
	// PACKET
	p = protocol("PACKET");
	
	// add bssid to prepared fields, so the network number can be calculated
	t = addNewTemplate("bssid",p);
	addNewPreparedField("bssid",t,p);
	
	// add a net index value, so we can match packets to networks
	t = addNewTemplate("net_index",p);
	addNewPreparedFunctionBuffer("net_index",netIndex,t,p,LO_INT32,8);
	
	// insert a "type" template here which triggers the setPacketRank function
	t = addNewTemplate("type",p);
	addNewPreparedFunction("type",setPacketRank,t,p);
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

		// list capabilities for each protocol
		for (proto = strtok_r((char*)data+hdrlen, sep, &last);
			 proto;
			 proto = strtok_r(NULL, sep, &last))
		{
			// list capabilities if protocol is interesting
			kismetListCapability(proto);
		}
	}
	else if (!strncmp(header, "*CAPABILITY", 64)) {		
		// return if we don't have a complete line
		char *fbuf = (char*)data+hdrlen;
		char* nl = strchr(fbuf,'\n');
		if(!nl)
			return 0;
		
		setupCapability(fbuf);
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
		char* nl = strchr((char*)fbuf,'\n');
		if(!nl) return 0;
		
		// output protocol data to desired destinations
		outputProtocolData(&header[1],fbuf);
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
				// workaround a bug in kismet where end of a c string is escaped !!!
				if (quoted &&
					fchar - field > sizeof(char) * 2 &&
					*(fchar-sizeof(char)) == '0' &&
					*(fchar-sizeof(char)*2) == '\\') {
					quoted = 1 - quoted;
					*(fchar-sizeof(char)) = '"';
				}
				if (quoted) {
					break;
				}
			case '\n':
				// close string and break if we found an unqouted space or 
				// newline
				if (addNullChar) {
					*fchar = '\0';
				}
				done = 1;
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
				if (!(isdigit(*fchar) || (fchar == *ctx && *fchar == '-'))) {
					stringyness = 2;
				}
				if (!isprint(*fchar)) {
					*fchar = '?';
				}
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
	{ "target",	required_argument, 0, 't' },
	{ "outfile", required_argument, 0, 'o' },
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
		
		int c = getopt_long (argc, argv, "k:d:f:t:o:", long_options, &option_index);
		
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
			
			case 't':
			{
				// add an osc target
				if (ocount < maxotargets && optarg && optarg[0]) {
					otargets[ocount] = lo_address_new_from_url(optarg);
					if(!otargets[ocount]) {
						ELOG("failed to setup target for %s", optarg);
						catchTerm(-1);
					}
					ILOG("setup target for %s", optarg);
					ocount++;
				}
				break;
			}
			
			case 'o':
			{
				// open outputfile. use - for stdout
				if (optarg && optarg[0]) {
					if(optarg[0] == '-') {
						outputfile = stderr;
						ILOG("output will go to stdout");
					}
					else {
						outputfile = fopen(optarg,"w");
						if(outputfile == NULL) {
							ELOG("failed to open outpu file %s: %s (%d)",
								optarg,strerror(errno),errno);
							catchTerm(-1);
						}
						ILOG("opened output file %s", optarg);
					}
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
	
	// sanity check arguments
	if (outputfile == NULL && ocount == 0) {
		ELOG("you did not specify any output method!");
		usage(argv[0]);
	}
	
	// initialize global lists and hashes
	prepareProtocolMap();
	//protocolMap = proto_hash_new();
	networkMap = net_hash_new();
	netDataRank = net_list_new();
	netLlcRank = net_list_new();
	netNoiseRank = net_list_new();

	
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
