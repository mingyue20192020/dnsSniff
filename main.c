#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <assert.h>   
#include <libmemcached/memcached.h>
#include <mysql/mysql.h>

#define MAX_CAP 512
#define CONFIGFILE	"./config"

#define COMMONCONTENT_1 "" 

#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0],\
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3] 


const char * gSniffEth="eth2";//local,jiang'xi'tie'tong,

pcap_t * ghSniff=0;
const char * gSendEth="eth2";//jiang'xi'tie'tong,hai nan,pu tian


pcap_t * ghSender=0;

#ifdef ROUTEMAC
char gaRouteMac[ETH_ALEN]={ROUTEMAC};
#else
char gaRouteMac[ETH_ALEN]={0x00,0x50,0x56,0xe8,0x60,0xae};//

#endif
#ifdef IFMAC
char gaIFMac[ETH_ALEN]={IFMAC}; 
#else 
//wang ka
char gaIFMac[ETH_ALEN]={0x00,0x00,0x00,0x00,0x00,0x00};//   


#endif


int gDebugLv=1;
enum {NUL=0,QUIT,RELOAD,DUMP} gFunc;
struct timeval gTime={0};
struct tm gTM={0};
static char *pHost="127.0.0.1",*pUser="root",*pPassword="kmip123";


static MYSQL ghMysql;


struct DNS_HEADER {
    unsigned short id; //
    unsigned char rd :1; // 
    unsigned char tc :1; // 
    unsigned char aa :1; // 
    unsigned char opcode :4; 
    unsigned char qr :1; //  
    unsigned char rcode :4; //
    unsigned char cd :1; 
    unsigned char ad :1; 
    unsigned char z :1; //
    unsigned char ra :1; // 
    unsigned short q_count; // 
    unsigned short ans_count; // 
    unsigned short auth_count; // 
    unsigned short add_count; // 
};


void Quit(int SigNo)
{
	gFunc=QUIT;
	pcap_breakloop(ghSniff);
}

void Reload(int SigNo)
{
	gFunc=RELOAD;
	pcap_breakloop(ghSniff);
}

void Dump(int SigNo)
{
	gFunc=DUMP;
	pcap_breakloop(ghSniff);
}

int setSniffer()
{
	char aErrBuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;

	if(ghSniff) pcap_close(ghSniff);

	ghSniff=pcap_open_live(gSniffEth,MAX_CAP,1,10,aErrBuf);

	if(ghSniff==NULL)
	{
		printf("pcap_open_live():%s\n",aErrBuf);
		exit(-1);
	}
	printf("open device successful\n");
   if(pcap_compile(ghSniff,&filter,"udp dst port 53",1,PCAP_NETMASK_UNKNOWN)==-1) 
    {
		printf("Error on pcap_compile\n");
		exit(-1);
	}
	printf("compile successful\n");

	if(pcap_setfilter(ghSniff,&filter)==-1)
	{
		printf("Error no pcap_setfilter\n");
		exit(-1);
	}
	printf("setfilter successful\n");
    if(gDebugLv==0){
        if(pcap_setdirection(ghSniff,PCAP_D_IN)==-1)
        {
            printf("No Support on set direction");
        }
    }

}

int initVars()
{
    	int rc;
	//????????
	setlinebuf(stdout);

	//??????
	gettimeofday(&gTime,NULL);
	localtime_r(&gTime.tv_sec,&gTM);

	//????????????
	char * p;
	if(p=getenv("ROUTEMAC")) sscanf(p,"%2hhX%2hhX%2hhX%2hhX%2hhX%2hhX",&gaRouteMac[0],&gaRouteMac[1],&gaRouteMac[2],&gaRouteMac[3],&gaRouteMac[4],&gaRouteMac[5]);
	if(p=getenv("IFMAC")) sscanf(p,"%2hhX%2hhX%2hhX%2hhX%2hhX%2hhX",&gaIFMac[0],&gaIFMac[1],&gaIFMac[2],&gaIFMac[3],&gaIFMac[4],&gaIFMac[5]);
	if(p=getenv("SNIFFETH")) gSniffEth=p;
	if(p=getenv("SENDETH")) gSendEth=p;
	if(p=getenv("DEBUGLEVEL")) gDebugLv=atoi(p);

    return 0;
}


static void parse_dns_name(unsigned char *ptr , char *out , int *len)
{
	int n , alen , flag;
	char *pos = out + (*len);
	for(;;){
		flag = (int)ptr[0];
		if(flag == 0){//*pos = 0;
			break;
        }
		ptr++;
		memcpy(pos , ptr , flag);
		pos += flag;
		ptr += flag;
		*len += flag;
		if((int)ptr[0] != 0){
			memcpy(pos , "." , 1);
			pos += 1;
			(*len) += 1;
		}
	}
}


void analyzeDns(u_char * pUserChar,const struct pcap_pkthdr* pstPktHdr,const u_char * packet)
{
    struct ether_header *pEther=(void*)packet;
	struct iphdr * pIpHdr=(void*)(packet+14);
    struct udphdr * pUdpHdr=(void*)(pIpHdr)+(pIpHdr->ihl<<2);
    char url_domain[64] = "";
    struct DNS_HEADER * dnsHeader=(void*)(pUdpHdr+1); 
    u_char *pData=(void*)(dnsHeader+1);
    int domain_len = 0;
    memset(url_domain, 0, sizeof(url_domain));
    parse_dns_name(pData, url_domain, &domain_len);
    printf("url_domain-------%s\n", url_domain); 
    inject(pEther,pIpHdr,pUdpHdr,dnsHeader,pData);
}

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register int sum=0;
	u_short oddbyte;
        
	while(nbytes>1){
        	sum+=*ptr++;
	        nbytes-=2;    
	}
	if(nbytes==1){
        	oddbyte=0;
	        *(u_char *)(&oddbyte)=*(u_char *)ptr;
        	sum+=oddbyte;
	}               
	sum = (sum >> 16) + (sum & 0xFFFF);
	return ~(sum  + (sum >> 16)) & 0xFFFF;
}

unsigned short ip_in_cksum(struct iphdr *iph, unsigned short *ptr, int nbytes)
{
	register int sum = 0;
	u_short oddbyte;
	int pheader_len;
	unsigned short *pheader_ptr;
	
	struct pseudo_header {
		unsigned int saddr;
		unsigned int daddr;
		unsigned char null;
		unsigned char proto;
		unsigned short tlen;
	} pheader;
	
	pheader.saddr = iph->saddr;
	pheader.daddr = iph->daddr;
	pheader.null = 0;
	pheader.proto = iph->protocol;
	pheader.tlen = htons(nbytes);
	
	pheader_ptr = (unsigned short *)&pheader;
	for (pheader_len = sizeof(pheader); pheader_len; pheader_len -= 2) {
		sum += *pheader_ptr++;
	}
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*(u_char *) (& oddbyte) = *(u_char *) ptr;
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	return ~(sum  + (sum >> 16)) & 0xFFFF;
}



int inject(struct ether_header *pEthSrc,struct iphdr *pIpSrc,struct udphdr *pUdpSrc,struct DNS_HEADER * dnsHeaderSrc,char *dnsQueryData)
{

    int rc;
    char gSendBuf[512]={0}; 
    struct ether_header *pEth;
    pEth = (void *)gSendBuf; 
	struct iphdr *pIp=(void*)(pEth+1);
	struct udphdr *pUdp=(void*)(pIp+1);
    struct DNS_HEADER * dnsHeader=(void*)(pUdp+1); 
	char * pData=(void*)(dnsHeader+1);
    strcpy(pData,dnsQueryData);   
    int DataLen=strlen(pData);
    memcpy(pEth->ether_dhost,gaRouteMac,ETH_ALEN);
	memcpy(pEth->ether_shost,gaIFMac,ETH_ALEN);
    pEth->ether_type=htons(ETH_P_IP);

    pIp->version=4;
	pIp->ihl=5;
	pIp->ttl=64;
	pIp->protocol=IPPROTO_UDP;
    pIp->tot_len=htons(sizeof(struct iphdr)+sizeof(struct udphdr)+sizeof(struct DNS_HEADER)+DataLen);
	pIp->saddr=pIpSrc->daddr;
	pIp->daddr=pIpSrc->saddr;
	pIp->id=pIpSrc->id;
	pIp->check=0;
	pIp->check=in_cksum((void*)pIp,20);
    

    char aUserIP[16];
	sprintf(aUserIP,"%d.%d.%d.%d",NIPQUAD(pIp->saddr));
    printf("aUserIP-------%s\n", aUserIP); 
    printf("id-------%d\n",DataLen); 


	pUdp->source=pUdpSrc->dest;
	pUdp->dest=pUdpSrc->source;
    pUdp->len=htons(sizeof(struct udphdr)+sizeof(struct DNS_HEADER)+DataLen);
    pUdp->check=0;
	pUdp->check=ip_in_cksum((void*)pIp,(void*)pUdp,sizeof(struct udphdr)+sizeof(struct DNS_HEADER)+DataLen);
    dnsHeader->id=dnsHeaderSrc->id;
    dnsHeader->qr=1;
    if(gDebugLv==0){
        rc=pcap_inject(ghSender,gSendBuf,sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct udphdr)+sizeof(struct DNS_HEADER)+DataLen);
    }else{
        rc=pcap_inject(ghSniff,gSendBuf,sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct udphdr)+sizeof(struct DNS_HEADER)+DataLen);//local
    } 
}


int main()
{
    int rc;
    struct pcap_pkthdr hdr;
	struct pcap_stat ps;
    
	sigset_t sigs;
    do
	{
		rc=initVars();
		if(rc!=0)
		{
			printf("Init failed...\n");
			sleep(60);
		}
	}while(rc!=0);
	signal(SIGINT,Quit);
	signal(SIGTERM,Quit);
	signal(SIGHUP,Reload);
	signal(SIGALRM,Reload);
	signal(SIGUSR1,Dump);
	while(1)
	{		switch(gFunc)
		{
            case QUIT:
				exit(0);
				break;
			case RELOAD:
				break;
		}
		setSniffer();
		gFunc=NUL;
		pcap_loop(ghSniff,100000000,analyzeDns,NULL);
        pcap_stats(ghSniff, &ps); 
        printf("\nstatistics:\n\tps_recv:%u\n\tps_drop:%u\n\tps_ifdrop:%u\n",ps.ps_recv,ps.ps_drop,ps.ps_ifdrop);
		gettimeofday(&gTime,NULL);
		localtime_r(&gTime.tv_sec,&gTM);
	}
	exit(0);
}
