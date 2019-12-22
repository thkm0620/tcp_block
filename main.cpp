#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct eth_header{
	unsigned char dst_addr[6];
	unsigned char src_addr[6];
};

struct ip_header{
	unsigned char  header_len         :4; 
	unsigned char  version            :4;
	unsigned char  DSCP;   
	unsigned short total_len;
	unsigned short id;
	unsigned char  flags              :1;
	unsigned char  fragment_offset    :3;
	unsigned char  TTL;
	unsigned char  protocol;
	unsigned short checksum;
	unsigned char eth_addr[6];
	unsigned char ip_addr[6];
};

struct tcp_header{
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int   seq;
	unsigned int   ack;
	unsigned char  reserved          :4;
	unsigned char  offset            :4;	
	unsigned char  flags;	 
	unsigned short window;
	unsigned short checksum;
	unsigned short UP;
};

u_char* new_pkt(const unsigned char *packet, int packet_len){
	u_char* pkt;
	struct eth_header *eth=(struct eth_header *)packet;
	struct ip_header *iph;
	iph = (struct ip_header *)(packet+14);
	int iphlen=iph->header_len*4;
	struct tcp_header *tcph=(struct tcp_header *)(packet+14+iphlen);
	int tcphlen=tcph->offset * 4;
	tcph->flags = 17;
	memcpy(pkt, packet, packet_len);
	return pkt;
}

int main(int argc, char *argv[])
{
	char* dev=argv[1];
	char* host_name = argv[2];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle=pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	
	struct pcap_pkthdr *header;
	const unsigned char *data;

	if(handle == NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 0;
	}

	while(1){
		int res = pcap_next_ex(handle, &header,&data);
        	if (res == 0) continue;
        	if (res == -1 || res == -2) break;
		struct ip_header *iph=(struct ip_header *)(data+14);
		int iphlen=iph->header_len*4;
		struct tcp_header *tcph=(struct tcp_header *)(data+14+iphlen);
		int tcphlen=tcph->offset * 4;

		int findHost=0;
		while(findHost <= strlen((char *)data)){
		    if(!memcmp(data+findHost, "Host: ", 6)) break;
		    findHost++;
		}

		if(!memcmp(data+findHost+6,host_name,strlen(host_name))){
			u_char* pkt=new_pkt(data, header -> caplen);

			if(pcap_sendpacket(handle, pkt, sizeof(eth_header) + sizeof(ip_header) + sizeof(tcp_header))!=0){
				printf("pcap_sendpacket error");
			} else{
				printf("newpacket sent\n");
			}
		}
		
		
	}

	pcap_close(handle);
}
