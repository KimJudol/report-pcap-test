#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "packet_header.h"

#define MAX_LEN 20
#define TCP 6

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void packet_info(const u_char* packet)
{
		ethernet_header *eth_hdr;
		ip_header *ip_hdr;
		tcp_header *tcp_hdr;
		uint8_t *payload;

		eth_hdr = (ethernet_header *)packet;

		ip_hdr = (ip_header *)(packet + sizeof(ethernet_header));
		uint8_t ip_size = ( ip_hdr->ver_ihl & 0x000000F ) * 4;

		tcp_hdr = (tcp_header *)(packet + sizeof(ethernet_header) + ip_size);
		uint8_t tcp_hdr_size = (tcp_hdr->data_offset_reserved >> 4) * 4;

		payload = (uint8_t *)(packet + sizeof(ethernet_header) + ip_size + tcp_hdr_size);

				if(ip_hdr->protocol == TCP ){
		printf("<TCP Packet Information>\n");
		// Ethernet Header
		printf("src MAC: ");
		for(int i = 0; i < 6; i++){
			if(i<5) printf("%02x:", eth_hdr->src_mac[i]);
			else printf("%02x", eth_hdr->src_mac[i]);
		}
		printf("\n");
		printf("dst MAC: ");
		for(int i = 0; i < 6; i++){
			if(i<5) printf("%02x:", eth_hdr->dst_mac[i]);
			else printf("%02x\n", eth_hdr->dst_mac[i]);
		}

		// IP header
		printf("src IP: ");
		for(int i = 0 ; i < 4; i++){
			if(i < 3) printf("%d.", ip_hdr->src_ip[i]);
			else printf("%d\n", ip_hdr->src_ip[i]);
		}
		printf("dst IP: ");
		for(int i = 0 ; i < 4; i++){
			if(i < 3) printf("%d.", ip_hdr->dst_ip[i]);
			else printf("%d\n", ip_hdr->dst_ip[i]);
		}

		// TCP header
		printf("src Port: %d\n", ntohs(tcp_hdr->src_port));
		printf("dst Port: %d\n", ntohs(tcp_hdr->dst_port));
		
		if((sizeof(ethernet_header) + ip_size + tcp_hdr_size) < ntohs(ip_hdr->total_len))
		{		
			// payload
			printf("payload: ");
		for(int i =0; i< MAX_LEN; i++){
			printf("%02x", payload[i]);
		}
		printf("\n\n");
		}
		else{
			printf("There is no payload.\n\n");
		}


		}

}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		packet_info(packet);
	}

	pcap_close(pcap);
}
