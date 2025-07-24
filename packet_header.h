#include <stdbool.h>
#include <stdio.h>

#define ETH_ALEN 6 
#define IP_ALEN 4
#define OP_LEN 12

typedef struct {
	uint8_t dst_mac[ETH_ALEN];
	uint8_t src_mac[ETH_ALEN];
	uint16_t EtherType;
} ethernet_header;

typedef struct {
	uint8_t ver_ihl;
	uint8_t dscp_ecn;
	uint16_t total_len;
	uint16_t identification;
	uint16_t flags_fragment_offset;
	uint8_t T2L;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t dst_ip[IP_ALEN];
	uint8_t src_ip[IP_ALEN];
} ip_header;

typedef struct {
	uint16_t dst_port;
	uint16_t src_port;
	uint32_t sequence_num;
	uint32_t ack_num;
	uint8_t data_offset_reserved;
	uint8_t flags;
	uint16_t window;
	uint8_t checksum;
	uint8_t urg_pointer;
	uint8_t options[OP_LEN];
} tcp_header;