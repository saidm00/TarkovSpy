#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>
//#include <Winsock>
#include <Winsock2.h>
#include <pthread.h>

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct
{
	ip_address dev_ip_raw;
} config_t;

/* IPv4 header */
typedef struct ip_header{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport,dport;
	time_t local_tv_sec;

	/*
	 * Unused variable
	 */
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

	/* print timestamp and length of the packet */
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	/* retireve the position of the ip header */
	ih = (ip_header *) (pkt_data +
		14); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xF) * 4;
	uh = (udp_header *) ((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs( uh->sport );
	dport = ntohs( uh->dport );

	/* print ip addresses and udp ports */
	printf("%hhu.%hhu.%hhu.%hhu:%hu -> %hhu.%hhu.%hhu.%hhu:%hu\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);


	
}

int main(int argc, char *argv[])
{
	int err;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	const char *pcap_version = pcap_lib_version();
    printf("Npcap version: %s\n", pcap_version);

	pcap_if_t *alldevs;
	config_t conf;
	conf.dev_ip_raw = (ip_address){ 192, 168, 137, 2 };
	pcap_t *devhdl;
    
    //config_t conf;

	//netdev = pcap_lookupdev(errbuf);

	//if (netdev == NULL)
	//{
	//	printf("Error finding device: %s\n", errbuf);
	//	return 1;
	//}

	/* Get device info */

	err = pcap_findalldevs(&alldevs, errbuf);
	if (err == -1)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	
	pcap_if_t *dev = &alldevs[0];
	pcap_if_t *src_dev;
	pcap_if_t *dst_dev;
	
	while (dev != NULL)
	{
		//char ip[13];
		char subnet_mask[13];
		bpf_u_int32 subnet_mask_raw; /* Subnet mask as integer */
		struct in_addr address; /* Used for both ip & subnet */

		printf("name: %s\n", dev->name);
		printf("description: %s\n", dev->description);

		pcap_addr_t *devaddr = &dev->addresses[0];

		while (devaddr != NULL)
		{
			if(devaddr->addr->sa_family == AF_INET)
			{
				char ip[16];
				struct sockaddr_in *addr = (struct sockaddr_in *)devaddr->addr;
				ip_address *ip_raw = (ip_address *)&addr->sin_addr;
				sprintf(ip, "%hhu.%hhu.%hhu.%hhu", ip_raw->byte1, ip_raw->byte2, ip_raw->byte3, ip_raw->byte4);

				printf("ip: %s\n", ip);

				if (memcmp((void *)&conf.dev_ip_raw, (void *)ip_raw, sizeof(ip_address)))
				{
					printf("Found source device with ip %s!\n", ip);
					src_dev= dev;
				}
			}

			devaddr = devaddr->next;
		}

		//sprintf(ip, "%hhu.%hhu.%hhu.%hhu", (uint8_t)(ip_raw >> 0), (uint8_t)(ip_raw >> 8), (uint8_t)(ip_raw >> 16), (uint8_t)(ip_raw >> 24));
		//printf("ip: %s\n", ip);

		putchar('\n');
		dev = dev->next;
	}

	/* Open the device */
	if ( (devhdl = pcap_open(src_dev->name, // name of the device
				65536, // portion of the packet to capture
					 // 65536 guarantees that the whole packet will be captured on all the link layers
				PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
				1000, // read timeout
				NULL, // authentication on the remote machine
				errbuf // error buffer
				) ) == NULL)
	{
		printf("Unable to open the adapter. %s is not supported by Npcap!\n", src_dev->name);
		return 1;
	}
	
	printf("Listening on %s...\n", src_dev->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	const char *filter = "ip and udp";
	struct bpf_program prog;
	err = pcap_compile(devhdl, &prog, filter, true, PCAP_NETMASK_UNKNOWN);

	err = pcap_setfilter(devhdl, &prog);

	pcap_loop(devhdl, 0, packet_handler, NULL);

	return 0;
}