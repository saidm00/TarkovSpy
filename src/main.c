// Test memory leak with nuklear
#define NK_INCLUDE_STANDARD_IO
#define NK_INCLUDE_FIXED_TYPES
#define NK_INCLUDE_DEFAULT_ALLOCATOR
#define NK_INCLUDE_VERTEX_BUFFER_OUTPUT
#define NK_INCLUDE_FONT_BAKING
#define NK_KEYSTATE_BASED_INPUT

#define NK_IMPLEMENTATION
#include "nuklear.h"




#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#include <glad/glad.h>

#define NK_GLFW_GL3_IMPLEMENTATION
#include "nuklear_glfw_gl3.h"

#include <pcap.h> //peniscap
#include <glm/glm.h>

#include "common.h"
#include "ini.h"
#include "unet.h"

#include "world.h"
#include "bytestream.h"
#include "network.h"

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#define ARRAY_LENGTH(x) (sizeof(x)/sizeof((x)[0]))

typedef struct Logger
{
	struct nk_text_edit edit;
	mtx_t mutex;
} Logger;

static Logger debugLogger;

static unsigned int CountNewLinesInString(const char *s)
{
	char *p = &s[0];
	unsigned int k = 0;
	while (*p != '\0')
	{
		if (*p == '\n') ++k;
		++p;
	}

	return k;
}

static void DebugLog(const char *fmt, ...)
{
	char buffer[1024] = {0};
	va_list args;
	va_start(args, fmt);

	vsprintf(buffer, fmt, args);

	mtx_lock(&debugLogger.mutex);
	debugLogger.edit.mode = NK_TEXT_EDIT_MODE_INSERT;
	nk_textedit_paste(&debugLogger.edit, buffer, strlen(buffer));
	mtx_unlock(&debugLogger.mutex);

	vfprintf(stdout, fmt, args);

	va_end(args);
}

static size_t gNkMemTestAllocated = 0;
static size_t gNkMemTestFreed = 0;
static float gNkMemTestPrintInterval = 10.0f;
static float gNkMemTestTimeSinceLastPrint = 0.0f;
static float gNkMemTestLastTime = 0.0f;
static float gNkMemTestCurrentTime = 0.0f;

NK_LIB void* nk_malloc(nk_handle unused, void *old, nk_size size)
{
    NK_UNUSED(unused);
    NK_UNUSED(old);
    ++gNkMemTestAllocated;
    return malloc(size);
    //return (old != NULL) ? realloc(old, size) : malloc(size);
}

NK_LIB void nk_mfree(nk_handle unused, void *ptr)
{
    NK_UNUSED(unused);
    ++gNkMemTestFreed;
    free(ptr);
}


typedef struct ByteBuffer
{
	uint8_t *data;
	size_t size;
} ByteBuffer;


static const size_t MAX_CHANNEL_ID = 3 + (102*2);
static const size_t MAX_FRAGMENTED_MESSAGES = 4096;

typedef struct MessageFragment
{
	size_t size;
	uint8_t *data;
} MessageFragment;

static void InitializeMessageFragment(MessageFragment *fragment, size_t size, const void *data)
{
	fragment->data = malloc(size);
	fragment->size = size;
	memcpy((void *)fragment->data, data, size);
}

static void DestroyMessageFragment(MessageFragment *fragment)
{
	free((void *)fragment->data);
	fragment->size = 0;
	fragment->data = NULL;
}

/*
typedef struct FragmentedMessage
{
	StretchyArray fragments;
} FragmentedMessage;

static void InitializeFragmentedMessage(FragmentedMessage *message)
{
	InitializeStretchyArray(&message->fragments, sizeof(MessageFragment));
}

static void DestroyFragmentedMessage(FragmentedMessage *message)
{
	DestroyStretchyArray(&message->fragments);
}*/


/* 4 bytes IP address */
typedef struct ip_address
{
	uint8_t byte1;
	uint8_t byte2;
	uint8_t byte3;
	uint8_t byte4;
} ip_address_t;

typedef struct
{
	ip_address_t network_ip;
	ip_address_t target_ip;
	uint16_t lower_port;
	uint16_t upper_port;
} config_t;

// Just in case!
//#pragma pack(push, 1)

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address_t	saddr;		// Source address
	ip_address_t	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
} ip_header_t;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
} udp_header_t;

//#pragma pack(pop)

typedef struct packet
{
	uint64_t ts;
	uint8_t *data;
	uint16_t size;
	uint32_t ip1, ip2;
	bool outbound; // External packet
} packet_t;

typedef struct packet_node packet_node_t;

struct packet_node
{
	packet_node_t *prev;
	packet_node_t *next;
	packet_t value;
};

typedef struct packet_work
{
	packet_node_t *root;
	size_t size;
} packet_work_t;


static void
zero_packet_work(packet_work_t *work)
{
	work->root = NULL;
	work->size = 0;
}

static void zero_packet_node(packet_node_t *node)
{
	node->prev = NULL;
	node->next = NULL;
	memset((void *)&node->value, 0, sizeof(node->value));
}

/*
	Returns address to the node which was just added. If packet pointer is NULL, then it doesn't get written.
	And vice-versa if it's not NULL it does. 
*/
static packet_node_t *push_work_packet(packet_work_t *work, packet_t const *packet)
{
	packet_node_t *new_node = malloc(sizeof(packet_node_t));
	zero_packet_node(new_node);

	if (work->root == NULL)
	{
		if (packet != NULL)
		{
			// If packet value pointer, is NULL, move to node
			new_node->value = *packet;
		}

		work->root = new_node;
	}
	else
	{
		packet_node_t *curr_node = work->root;

		while (curr_node->next != NULL)
		{
			curr_node = curr_node->next;
		}

		// node->next can be allocated on, in order to place packet within

		new_node->prev = curr_node;

		if (packet != NULL)
		{
			// If packet value pointer, is NULL, move to node
			new_node->value = *packet;
		}
		
		curr_node->next = new_node;
	}

	++work->size;

	return new_node;
}

static packet_t work_packet_pop_root(packet_work_t *work)
{
	packet_t value;

	if (work->root != NULL)
	{
		packet_node_t *tmp = work->root;
		value = tmp->value;

		if (work->root->next == NULL)
		{
			// No need to link next with root, as it doesn't exist
			work->root = NULL;
		}
		else
		{
			work->root = tmp->next;
			work->root->prev = NULL;
		}

		free(tmp);

		--work->size;
	}
	else
	{
		// Nothing in linked list in root
	}

	return value;
}

static bool work_packet_root_exists(packet_work_t *work)
{
	return work->root != NULL;
}

static void remove_work_packet(packet_work_t *work, packet_node_t *node)
{
	if (node->next != NULL)
	{
		if (node->prev != NULL)
			node->prev->next = node->next;
		else
			work->root = node->next;
	}
	else
	{
		if (node->prev != NULL)
			node->prev->next = NULL;
		else
		{
			// Root, with no next pointer, or somehow detached
			work->root = NULL;

		}
	}

	free(node);
	--work->size;
}

typedef struct Analyzer
{
	pcap_t *handle;

	thrd_t sniffer_thread;
	thrd_t decoder_thread;

	_Atomic bool is_working;
	_Atomic unsigned int ms_batch_delay;
	//_Atomic _Bool any_thread_errored; // Defaults to false

	mtx_t mutex;
} Analyzer_t;


static void zero_analyzer(Analyzer_t *analyzer)
{
	analyzer->handle = NULL;
	analyzer->is_working = false;
}

static void stop_analyzer(Analyzer_t *analyzer)
{
	if (analyzer->handle != NULL)
	{
		pcap_close(analyzer->handle);
		analyzer->handle = NULL;
	}

	if (analyzer->is_working)
	{
		//mtx_lock(&analyzer->mutex);
		//pthread_kill(analyzer->sniffer_thread, 0);
		//pthread_kill(analyzer->decoder_thread, 0);
		//mtx_unlock(&analyzer->mutex);

		//mtx_destroy(&analyzer->mutex);
		analyzer->is_working = false;
	}
	//analyzer->is_sniffing = false;
	//analyzer->is_decoding = false;
	//zero_default_analyzer(analyzer);
	//memset(sniffer, 0, sizeof(Analyzer_t));
}


typedef struct global_data
{
	packet_work_t work;
	Analyzer_t analyzer;
	config_t config;
	
	bool is_connected; // To Tarkov server
	uint32_t server_ip, client_ip;

	World world;
	
	HashRecord fragmentedMessages;
	AcksCache inboundAcks, outboundAcks;
} global_data_t;

static void initialize_packet(packet_t *pkt, uint64_t ts,
	uint8_t const* data, size_t size, uint32_t ip1, uint32_t ip2, bool outbound)
{
	pkt->outbound = outbound;
	pkt->ts = ts;
	pkt->data = malloc(size);
	memcpy(pkt->data, data, size);
	pkt->size = size;
	pkt->ip1 = ip1;
	pkt->ip2 = ip2;
}

static void FreePacket(packet_t const* packet)
{
	free(packet->data);
}

// /* Callback function invoked by libpcap for every outbound packet */
// void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *pkt_data)
// {
// }

typedef enum
{
	CONNECTION_STATUS_SUCCEEDED,
	CONNECTION_STATUS_COULD_NOT_FIND_DEVICE
} connect_status_t;

static int run_packet_sniffer(void *user)
{
	global_data_t *gd = (global_data_t *)user;
	
	const uint8_t *pkt_data;
	struct pcap_pkthdr *header;

	int res;

	while( ((res = pcap_next_ex(gd->analyzer.handle, &header, &pkt_data)) >= 0)
		&& gd->analyzer.is_working)
	{
		if(res == 0)
			/* Timeout elapsed */
			continue;

		// user_data cannot be null

		ip_header_t *ih;
		udp_header_t *uh;
		u_int ip_len;

		// Packet to be filled
		uint64_t ts;
		uint8_t *data;
		uint32_t ip1, ip2;
		bool outbound;
		size_t size;

		//data = pkt_data;
		//size = header->len;
		ts = header->ts.tv_sec;
		
		ih = (ip_header_t *) (pkt_data + 14); // skip length of ethernet header
		//data += 14;
		//size -= 14;

		/* retireve the position of the udp header */
		ip_len = (ih->ver_ihl & 0xF) * 4;
		uh = (udp_header_t *) (pkt_data + 14 + ip_len);
		data = (uint8_t *)uh + 8;

		size = (size_t)ntohs(uh->len);
		if (size <= 8) continue; // Size less than UDP header, skip
		size -= 8;

		//data += ip_len;
		//size -= ip_len;

		ip1 = *(uint32_t *)&ih->saddr;
		ip2 = *(uint32_t *)&ih->daddr;
		//data += 8;
		//size -= 8;

		outbound = ip1 == *(uint32_t *)&gd->config.target_ip;

		// Push packet to saved work list

		packet_t pkt;
		initialize_packet(&pkt, ts, data, size, ip1, ip2, outbound);

		mtx_lock(&gd->analyzer.mutex);
		push_work_packet(&gd->work, &pkt);
		mtx_unlock(&gd->analyzer.mutex);
	}

	gd->analyzer.is_working = false;
	thrd_exit(0);
}


static void move_packet_work(packet_work_t *dst, packet_work_t *src)
{
	dst->root = src->root;
	dst->size = src->size;
	zero_packet_work(src);
}

// Process packet batch while popping them off linked list
static void ProcessPacketBatch(global_data_t *gd, packet_work_t *local_work)
{
	//size_t messageCount = 0;
	
	while (work_packet_root_exists(local_work))
	{
		packet_t const *packet = &local_work->root->value;

		// If packet empty, just pop it off
		if (packet->data == NULL || packet->size == 0)
			goto JmpPopPacket;

		// Temporary byte stream for parsing packet
		ByteStream packetStream = CreateByteStreamByRef(packet->data, packet->size);

		if (ByteStreamRemaining(&packetStream) <= 3)
			goto JmpFreePacket; // Too short

		uint32_t ip1 = packet->ip1;
		uint32_t ip2 = packet->ip2;
		bool outbound = packet->outbound;
		
		// Decode packet using UNET specific code	
		if (!gd->is_connected)
		{
			// We don't care, too short
			if (ByteStreamRemaining(&packetStream) <= sizeof(NetPacketBaseHeader))
				goto JmpFreePacket;
		
			NetPacketBaseHeader packetBaseHeader = ByteStreamDecodeNetPacketBaseHeader(&packetStream);
			
			// Client isn't connected to server, check for UNET connect signal
			if (!packetBaseHeader.connectionID)
			{	
				NetSystemRequest systemRequest = ByteStreamReadUInt8(&packetStream);
				if (systemRequest == NET_SYSTEM_REQUEST_CONNECT)
				{
					InitializeAcksCache(&gd->inboundAcks, "INBOUND");
					InitializeAcksCache(&gd->outboundAcks, "OUTBOUND");

					gd->is_connected = true;
					
					// Connect packet is always outbound.
					gd->client_ip = ip1;
					gd->server_ip = ip2;
					
					DebugLog("Connected to server (Client IP: %hhu.%hhu.%hhu.%hhu, Server IP: %hhu.%hhu.%hhu.%hhu)!\n",
						((ip_address_t *)&gd->client_ip)->byte1,
						((ip_address_t *)&gd->client_ip)->byte2,
						((ip_address_t *)&gd->client_ip)->byte3,
						((ip_address_t *)&gd->client_ip)->byte4,
						((ip_address_t *)&gd->server_ip)->byte1,
						((ip_address_t *)&gd->server_ip)->byte2,
						((ip_address_t *)&gd->server_ip)->byte3,
						((ip_address_t *)&gd->server_ip)->byte4
					);
				}
			}
		}
		else
		{
			// Connected to server, check if this packet is a communication between server and client
			if (gd->server_ip == ip1 || gd->server_ip == ip2)
			{
				//printf("Hi 1\n");
				if (ByteStreamRemaining(&packetStream) <= sizeof(NetPacketHeader))
					goto JmpFreePacket;

				NetPacketHeader header = ByteStreamDecodeNetPacketHeader(&packetStream);

				if (ByteStreamRemaining(&packetStream) <= sizeof(PacketAcks128))
					goto JmpFreePacket;

				// Read Acks
				PacketAcks128 acks = ByteStreamDecodePacketAcks128(&packetStream);

				AcksCache *receivedAcks = outbound ? &gd->outboundAcks : &gd->inboundAcks;
				MessageExtractor messageExtractor = CreateMessageExtractor(&packetStream, MAX_CHANNEL_ID, receivedAcks);

				//printf("Before message loop: 0x%p, %lu\n", messageExtractor.data, (size_t)messageExtractor.totalLength);
				// Either gets stuck in this loop, or in ProcessActions()
				while (MessageExtractorGetNextMessage(&messageExtractor))
				{
				 	bool gotCompleteMessage = false;
					ByteStream completeMessageStream; // Initialized later, if we get it

					uint8_t *userData = MessageExtractorGetMessageStart(&messageExtractor);
					uint16_t userLength = MessageExtractorGetMessageLength(&messageExtractor);
					uint8_t channelID = MessageExtractorGetChannelID(&messageExtractor);

					// Temporary byte stream for parsing user data
					ByteStream userStream = CreateByteStreamByRef(userData, userLength);

					if (channelID < 3) // ReliableFragmented
					{
/*
						NetMessageFragmentedHeader fragmentedHeader = ByteStreamDecodeNetMessageFragmentedHeader(&userStream);
						
						uint16_t keyValue = (uint16_t)fragmentedHeader.fragmentedMessageID | (uint16_t)channelID << 8;
						HashKey key = { sizeof(keyValue), &keyValue };
						uint64_t index = HashRecordQueryIndex(&gd->fragmentedMessages, &key);
						
						// Deal with fragmented message
						StretchyArray *fragmentedMessage;

						if (!HashRecordQueryExistsByIndex(&gd->fragmentedMessages, index))
						{
							StretchyArray newFragmentedMessage;
							InitializeStretchyArray(&newFragmentedMessage, sizeof(MessageFragment));

							if (!HashRecordInsertByIndex(&gd->fragmentedMessages, index, (const void *)&newFragmentedMessage))
							{
								// Couldn't insert new fragmented message to hash record
							}
						}
					
						fragmentedMessage = HashRecordQueryByIndex(&gd->fragmentedMessages, index);

						StretchyArrayResize(fragmentedMessage, fragmentedHeader.fragmentAmnt);

						if (fragmentedHeader.fragmentIdx >= fragmentedMessage->size)
						{
							// Broken fragment
						}
						else
						{
							// Set message fragment
							MessageFragment *messageFragment = StretchyArrayAccess(fragmentedMessage, fragmentedHeader.fragmentIdx);
							
							if (messageFragment->data != NULL)
							{
								// Destroy if data was already set
								DestroyMessageFragment(messageFragment);
							}
							
							InitializeMessageFragment(messageFragment, (size_t)ByteStreamRemaining(&userStream), ByteStreamHeadAddr(&userStream));
						}

						// Checks if fragmented message is complete
						bool isComplete = true;
						for (size_t i = 0; i < fragmentedHeader.fragmentAmnt; ++i)
						{
							const MessageFragment *messageFragment = StretchyArrayAccess(fragmentedMessage, i);
							if (messageFragment->data == NULL)
							{
								isComplete = false;
								break;
							}
						}
						
						if (isComplete)
						{
							size_t head = 0;
							uint8_t *messageData = NULL;
							uint8_t messageLen = 0;

							for (size_t i = 0; i < fragmentedHeader.fragmentAmnt; ++i)
							{
								MessageFragment *messageFragment = StretchyArrayAccess(fragmentedMessage, i);
								messageLen += messageFragment->size;

								if (messageData == NULL)
									messageData = malloc(messageLen);
								else
									messageData = realloc(messageData, messageLen);

								memcpy((void *)&messageData[ head ], (const void *)messageFragment->data, messageFragment->size);
								
								head += messageFragment->size;
								DestroyMessageFragment(messageFragment);

								StretchyArrayPopAt(fragmentedMessage, i);
							}

							HashRecordRemoveByIndex(&gd->fragmentedMessages, index);
							completeMessageStream = CreateByteStream(messageData, messageLen);
							free(messageData);
						}
*/
					}
					else
					{
						DebugLog("ChannelID: %hhu\n", channelID);
						//printf("Hi 3\n");
						if (channelID % 2 == 1) // Odd channelID other than 0, 1 and 2
						{
							//if (ByteStreamRemaining(&userStream) <= sizeof(NetMessageReliableHeader)) continue;
							NetMessageReliableHeader messageReliableHeader = ByteStreamDecodeNetMessageReliableHeader(&userStream);
							ByteStreamSeekRel(&userStream, -sizeof(NetMessageReliableHeader));

							if (!AcksReadMessage(receivedAcks, messageReliableHeader.messageID))
							{
								// Wut??
								continue;
							}
						}
						
						// channelID % 2 == 0 does not have NetMessageReliableHeader
						// but skip same bytes so this works.
						size_t skipLength = sizeof(NetMessageReliableHeader)
							+ sizeof(NetMessageOrderedHeader);
							
						//if (ByteStreamRemaining(&userStream) <= skipLength) continue;

						ByteStreamSeekRel(&userStream, skipLength);
						//printf("Hi 5\n");
						
						
						// Creates completeMessageStream ByteStream by reference, so no allocation is needed, from the remaining
						// data is userStream.
						completeMessageStream = CreateByteStream(ByteStreamHeadAddr(&userStream),
								ByteStreamRemaining(&userStream));
						
						gotCompleteMessage = true;
						//printf("Hi 6\n");
					}

					if (gotCompleteMessage)
					{
						//printf("Hi 7\n");
						ProcessActions(&gd->world, &completeMessageStream, channelID, outbound);
						DestroyByteStream(&completeMessageStream);
					}
					//printf("Hi 3!\n");
				}
			}
		}

JmpFreePacket:
		// Free data in packet
		FreePacket(packet);
JmpPopPacket:
		// Pop root off the list
		work_packet_pop_root(local_work);
	}

	//printf("Parsed through %lu messages this batch.\n", messageCount);
}

/* Thread running to analyze and decode packets, for possible UNET packets coming from Tarkov servers */
static int run_packet_decoder(void *user)
{
	global_data_t *gd = (global_data_t *)user;
	packet_t pkt;
	packet_work_t local_work;
	zero_packet_work(&local_work);

	while (gd->analyzer.is_working)
	{
		mtx_lock(&gd->analyzer.mutex);
		if (gd->work.size > 0)
		{
			move_packet_work(&local_work, &gd->work);
		}
		mtx_unlock(&gd->analyzer.mutex);
		
		if (local_work.size > 0)
		{
			//printf("Packet batch size: %u\n", local_work.size);
			ProcessPacketBatch(gd, &local_work);
		}
		unsigned long milisec = gd->analyzer.ms_batch_delay;
		struct timespec delay;
		time_t sec = (time_t)(milisec / 1000);
		delay.tv_sec = sec;
		delay.tv_nsec = 0;

		thrd_sleep(&delay, NULL); // Delay for accumulating packets
	}

	gd->analyzer.is_working = false;
	thrd_exit(0);
}

static connect_status_t start_analyzer(global_data_t *gd)
{
	connect_status_t status;
	int err;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;

	if (gd->analyzer.is_working)
		stop_analyzer(&gd->analyzer);

	gd->is_connected = false;

	err = pcap_findalldevs(&alldevs, errbuf);
	if (err == -1)
	{
		DebugLog("Couldn't find default device: %s\n", errbuf);
		return 2;
	}
	
	bool found_dev = false;
	pcap_if_t *dev = &alldevs[0];
	
	while (dev != NULL)
	{
		//char ip[13];
		char subnet_mask[13];
		bpf_u_int32 subnet_mask_raw; /* Subnet mask as integer */
		struct in_addr address; /* Used for both ip & subnet */

		DebugLog("name: %s\n", dev->name);
		DebugLog("description: %s\n", dev->description);

		pcap_addr_t *devaddr = &dev->addresses[0];

		while (devaddr != NULL)
		{
			if(devaddr->addr->sa_family == AF_INET)
			{
				char ip[16];
				struct sockaddr_in *addr = (struct sockaddr_in *)devaddr->addr;
				ip_address_t *ip_raw = (ip_address_t *)&addr->sin_addr;
				sprintf(ip, "%hhu.%hhu.%hhu.%hhu", ip_raw->byte1, ip_raw->byte2, ip_raw->byte3, ip_raw->byte4);

				DebugLog("ip: %s\n", ip);

				if (!memcmp((void *)&gd->config.network_ip, (void *)ip_raw, sizeof(ip_address_t)))
				{
					DebugLog( "Found device with ip %s!\n", ip);
					found_dev = true;
					goto im_so_happy;
				}
			}

			devaddr = devaddr->next;
		}

		//sprintf(ip, "%hhu.%hhu.%hhu.%hhu", (uint8_t)(ip_raw >> 0), (uint8_t)(ip_raw >> 8), (uint8_t)(ip_raw >> 16), (uint8_t)(ip_raw >> 24));
		//printf("ip: %s\n", ip);

		putchar('\n');
		dev = dev->next;
	}

im_so_happy:

	if (!found_dev)
	{
		DebugLog("Couldn't find device!\n");
		status = CONNECTION_STATUS_COULD_NOT_FIND_DEVICE;
		goto smells_nasty;
	}

	gd->analyzer.handle = pcap_open(dev->name, // name of the device
				65536, // portion of the packet to capture
					 // 65536 guarantees that the whole packet will be captured on all the link layers
				PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
				1000, // read timeout
				NULL, // authentication on the remote machine
				errbuf // error buffer
				);


	/* Open the device */
	if (gd->analyzer.handle == NULL)
	{
		DebugLog("Unable to open the adapter. %s is not supported by Npcap!\n", dev->name);
		return 1;
	}

	DebugLog("Listening on %s...\n", dev->description);

	/* At this point, we don't need any more the device list. Free it */

	char filter[50];

	unsigned char target_ip[16];
	sprintf(target_ip, "%hhu.%hhu.%hhu.%hhu",
		gd->config.target_ip.byte1,
		gd->config.target_ip.byte2,
		gd->config.target_ip.byte3,
		gd->config.target_ip.byte4 );
	

	sprintf((char *)filter, "udp && (ip host %s)"/* && (portrange %hu-%hu)"*/, target_ip,
		gd->config.lower_port,
		gd->config.upper_port);

	//printf("%s'\n", filter);

	struct bpf_program prog;
	err = pcap_compile(gd->analyzer.handle, &prog, filter, true, PCAP_NETMASK_UNKNOWN);

	if (err != 0)
	{
		DebugLog("%s\n", "Failed to compile filter program!");
		goto smells_nasty;
	}

	err = pcap_setfilter(gd->analyzer.handle, &prog);

	if (err != 0)
	{
		DebugLog("%s\n", "Failed to set filter program!");
		goto smells_nasty;
	}

	/*pthread_attr_t attrib;
	pthread_attr_init(&attrib);

	int thread_err;*/
	
	// Create mutex
	//pthread_mutexattr_t mutex_attr;
	//pthread_mutexattr_init(&mutex_attr);
	//pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_NORMAL);
	//pthread_mutex_init(&gd->analyzer.mutex, &mutex_attr);

	//pthread_mutexattr_destroy(&mutex_attr);

	// Attempt to start sniffer thread
	err = thrd_create(&gd->analyzer.sniffer_thread, &run_packet_sniffer, (void*)gd);

	if (err != thrd_success)
	{
		DebugLog("%s\n", "Failed to create sniffer thread!");
		goto smells_nasty;
	}

	// Attempt to start decoder thread
	//thread_err = pthread_create(&gd->analyzer.decoder_thread, &attrib,
	//	&run_packet_decoder, (void *)gd);
	err = thrd_create(&gd->analyzer.decoder_thread, &run_packet_decoder, (void*)gd);

	if (err != thrd_success)
	{
		DebugLog("%s\n", "Failed to create decoder thread!");
		goto smells_nasty;
	}

	// Success
	gd->analyzer.is_working = true;
	status = CONNECTION_STATUS_SUCCEEDED;
	DebugLog("%s\n", "Successfully created analyzer threads!");


	//pthread_attr_destroy(&attrib);

smells_nasty:
	pcap_freealldevs(alldevs);
	
	return status;
}

static config_t create_default_config(void)
{
	config_t config;
	config.lower_port = 0;
	config.upper_port = 65535;
	config.network_ip = (ip_address_t){ 192,168,2,1 };
	config.target_ip = (ip_address_t){ 192,168,2,1 };
	return config;
}

static int ini_config_handler(void* user, const char* section, const char* name, const char* value)
{
	config_t *config = (config_t *)user;

	if (!strcmp(section, "connection"))
	{
		if (!strcmp(name, "network_ip"))
		{
			sscanf(value, "%hhu.%hhu.%hhu.%hhu",
				&config->network_ip.byte1,
				&config->network_ip.byte2,
				&config->network_ip.byte3,
				&config->network_ip.byte4
			);
		}
		else if (!strcmp(name, "target_ip"))
		{
			sscanf(value, "%hhu.%hhu.%hhu.%hhu",
				&config->target_ip.byte1,
				&config->target_ip.byte2,
				&config->target_ip.byte3,
				&config->target_ip.byte4
			);
		}
		else if (!strcmp(name, "lower_port"))
		{
			sscanf(value, "%hu", &config->lower_port);
		}
		else if (!strcmp(name, "upper_port"))
		{
			sscanf(value, "%hu", &config->upper_port);
		}
	}
}


static int read_config_file(config_t *config, const char *filename)
{
	/*
	FILE *file = fopen(filename, "rb");
	uint8_t *data = NULL;
	size_t size;

	if (file != NULL)
	{
		fseek(file, 0, SEEK_END);
		size = ftell();
		data = malloc(size);
		fseek(file, 0, SEEK_SET);
		
		fread(data, size, 1, file);
	
		fclose(f);
	}
	else
	{
		printf("Failed to open config file at: %s\n", filename);
		return -1;
	}

*/
	ini_parse(filename, ini_config_handler, (void *)config);

	return 0;
}

static void initialize_global_data(global_data_t *gd)
{
	int err;
	zero_packet_work(&gd->work);

	memset(&gd->config, 0, sizeof(config_t));
	err = read_config_file(&gd->config, "../data/config.ini");

	if (err)
		gd->config = create_default_config();
	
	zero_analyzer(&gd->analyzer);

	gd->analyzer.ms_batch_delay = 10;
	gd->is_connected = false;
	mtx_init(&gd->analyzer.mutex, mtx_plain);

	InitializeHashRecord(&gd->fragmentedMessages, MAX_FRAGMENTED_MESSAGES,
		sizeof(uint16_t) /* fragmentedMessageID | channelID << 8 */,
		sizeof(StretchyArray) /* std::vector<MessageFragment> */);

	InitializeWorld(&gd->world);
}

typedef struct Camera2D
{
	glm_vec2 pos;
	float aspect;
	float zoom;
} Camera2D;

static inline glm_float3x3 glm_mul_float3x3_float3x3(glm_float3x3 x, glm_float3x3 y)
{
	glm_float3x3 Result = { 0 };

	for (size_t i = 0; i < 3; ++i)
	{
		for (size_t j = 0; j < 3; ++j)
		{
			for (size_t k = 0; k < 3; ++k)
			{
				Result.elem[i][j] += x.elem[i][k] * y.elem[k][j];
			}
		}
	}

	return Result;
}

static inline glm_float3x3 glm_float3x3_identity(void)
{
	return (glm_float3x3)
	{
		.elem = {
		{1.0f, 0.0f, 0.0f},
		{0.0f, 1.0f, 0.0f},
		{0.0f, 0.0f, 1.0f}
		}
	};
}

static inline glm_float4x4 glm_float4x4_identity(void)
{
	return (glm_float4x4)
	{
		.elem = {
		{1.0f, 0.0f, 0.0f, 0.0f},
		{0.0f, 1.0f, 0.0f, 0.0f},
		{0.0f, 0.0f, 1.0f, 0.0f},
		{0.0f, 0.0f, 0.0f, 1.0f} }
	};
}

static inline glm_mat3 Camera2DGetViewMatrix(const Camera2D *camera)
{
	//glm_mat4 Result;

	glm_mat3x3 A = glm_float3x3_identity();
	A.elem[2][0] = -camera->pos.x;
	A.elem[2][1] = -camera->pos.y;

	glm_mat3x3 B = glm_float3x3_identity();
	B.elem[0][0] = camera->zoom * camera->aspect;
	B.elem[1][1] = camera->zoom;

	glm_mat3 m = glm_mul_float3x3_float3x3(A, B);

	//Result = (glm_mat4)
	//{
//		m.elem[0][0], m.elem[1][0], m.elem[2][0], 0.0f,
//		m.elem[0][1], m.elem[1][1], m.elem[2][1], 0.0f,
//		m.elem[0][2], m.elem[1][2], m.elem[2][2], 0.0f,
//		0.0f        , 0.0f        , 0.0f,         1.0f
//	};
	
	return m;
}

typedef struct Mesh
{
	GLuint id;
	GLuint vertexBuffers[2]; // [0] -> vertex buffer, [2] index buffer
	size_t drawCount;
} Mesh;

typedef struct Vertex
{
	glm_vec3 pos;
	glm_vec2 uv;
} Vertex;

static Mesh CreateMesh(size_t vertexArraySize, Vertex *vertexArray, size_t indexArraySize, uint32_t *indexArray)
{
	Mesh mesh;

	glGenVertexArrays(1, &mesh.id);
	glBindVertexArray(mesh.id);

	glGenBuffers(2, &mesh.vertexBuffers[0]);

	// Upload vertex data to the GPU
	glBindBuffer(GL_ARRAY_BUFFER, mesh.vertexBuffers[0]);
	glBufferData(GL_ARRAY_BUFFER, sizeof(Vertex) * vertexArraySize, vertexArray, GL_STATIC_DRAW);
	glEnableVertexAttribArray(0);
	glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, sizeof(Vertex), (void *)0);
	glEnableVertexAttribArray(1);
	glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, sizeof(Vertex), (void *)offsetof(Vertex, uv));

	// Upload index data to the GPU
	glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, mesh.vertexBuffers[1]);
	glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(uint32_t) * indexArraySize, indexArray, GL_STATIC_DRAW);

	glBindVertexArray(0);

	mesh.drawCount = indexArraySize;

	return mesh;
}

static void RenderMesh(const Mesh *mesh)
{
	glBindVertexArray(mesh->id);

	glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, mesh->vertexBuffers[1]);
	glDrawElements(GL_TRIANGLES, mesh->drawCount, GL_UNSIGNED_INT, (void *)0);

	glBindVertexArray(0);
}

static void DestroyMesh(const Mesh *mesh)
{
	glDeleteVertexArrays(2, &mesh->vertexBuffers[0]);
	glDeleteVertexArrays(1, &mesh->id);
}

static char *ReadFileAsString(const char *path)
{
	FILE *fp = fopen(path, "rb");
	char *data = NULL;

	if (fp)
	{
		fseek(fp, 0, SEEK_END);
		size_t size = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		data = malloc(size + 1);
		fread(data, 1, size, fp);
		data[size] = '\0';
	}
	
	return data;
}

typedef struct Shader
{
	GLuint id;
} Shader;

typedef struct Texture
{
	GLuint id;
	uint32_t width, height;
} Texture;

static Texture CreateTexture(uint8_t *data, size_t channelCount, uint32_t width, uint32_t height)
{
	Texture texture;
	texture.width = width;
	texture.height = height;
	glGenTextures(1, &texture.id);

	//size_t dataSize = channelCount * width * height;

	glBindTexture(GL_TEXTURE_2D, texture.id);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, data);

	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

	return texture;
}

static void BindTexture(const Texture *texture, uint32_t slot)
{
	glActiveTexture(GL_TEXTURE0 + slot);
	glBindTexture(GL_TEXTURE_2D, texture->id);
}

static GLuint CreateShader(const char *shaderString, GLenum shaderType)
{
	GLuint shader = glCreateShader(shaderType);
	glShaderSource(shader, 1, (const char **)&shaderString, NULL);
	glCompileShader(shader);

	// Check and log any errors
	GLint status;
	glGetShaderiv(shader, GL_COMPILE_STATUS, &status);
	if (status == GL_FALSE)
	{
		GLint maxLength = 0;
		glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &maxLength);

		// The maxLength includes the NULL character
		GLchar errorLog[maxLength];
		glGetShaderInfoLog(shader, maxLength, &maxLength, &errorLog[0]);
		DebugLog("Failed to compile shader with error:\n\n %s\n", errorLog);

		// Provide the infolog in whatever manor you deem best.
		// Exit with failure.
		glDeleteShader(shader); // Don't leak the shader.
	}

	return shader;
}

static Shader CreateMinimalShader(const char *vertexShaderPath, const char *fragmentShaderPath)
{
	Shader shader;
	shader.id = glCreateProgram();

	// Creates and links vertex shader, then destroys it
	char *vertexShaderString = ReadFileAsString(vertexShaderPath);
	GLuint vertexShader = CreateShader(vertexShaderString, GL_VERTEX_SHADER);
	free(vertexShaderString);
	glAttachShader(shader.id, vertexShader);
	glDeleteShader(vertexShader);
	
	// Creates and links fragment shader, then destroys it
	char *fragmentShaderString = ReadFileAsString(fragmentShaderPath);
	GLuint fragmentShader = CreateShader(fragmentShaderString, GL_FRAGMENT_SHADER);
	free(fragmentShaderString);
	glAttachShader(shader.id, fragmentShader);
	glDeleteShader(fragmentShader);

	glLinkProgram(shader.id);

	GLint status;
	glGetProgramiv(shader.id, GL_LINK_STATUS, &status);

	if (status == GL_FALSE)
	{
		// Error linking, print message
		
		GLint maxLength = 0;
		glGetProgramiv(shader.id, GL_INFO_LOG_LENGTH, &maxLength);

		// The maxLength includes the NULL character
		GLchar errorLog[maxLength];
		glGetProgramInfoLog(shader.id, maxLength, &maxLength, &errorLog[0]);

		fprintf(stderr, "Failed to link program with error:\n\n %s\n", errorLog);

		// Provide the infolog in whatever manor you deem best.
		// Exit with failure.
		glDeleteProgram(shader.id); // Don't leak the shader.
	}

	return shader;
}

static void BindShader(const Shader *shader)
{
	glUseProgram(shader->id);
}

static void ShaderUploadMat3(const Shader *shader, const char *name, const glm_mat3 m)
{
	glUniformMatrix3fv(glGetUniformLocation(shader->id, name), 1, GL_FALSE, &m.elem[0][0]);
}

static void ShaderUploadTex(const Shader *shader, const char *name, const uint32_t x)
{
	glUniform1i(glGetUniformLocation(shader->id, name), x);
}

static void RenderObservers(const World *world,
	const Mesh *observerMesh, const Shader *observerShader, const Texture *observerTexture,
	const Camera2D *camera, bool doRenderGrid)
{
	glm_mat3 view = Camera2DGetViewMatrix(camera);

	BindShader(observerShader);

	for (unsigned int i = 0; i < 256; ++i)
	{
		uint8_t cid = i;
		HashKey key = { 1, (void *)&cid };
		uint64_t index = HashRecordQueryIndex(&world->observers, &key);
		
		if (HashRecordQueryExistsByIndex(&world->observers, index))
		{
			// Observer exists, render it!
			Observer *obs = (Observer *)HashRecordQueryByIndex(&world->observers, index);

			glm_mat3 model = glm_float3x3_identity();
			//model.elem[2][0] = obs->currPos.x;
			//model.elem[2][1] = obs->currPos.z;

			glm_mat3 mv = model;//glm_mul_float3x3_float3x3(view, model);

			// Bind shader, and set uniforms
			ShaderUploadMat3(observerShader, "inWorldToScreen", mv);

			// Bind texture
			BindTexture(observerTexture, 0);
			ShaderUploadTex(observerShader, "inAlbedoTexture", 0);

			// Draw mesh
			RenderMesh(observerMesh);
		}
	}
}

// Window aspect ratio: ax1
// Image aspect ratio: ax2
static glm_mat3 PerfectZoomed_Unoptimized(float ax1, float ax2)
{
	glm_mat3 Result = glm_float3x3_identity();

	// Destination or screen aspect ratio
	float ay1 = 1.0f / ax1;
	float aw1 = ax1;//(ax1 >= 1.0f) ? ax1 : 1.0f;
	//float ah1 = (ay1 >= 1.0f) ? ay1 : 1.0f;

	// Source or image aspect ratio
	float ay2 = 1.0f / ax2;

	float zoom = 0.0f;

	// NOTE: This only works if ax2 >= 1.0f, or image is wider than higher
	if (ax1 >= ax2 && ax2 >= 1.0f)
	{
		zoom = ax1/ax2;
	}
	else if (ax1 < ax2 && ax2 >= 1.0f)
	{
		zoom = 1.0f;
	}
/*
	if (ax1 >= 1.0f)
	{
		// Both rects are wider than taller
		if (ax2 >= 1.0f)
		{
			zoom = ax1 / ax2;
		}
		else
		{
			zoom = ay1 / ay2;
		}
	}
	*/
	Result.elem[0][0] = zoom / aw1;
	//Result.elem[1][1] = zoom / ah1;
	Result.elem[1][1] = zoom;

	return Result;
}

static Logger CreateLogger(void)
{
	Logger logger;
	nk_textedit_init_default(&logger.edit);
	mtx_init(&logger.mutex, mtx_plain);
	return logger;
}

int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	int err;
	Mesh quadMesh;
	Shader unlitShader1;
	Texture observerIcon;
	Texture background;

	global_data_t gd;
	debugLogger = CreateLogger();
	initialize_global_data(&gd);

	const char *pcap_version = pcap_lib_version();
	DebugLog("%s\n", pcap_version);
	/* init gui state */
	// struct nk_context ctx;
	// nk_init_fixed(&ctx, calloc(1, MAX_MEMORY), MAX_MEMORY, &font);

	//start_analyzer(&gd);

	//bool b = false;
	//while(!b)
	//{
	//	//thrd_sleep(20);
	//}


	unsigned int width = 1280, height = 720;

	glfwInit();

	glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
	//glfwWindowHint(GLFW_OPENGL_DEBUG_CONTEXT, GLFW_TRUE);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
	glfwWindowHint( GLFW_DOUBLEBUFFER, GLFW_FALSE );

	GLFWwindow *win = glfwCreateWindow(width, height, "Tarkov Spy", NULL, NULL);

	if (win == NULL)
	{
		// Some kind of error creating the window
		DebugLog("Error creating window!\n");
		return 1;
	}

	DebugLog("Created a window!\n");

	glfwMakeContextCurrent(win);
	glfwSwapInterval(1);

	err = gladLoadGL();
	if (err == 0)
	{
		DebugLog("Error failed to load OpenGL!\n");
		return 1;
	}

	DebugLog("Loaded OpenGL properly with gladLoadGL().\n");
	DebugLog("OpenGL version string: %s\n", glGetString(GL_VERSION));

	glViewport(0, 0, width, height);

	// Initialize OpenGL drawing related data
	{
		// Create quadMesh
		Vertex vertices[] = {
			(Vertex){ glm_vec3(-1.0f, -1.0f, 0.0f), glm_vec2(0.0f, 0.0f) },
			(Vertex){ glm_vec3(1.0f, -1.0f, 0.0f), glm_vec2(1.0f, 0.0f) },
			(Vertex){ glm_vec3(-1.0f, 1.0f, 0.0f), glm_vec2(0.0f, 1.0f) },
			(Vertex){ glm_vec3(1.0f, 1.0f, 0.0f), glm_vec2(1.0f, 1.0f) }
		};

		uint32_t indices[] = { 0, 1, 2, 2, 1, 3 };

		quadMesh = CreateMesh(4, vertices, 6, indices);
	}

	{
		// Create general shader with texturing
		unlitShader1 = CreateMinimalShader("../data/shaders/unlitShader1.vert", "../data/shaders/unlitShader1.frag");
	}

	{
		// Create texture for observers
		int channels;
		int width;
		int height;
		uint8_t *data = stbi_load("../data/images/UI/emoji.png", &width, &height, &channels, STBI_rgb_alpha);
		observerIcon = CreateTexture(data, channels, width, height);
	}

	{
		// Create background texture
		int channels;
		int width;
		int height;
		uint8_t *data = stbi_load("../data/images/background1.jpg", &width, &height, &channels, STBI_rgb_alpha);
		background =  CreateTexture(data, channels, width, height);
	}

	{
		// Add observer to test
		Observer obs;
		obs.currPos = (Vector3) { 0.0f, 0.0f, 0.0f };
		WorldCreateObserver(&gd.world, 0, &obs);
	}

	bool isQuit = false;

	struct nk_context *ctx = nk_glfw3_init(win, NK_GLFW3_INSTALL_CALLBACKS);
	

	{
		struct nk_font_atlas *atlas;
		nk_glfw3_font_stash_begin(&atlas);

		struct nk_font_config font_config;
		font_config.pixel_snap = false;
		font_config.oversample_v = 10;
		font_config.oversample_h = 10;


		struct nk_font *font = nk_font_atlas_add_from_file(atlas,
			"../data/fonts/AnonymousPro-Regular.ttf", 14, NULL);

		nk_glfw3_font_stash_end();
		//nk_style_load_all_cursors(ctx, atlas->cursors);
		nk_style_set_font(ctx, &font->handle);
	}

	char network_ip[16] = { 0 };
	char target_ip[16] = { 0 };
	
	sprintf(network_ip, "%hhu.%hhu.%hhu.%hhu",
		gd.config.network_ip.byte1,
		gd.config.network_ip.byte2,
		gd.config.network_ip.byte3,
		gd.config.network_ip.byte4
	);

	sprintf(target_ip, "%hhu.%hhu.%hhu.%hhu",
		gd.config.target_ip.byte1,
		gd.config.target_ip.byte2,
		gd.config.target_ip.byte3,
		gd.config.target_ip.byte4
	);


	int max_ip_len = 16;
	bool pressed_connect = false;
	connect_status_t connect_status;
	bool config_window_open = false;
	bool commands_window_open = false;
	int render_map = 0;
	int render_loot = 0;
	int render_enemy_line_of_sight = 0;
	int render_enemy_vision = 0;
	float enemy_vision_fov = 75.0f;
	bool mapViewerOpen = false;
	bool debugLogViewOpen = true;

	glClearColor(0.0f, 0.0f, 0.0f, 1.0f);

	Texture startTexture, stopTexture;
	struct nk_image startImage, stopImage;

	//debugLog.mode = NK_TEXT_EDIT_MODE_INSERT;

	{
		// Load start button
		
		int channels;
		int width;
		int height;
		uint8_t *data = stbi_load("../data/images/UI/start.png", &width, &height, &channels, STBI_rgb_alpha);
		startTexture = CreateTexture(data, channels, width, height);
		startImage.handle = nk_handle_id(startTexture.id);
		startImage.w = width;
		startImage.h = height;
		startImage.region[0] = 0;
		startImage.region[1] = 0;
		startImage.region[2] = width;
		startImage.region[3] = height;
		// Load stop button
	}

	{
		// Load stop button
		
		int channels;
		int width;
		int height;
		uint8_t *data = stbi_load("../data/images/UI/stop.png", &width, &height, &channels, STBI_rgb_alpha);
		stopTexture = CreateTexture(data, channels, width, height);
		stopImage.handle = nk_handle_id(stopTexture.id);
		stopImage.w = width;
		stopImage.h = height;
		stopImage.region[0] = 0;
		stopImage.region[1] = 0;
		stopImage.region[2] = width;
		stopImage.region[3] = height;
		// Load stop button
	}

	struct nk_style_button buttonStyle = ctx->style.button;
	buttonStyle.rounding = 0;
	buttonStyle.padding = nk_vec2(0,0);
	buttonStyle.image_padding = nk_vec2(3,3);
	buttonStyle.border = 1;

	while (!isQuit)
	{
		isQuit = glfwWindowShouldClose(win);


		glfwGetFramebufferSize(win, (int *)&width, (int *)&height);

        {
            gNkMemTestLastTime = gNkMemTestCurrentTime;
            gNkMemTestCurrentTime = (float)glfwGetTime();
            gNkMemTestTimeSinceLastPrint += gNkMemTestCurrentTime - gNkMemTestLastTime;

            while (gNkMemTestTimeSinceLastPrint > gNkMemTestPrintInterval)
            {
                DebugLog("[%5.f]: Nuklear called malloc() x %lu, and free() x %lu\n",
                         gNkMemTestCurrentTime, gNkMemTestAllocated, gNkMemTestFreed);

                gNkMemTestTimeSinceLastPrint -= gNkMemTestPrintInterval;
            }
        }

		// Start rendering
		
		// float time = 0.25f * powf(glfwGetTime(), 2.0f);
		// float alpha = time > 1.0f ? 1.0f : time;

		// glm_vec3 bg = glm_vec3(0.64f, 0.65f, 0.62f);

		// glClearColor(alpha * bg.r, alpha * bg.g, alpha * bg.b, 1.0f);


        glClear(GL_COLOR_BUFFER_BIT);

        {
			// Render background 
			float ax1 = (float)width / (float)height;
			float ax2 = (float)background.width / (float)background.height;
			glm_mat3 view = PerfectZoomed_Unoptimized(ax1, ax2);
			glm_mat3 model = glm_float3x3_identity();

			model.elem[0][0] = ax2;

			glm_mat3 mv = glm_mul_float3x3_float3x3(view, model);

			BindShader(&unlitShader1);
			ShaderUploadMat3(&unlitShader1, "inWorldToScreen", mv);
			
			BindTexture(&background, 0);
			ShaderUploadTex(&unlitShader1, "inAlbedoTexture", 0);
			
			//RenderMesh(&quadMesh);
		}

		//RenderMesh(&mapMesh);
		//Camera2D camera = { glm_vec2(0), (float)width/(float)height, 0.0f };
		//RenderObservers(&gd.world, &quadMesh, &unlitShader1, &observerIcon, &camera, false);

		nk_glfw3_new_frame();
/* if this assert triggers you allocated space between nk_begin and nk_menubar_begin.
    If you want a menubar the first nuklear function after `nk_begin` has to be a
    `nk_menubar_begin` call. Inside the menubar you then have to allocate space for
    widgets (also supports multiple rows).
    Example:
        if (nk_begin(...)) {
            nk_menubar_begin(...);
                nk_layout_xxxx(...);
                nk_button(...);
                nk_layout_xxxx(...);
                nk_button(...);
            nk_menubar_end(...);
        }
        nk_end(...);
    */

		const unsigned int desired_h = 20;
		const struct nk_style_button *style = &ctx->style.button;
		const unsigned int actual_h = desired_h +2 * style->padding.y + style->rounding;

		//content->h = r.h - (2 * style->padding.y + style->border + style->rounding*2);

		if (nk_begin(ctx, "Main", nk_rect(0, 0, width, actual_h),
			NK_WINDOW_NO_SCROLLBAR|NK_WINDOW_BACKGROUND))
		{

			nk_menubar_begin(ctx);

			const char *menu1 = "Configs";
			const char *menu2 = "Options";
			const char *menu3 = "View";

			//nk_layout_space_begin(ctx, NK_STATIC, 500, INT_MAX);
			//nk_layout_space_push(ctx, nk_rect(0,0,20,10));

			nk_layout_row_template_begin(ctx, desired_h);

			nk_layout_row_template_push_static(ctx, 80);
			if (nk_menu_begin_text(ctx, menu1, strlen(menu1), NK_TEXT_CENTERED, nk_vec2(200,200)))
			{
				nk_layout_row_dynamic(ctx, 20, 1);
				if (nk_menu_item_label(ctx, "Config", NK_TEXT_LEFT) && !config_window_open)
				{
					config_window_open = true;
				}
				nk_menu_end(ctx);
			}

			nk_layout_row_template_push_static(ctx, 80);
			if (nk_menu_begin_text(ctx, menu2, strlen(menu2), NK_TEXT_CENTERED, nk_vec2(200,200)))
			{
				nk_layout_row_dynamic(ctx, 20, 1);
				
				if (nk_menu_item_label(ctx, "Map Options", NK_TEXT_LEFT) && !config_window_open)
				{
				}

				nk_menu_end(ctx);
			}

			nk_layout_row_template_push_static(ctx, 80);
			if (nk_menu_begin_text(ctx, menu3, strlen(menu3), NK_TEXT_CENTERED, nk_vec2(200,200)))
			{
				nk_layout_row_dynamic(ctx, 20, 1);
				
				if (nk_menu_item_label(ctx, "Player Info", NK_TEXT_LEFT))
				{
				}
				if (nk_menu_item_label(ctx, "Loot Filter", NK_TEXT_LEFT))
				{
				}
				if (nk_menu_item_label(ctx, "Commands", NK_TEXT_LEFT) && !commands_window_open)
				{
					commands_window_open = true;
				}
				if (nk_menu_item_label(ctx, "Map Viewer", NK_TEXT_LEFT))
				{
					mapViewerOpen = true;
				}

				nk_menu_end(ctx);
			}
			//nk_menu_begin_text(ctx, title, strlen(title), 0, nk_vec2(20, 10));
			//nk_menu_end(ctx);

			//nk_layout_row_dynamic(ctx, 20, 2);
			//nk_label(ctx, "Network Adapter:", NK_TEXT_LEFT);
				
			//static int selectedNetworkAdapter_WIFI = 0;
			//static int selectedNetworkAdapter_ETHERNET = 0;
			//static const char *networkAdapterTypes[] = { "WIFI", "LAN" };
			//nk_combo(ctx, networkAdapterTypes, 2, &selectedNetworkAdapterType, 20, nk_vec2(20,20));
			/*
			nk_layout_row_template_push_static(ctx, 60);
			if (nk_button_image(ctx, ))
			{
			}

			nk_layout_row_template_push_static(ctx, 60);
			if (nk_button_label(ctx, ))
			{
			}*/

			//float usableSpace = nk_layout_row_calculate_usable_space(ctx, )

			static int selectedNetworkAdapterType = 1;
			static const char *networkAdapterTypes[] = { "Wi-Fi", "Ethernet", "Bluetooth" };

			nk_layout_row_template_push_static(ctx, 100);
			nk_combobox(ctx, networkAdapterTypes, ARRAY_LENGTH(networkAdapterTypes), &selectedNetworkAdapterType, 20, nk_vec2(100, 100));

			nk_layout_row_template_push_static(ctx, 20);
			if (nk_button_image_styled(ctx, &buttonStyle, startImage) && !gd.analyzer.is_working)
			{
				start_analyzer(&gd);
			}
			
			nk_layout_row_template_push_static(ctx, 20);
			if (nk_button_image_styled(ctx, &buttonStyle, stopImage) && gd.analyzer.is_working)
			{
				stop_analyzer(&gd.analyzer);
				printf("Cock has been slayed!\n");
			}

			/*

			nk_layout_row_template_push_static(ctx, 80);
			nk_label(ctx, "Status: ", NK_TEXT_LEFT);*/
			
			nk_layout_row_template_push_static(ctx, 80);
			nk_label(ctx, "Status: ", NK_TEXT_CENTERED);

			nk_layout_row_template_push_dynamic(ctx);
			//nk_layout_row_template_push_dynamic(ctx);
			if (gd.analyzer.is_working)
			{
				//nk_label_colored(ctx, "Started", NK_TEXT_LEFT, (struct nk_color){128,255,128,255});
				nk_label_colored(ctx, "Started", NK_TEXT_CENTERED, (struct nk_color){96,192,96,255});
			}
			else
			{
				//nk_label(ctx, "Stopped", NK_TEXT_CENTERED);
				nk_label_colored(ctx, "Stopped", NK_TEXT_CENTERED, (struct nk_color){192,96,96,255});
					
			}
			
			
			nk_menubar_end(ctx);
		}
		nk_end(ctx);

		if (commands_window_open)
		{
			int w = 250;
			int h = 290;
			int x = width/2 - w/2;
			int y = height/2 - h/2;

			int status = nk_begin(ctx, "Commands", nk_rect(x, y, w, h),
				NK_WINDOW_MOVABLE|NK_WINDOW_TITLE|NK_WINDOW_BORDER|NK_WINDOW_SCALABLE|NK_WINDOW_CLOSABLE);

			if (status != 0)
			{

				//nk_layout_row_dynamic(ctx, 20, 2);
				//nk_label(ctx, "Network IP:",NK_TEXT_CENTERED);

				////nk_edit_string(ctx, NK_EDIT_FIELD, s_dev_ip_str, &s_dev_ip_len, s_dev_ip_len, nk_filter_default);
				//nk_edit_string_zero_terminated(ctx,NK_EDIT_FIELD, network_ip, 16, nk_filter_default);

				////printf("%s\n", s_dev_ip_str);
				//nk_label(ctx, "Target IP:",NK_TEXT_CENTERED);

				//nk_edit_string_zero_terminated(ctx,NK_EDIT_FIELD, target_ip, 16, nk_filter_default);

				////nk_layout_row_dynamic(ctx, 20, 3);
				////nk_layout_row_template_begin(ctx, 20);
				////nk_layout_row_template_push_dynamic(ctx);
				////nk_layout_row_dynamic(ctx, 20, 2);
				////nk_label(ctx, "Batch Delay:", NK_TEXT_CENTERED);

				////nk_layout_row_template_push_static(ctx, 100);
				////nk_slider_int(ctx, 1, (int *)&gd.analyzer.ms_batch_delay, 16, 1);

				//nk_layout_row_dynamic(ctx, 20, 1);
				//nk_property_int(ctx, "Batch Delay", 1, (int *)&gd.analyzer.ms_batch_delay, 1000, 1, 1);

				//static char ms_batch_delay_str[20] = { 0 };
				//sprintf(ms_batch_delay_str, "%u", gd.analyzer.ms_batch_delay);
				////nk_layout_row_template_end(ctx);
				////nk_label(ctx, ms_batch_delay_str, NK_TEXT_LEFT);


				//nk_layout_row_dynamic(ctx, 20, 1);
				//nk_checkbox_label(ctx, "Show Map", &render_map);

				//nk_layout_row_dynamic(ctx, 20, 1);
				//nk_checkbox_label(ctx, "Show Loot", &render_loot);

				//nk_layout_row_dynamic(ctx, 20, 1);
				//nk_checkbox_label(ctx, "Render Enemy's Line of Sight", &render_enemy_line_of_sight);

				//nk_layout_row_dynamic(ctx, 20, 1);
				//nk_checkbox_label(ctx, "Render Enemy's View", &render_enemy_vision);


				////nk_layout_row_dynamic(ctx, 20, 2);
				////nk_label(ctx, "Enemy FOV (degrees):", NK_TEXT_CENTERED);

				////char fov_str[20] = { 0 };
				////sprintf(fov_str, "%3.1f", enemy_vision_fov);

				////nk_layout_row_template_begin(ctx, 20);
				////nk_layout_row_template_push_dynamic(ctx);
				////nk_layout_row_dynamic(ctx, 20, 2);
				////nk_label(ctx, fov_str, NK_TEXT_LEFT);
				////nk_layout_row_template_push_static(ctx, 70);
				//nk_property_float(ctx, "Enemy FOV", 50.0f, (float *)&enemy_vision_fov, 75.0f, 1.0f, 1.0f);
				////nk_slider_float(ctx, 50.0f, (float *)&enemy_vision_fov, 75.0f, 1.0f);
				////nk_layout_row_template_end(ctx);

				nk_layout_row_dynamic(ctx, 20, 2);
				if (nk_button_label(ctx, "Analyze") && !gd.analyzer.is_working) 
				{
					pressed_connect = true;

					// Set ip from text box, to config struct
					sscanf((const char *)network_ip, "%hhu.%hhu.%hhu.%hhu",
						&gd.config.network_ip.byte1,
						&gd.config.network_ip.byte2,
						&gd.config.network_ip.byte3,
						&gd.config.network_ip.byte4);

					sscanf((const char *)target_ip, "%hhu.%hhu.%hhu.%hhu",
						&gd.config.target_ip.byte1,
						&gd.config.target_ip.byte2,
						&gd.config.target_ip.byte3,
						&gd.config.target_ip.byte4);

					connect_status = start_analyzer(&gd);
				}

				if (nk_button_label(ctx, "Stop Analyzer") && gd.analyzer.is_working)
				{
					stop_analyzer(&gd.analyzer);
					printf("Cock has been slayed!\n");
				}

				nk_layout_row_dynamic(ctx, 20, 1);
				if (nk_button_label(ctx, "Save to INI"))
				{

				}
			}
			else
			{
				commands_window_open = false;
			}
			nk_end(ctx);
		}

		if (mapViewerOpen)
		{
			int w = 500;
			int h = 500;
			int x = width/2 - w/2;
			int y = height/2 - h/2;

			int status = nk_begin(ctx, "Map Viewer", nk_rect(x, y, w, h),
				NK_WINDOW_MOVABLE|NK_WINDOW_TITLE|NK_WINDOW_BORDER|NK_WINDOW_SCALABLE|NK_WINDOW_CLOSABLE);

			if (status != 0)
			{
				
			}
			else
			{
				mapViewerOpen = false;
			}

			nk_end(ctx);
		}

		if (debugLogViewOpen)
		{
			int w = 400;
			int h = 400;
			int x = width/2 - w/2;
			int y = height/2 - h/2;
			int status = nk_begin(ctx, "Debug Log", nk_rect(x,y,w,h), NK_WINDOW_MOVABLE|NK_WINDOW_TITLE|NK_WINDOW_BORDER/*|NK_WINDOW_SCALABLE*/|NK_WINDOW_CLOSABLE|NK_WINDOW_NO_SCROLLBAR);

			nk_layout_row_dynamic(ctx, 340.0f, 1);

			//static char debugLog[1024] = "Hello World";
			//static int debugLogSize = 0;

			//nk_edit_string_zero_terminated(ctx, NK_EDIT_MULTILINE | NK_EDIT_BOX | NK_EDIT_AUTO_SELECT, debugLog, sizeof(debugLog), nk_filter_ascii);
			//const char *str = "Hello \n";
			//debugLog.mode = NK_TEXT_EDIT_MODE_INSERT;
			//nk_textedit_paste(&debugLog, str, strlen(str));
			//debugLog.mode = NK_TEXT_EDIT_MODE_INSERT;
			debugLogger.edit.mode = NK_TEXT_EDIT_MODE_VIEW;
			nk_edit_buffer(ctx, NK_EDIT_READ_ONLY | NK_EDIT_ALLOW_TAB | NK_EDIT_MULTILINE, &debugLogger.edit, nk_filter_ascii);

			nk_end(ctx);
		}

		nk_glfw3_render(NK_ANTI_ALIASING_ON, 6000000, 6000000);
		
		glFlush();

		glfwSwapBuffers(win);
		glfwPollEvents();
	}

	nk_glfw3_shutdown();
	glfwTerminate();

	return 0;
}
