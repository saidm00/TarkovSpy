#define NK_INCLUDE_STANDARD_IO
#define NK_INCLUDE_DEFAULT_ALLOCATOR
#define NK_INCLUDE_VERTEX_BUFFER_OUTPUT
#define NK_INCLUDE_FONT_BAKING
#define NK_INCLUDE_DEFAULT_FONT
#define NK_IMPLEMENTATION
#define NK_KEYSTATE_BASED_INPUT
#define NK_IMPLEMENTATION
#include "nuklear.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>


#define NK_GLFW_GL3_IMPLEMENTATION
#include "nuklear_glfw_gl3.h"

#include <stdlib.h>
#include <stdio.h>

#include <Winsock2.h>
#include <Windows.h>
#include <pthread.h>
#include <pcap.h>

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include <unistd.h>

#include "ini.h"

/*
#include <glm/glm.h>
*/


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

typedef struct packet
{
	uint64_t ts;
	uint8_t *data;
	size_t len;
	uint32_t ip1, ip2;
	bool ext; // External packet
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
initialize_packet_work(packet_work_t *work)
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

typedef struct packet_analyzer
{
	pcap_t *handle;
	pthread_t sniffer_thread;
	//bool is_sniffing;
	pthread_t decoder_thread;
	//bool is_decoding;
	bool is_working;
	pthread_mutex_t mutex;
} packet_analyzer_t;

typedef struct global_data
{
	bool is_connected;
	packet_work_t work;
	packet_analyzer_t analyzer;
	config_t config;
} global_data_t;

static void
initialize_packet(packet_t *pkt, uint64_t ts,
	uint8_t const* data, size_t len, uint32_t ip1, uint32_t ip2, bool ext)
{
	pkt->ext = ext;
	pkt->ts = ts;
	pkt->data = malloc(len);
	memcpy(pkt->data, data, len);
	pkt->len = len;
	pkt->ip1 = ip1;
	pkt->ip2 = ip2;
}

static void
destroy_packet(packet_t const* pkt)
{
	free(pkt->data);
}

// /* Callback function invoked by libpcap for every incoming packet */
// void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *pkt_data)
// {
// }

typedef enum
{
	CONNECTION_STATUS_SUCCEEDED,
	CONNECTION_STATUS_COULD_NOT_FIND_DEVICE
} connect_status_t;

static void *run_packet_sniffer(void *user)
{
	global_data_t *gd = (global_data_t *)user;
	
	const uint8_t *pkt_data;
	struct pcap_pkthdr *header;

	int res;

	while((res = pcap_next_ex(gd->analyzer.handle, &header, &pkt_data)) >= 0)
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
		bool ext;
		size_t len;

		ts = header->ts.tv_sec;
		
		ih = (ip_header_t *) (pkt_data + 14); //length of ethernet header

		/* retireve the position of the udp header */
		ip_len = (ih->ver_ihl & 0xF) * 4;
		uh = (udp_header_t *) ((u_char*)ih + ip_len);

		ip1 = *(uint32_t *)&ih->saddr;
		ip2 = *(uint32_t *)&ih->daddr;
		data = (uint8_t *)&pkt_data[14 + ip_len + 8];
		len = uh->len;
		ext = memcmp((void *)&ip1, (void *)&gd->config.target_ip, sizeof(uint32_t));

		// Push packet to saved work list

		pthread_mutex_lock(&gd->analyzer.mutex);
		packet_node_t *pkt_node = push_work_packet(&gd->work, NULL);

		initialize_packet(&pkt_node->value, ts, data, len, ip1, ip2, ext);
		pthread_mutex_unlock(&gd->analyzer.mutex);

		printf("0x%08X (%hhu.%hhu.%hhu.%hhu) -> 0x%08X (%hhu.%hhu.%hhu.%hhu)\n",
			ip1,
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			ip2,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4
			);

		printf("Packets in cache: %u\n\n", gd->work.size);




		/* convert the timestamp to readable format */
		/*
		local_tv_sec = header->ts.tv_sec;
		localtime_s(&ltime, &local_tv_sec);
		strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

		printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);*/
	}
}


/* Thread running to analyze and decode packets, for possible UNET packets coming from Tarkov servers */
static void *run_packet_decoder(void *user)
{
	global_data_t *gd = (global_data_t *)user;
	packet_t pkt;

	while (true)
	{
		pthread_mutex_lock(&gd->analyzer.mutex);
		bool pkt_exists = work_packet_root_exists(&gd->work);

		if (pkt_exists)
		{
			pkt = work_packet_pop_root(&gd->work);
		}
		pthread_mutex_unlock(&gd->analyzer.mutex);
				
		if (pkt_exists)
		{
			const uint8_t *data = pkt.data;
			size_t len = pkt.len;

			// Decode packet using UNET specific code
			if (len <= 3)
			{
				// We don't care, too short 8====D
				goto too_short;
			}

			uint16_t conn_id = *(uint16_t *)data;
			if (!conn_id)
			{
				uint8_t req = *(uint8_t *) (data+ 2);

				if (req == 0x1)
				{
					printf("CONNECTED TO TARKOV SERVER!!!\n");
					exit(-1);
				}
			}

too_short:
			// Free data in packet
			free(pkt.data);
		}
		//usleep(1000);
	}
}

static void zero_default_analyzer(packet_analyzer_t *analyzer)
{
	analyzer->handle = NULL;
	analyzer->is_working = false;
}

static void stop_analyzer(packet_analyzer_t *analyzer)
{
	if (analyzer->handle != NULL)
	{
		pcap_close(analyzer->handle);
		analyzer->handle = NULL;
	}

	if (analyzer->is_working)
	{
		pthread_mutex_lock(&analyzer->mutex);
		pthread_kill(analyzer->sniffer_thread, 0);
		pthread_kill(analyzer->decoder_thread, 0);
		pthread_mutex_unlock(&analyzer->mutex);

		pthread_mutex_destroy(&analyzer->mutex);
		analyzer->is_working = false;
	}
	//analyzer->is_sniffing = false;
	//analyzer->is_decoding = false;
	//zero_default_analyzer(analyzer);
	//memset(sniffer, 0, sizeof(packet_analyzer_t));
}

static connect_status_t analyze(global_data_t *gd)
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
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
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

		printf("name: %s\n", dev->name);
		printf("description: %s\n", dev->description);

		pcap_addr_t *devaddr = &dev->addresses[0];

		while (devaddr != NULL)
		{
			if(devaddr->addr->sa_family == AF_INET)
			{
				char ip[16];
				struct sockaddr_in *addr = (struct sockaddr_in *)devaddr->addr;
				ip_address_t *ip_raw = (ip_address_t *)&addr->sin_addr;
				sprintf(ip, "%hhu.%hhu.%hhu.%hhu", ip_raw->byte1, ip_raw->byte2, ip_raw->byte3, ip_raw->byte4);

				printf("ip: %s\n", ip);

				if (!memcmp((void *)&gd->config.network_ip, (void *)ip_raw, sizeof(ip_address_t)))
				{
					printf("Found device with ip %s!\n", ip);
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
		printf("Couldn't find device!\n");
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
		printf("Unable to open the adapter. %s is not supported by Npcap!\n", dev->name);
		return 1;
	}

	printf("Listening on %s...\n", dev->description);

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
		printf("%s\n", "Failed to compile filter program!");
		goto smells_nasty;
	}

	err = pcap_setfilter(gd->analyzer.handle, &prog);

	if (err != 0)
	{
		printf("%s\n", "Failed to set filter program!");
		goto smells_nasty;
	}

	pthread_attr_t attrib;
	pthread_attr_init(&attrib);

	int thread_err;
	
	// Create mutex
	pthread_mutexattr_t mutex_attr;
	pthread_mutexattr_init(&mutex_attr);
	//pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_NORMAL);
	pthread_mutex_init(&gd->analyzer.mutex, &mutex_attr);

	pthread_mutexattr_destroy(&mutex_attr);

	// Attempt to start sniffer thread
	thread_err = pthread_create(&gd->analyzer.sniffer_thread, &attrib,
		&run_packet_sniffer, (void *)gd);

	if (thread_err != 0)
	{
		printf("%s\n", "Failed to create sniffer thread!");
		goto smells_nasty;
	}

	// Attempt to start decoder thread
	thread_err = pthread_create(&gd->analyzer.decoder_thread, &attrib,
		&run_packet_decoder, (void *)gd);

	if (thread_err != 0)
	{
		printf("%s\n", "Failed to create decoder thread!");
		goto smells_nasty;
	}

	// Success
	gd->analyzer.is_working = true;
	status = CONNECTION_STATUS_SUCCEEDED;
	printf("%s\n", "Successfully created analyzer threads!");


	pthread_attr_destroy(&attrib);

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
	initialize_packet_work(&gd->work);

	memset(&gd->config, 0, sizeof(config_t));
	err = read_config_file(&gd->config, "../data/config.ini");

	if (err)
		gd->config = create_default_config();
	
	zero_default_analyzer(&gd->analyzer);
	gd->is_connected = false;
}

int main(int argc, char *argv[])
{
	int err;
	global_data_t gd;
	initialize_global_data(&gd);

	const char *pcap_version = pcap_lib_version();
	printf("Npcap version: %s\n", pcap_version);
	/* init gui state */
	// struct nk_context ctx;
	// nk_init_fixed(&ctx, calloc(1, MAX_MEMORY), MAX_MEMORY, &font);


	unsigned int width = 800, height = 450;

	glfwInit();

	
	glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
	//glfwWindowHint(GLFW_OPENGL_DEBUG_CONTEXT, GLFW_TRUE);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
	glfwWindowHint( GLFW_DOUBLEBUFFER, GLFW_FALSE );

	GLFWwindow *win = glfwCreateWindow(width, height, "Escape From Tarkov Boy Radar", NULL, NULL);

	if (win == NULL)
	{
		// Some kind of error creating the window
		printf("Error creating window!\n");
		return 1;
	}

	printf("Created a window!\n");

	glfwMakeContextCurrent(win);
	glfwSwapInterval(1);

	err = gladLoadGL();
	if (err == 0)
	{
		printf("Error failed to load OpenGL!\n");
		return 1;
	}

	printf("Loaded OpenGL properly!\n");

	printf("OpenGL Version String: %s\n", glGetString(GL_VERSION));

	glViewport(0, 0, width, height);


	bool isQuit = false;

	struct nk_context *ctx = nk_glfw3_init(win, NK_GLFW3_INSTALL_CALLBACKS);
	{
		struct nk_font_atlas *atlas;
		nk_glfw3_font_stash_begin(&atlas);

		/*
		struct nk_font_config font_config;
		font_config.pixel_snap = true;
		font_config.oversample_v = 1;
		font_config.oversample_h = 1;


		struct nk_font *font = nk_font_atlas_add_from_file(atlas,
			"../data/fonts/AnonymousPro-Regular.ttf", 13, &font_config);

		nk_style_load_all_cursors(ctx, atlas->cursors);
		nk_style_set_font(ctx, &font->handle);*/
		nk_glfw3_font_stash_end();
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

	glClearColor(0.0f, 0.0f, 0.0f, 1.0f);


	while (!isQuit)
	{
		isQuit = glfwWindowShouldClose(win);


		// Start rendering
		
		// float time = 0.25f * powf(glfwGetTime(), 2.0f);
		// float alpha = time > 1.0f ? 1.0f : time;

		// glm_vec3 bg = glm_vec3(0.64f, 0.65f, 0.62f);

		// glClearColor(alpha * bg.r, alpha * bg.g, alpha * bg.b, 1.0f);
		

		glClear(GL_COLOR_BUFFER_BIT);


		nk_glfw3_new_frame();

		if (nk_begin(ctx, "Connection", nk_rect(50, 50, 280, 220),
			NK_WINDOW_MOVABLE|NK_WINDOW_NO_SCROLLBAR|NK_WINDOW_TITLE|NK_WINDOW_BORDER))
		{

			nk_layout_row_dynamic(ctx, 20, 1);
			nk_label(ctx, "Network device IP:",NK_TEXT_CENTERED);

			//nk_edit_string(ctx, NK_EDIT_FIELD, s_dev_ip_str, &s_dev_ip_len, s_dev_ip_len, nk_filter_default);
			nk_edit_string_zero_terminated(ctx,NK_EDIT_FIELD, network_ip, 16, nk_filter_default);

			//printf("%s\n", s_dev_ip_str);
			nk_label(ctx, "Target IP:",NK_TEXT_CENTERED);

			nk_edit_string_zero_terminated(ctx,NK_EDIT_FIELD, target_ip, 16, nk_filter_default);
			
			/*
			if (s_connect_state == UNKNOWN_STATE)
			{
				// Padding
				nk_layout_row_dynamic(ctx, 1, 1);
			}
			else*/
			{
				const char *message = "";
				bool success;

				if (pressed_connect)
				{
					success = connect_status == CONNECTION_STATUS_SUCCEEDED;
					switch (connect_status)
					{
						case CONNECTION_STATUS_COULD_NOT_FIND_DEVICE: message = "Couldn't find device!"; break;
						case CONNECTION_STATUS_SUCCEEDED: message = "Successful connection!"; break;
					}
				}

				nk_label(ctx, message, NK_TEXT_CENTERED);
			}

			nk_layout_row_dynamic(ctx, 20, 2);

			if (nk_button_label(ctx, "Analyze")) 
			{
				/* event handling */
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

				connect_status = analyze(&gd);
			}

			if (nk_button_label(ctx, "Stop"))
			{
				stop_analyzer(&gd.analyzer);
				printf("Cock has been slayed!\n");
			}

		}
		nk_end(ctx);

		nk_glfw3_render(NK_ANTI_ALIASING_ON, 65535, 65535);
		
		glFlush();

		glfwSwapBuffers(win);
		glfwPollEvents();
	}

	nk_glfw3_shutdown();
	glfwTerminate();

	return 0;
}