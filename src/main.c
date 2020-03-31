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

#include <glm/glm.h>

/* 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct
{
	ip_address dev_ip;
	ip_address pc_ip;
	uint16_t min_port;
	uint16_t max_port;
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
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
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
	uint64_t time;
	uint8_t *data;
	size_t len;
	unsigned char ip1[16];
	unsigned char ip2[16];
} packet_t;

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	/* param: users, header: from library, pkt_data: udp type 16 bit header*/
	struct tm ltime;
	char timestr[16];
	ip_header_t *ih;
	udp_header_t *uh;
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
	strftime( timestr, sizeof(timestr), "%H:%M:%S", &ltime);

	/* print timestamp and length of the packet */
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	/* retireve the position of the ip header */
	ih = (ip_header_t *) (pkt_data + 14); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xF) * 4;
	uh = (udp_header_t *) ((u_char*)ih + ip_len);

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

typedef enum
{
	CONNECTION_STATUS_SUCCEEDED,
	CONNECTION_STATUS_COULD_NOT_FIND_DEVICE
} connect_status_t;

typedef struct sniffer
{
	pcap_t *handle;
	pthread_t thread;
	bool is_sniffing;
	bool is_thread_running;
} sniffer_t;

void *start_sniffing_cock_thread(void *arg)
{
	pcap_t *devhdl = (pcap_t *)arg;
	pcap_loop(devhdl, 0, packet_handler, NULL);
}

void zero_default_sniffer(sniffer_t *sniffer)
{
	sniffer->is_thread_running = false;
	sniffer->handle = NULL;
	sniffer->is_sniffing = false;
}

void kill_cock_sniffer(sniffer_t *sniffer)
{
	if (sniffer->handle != NULL) pcap_close(sniffer->handle);
	if (sniffer->is_thread_running) pthread_kill(sniffer->thread, 0);
	sniffer->is_sniffing = false;

	zero_default_sniffer(sniffer);
	//memset(sniffer, 0, sizeof(sniffer_t));
}

connect_status_t sniff_cock(sniffer_t *sniffer, config_t *config)
{
	connect_status_t status;
	int err;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (sniffer->is_sniffing)
		kill_cock_sniffer(sniffer);


	pcap_if_t *alldevs;

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
				ip_address *ip_raw = (ip_address *)&addr->sin_addr;
				sprintf(ip, "%hhu.%hhu.%hhu.%hhu", ip_raw->byte1, ip_raw->byte2, ip_raw->byte3, ip_raw->byte4);

				printf("ip: %s\n", ip);

				if (!memcmp((void *)&config->dev_ip, (void *)ip_raw, sizeof(ip_address)))
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

	sniffer->handle = pcap_open(dev->name, // name of the device
				65536, // portion of the packet to capture
					 // 65536 guarantees that the whole packet will be captured on all the link layers
				PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
				1000, // read timeout
				NULL, // authentication on the remote machine
				errbuf // error buffer
				);


	/* Open the device */
	if (sniffer->handle == NULL)
	{
		printf("Unable to open the adapter. %s is not supported by Npcap!\n", dev->name);
		return 1;
	}

	printf("Listening on %s...\n", dev->description);

	/* At this point, we don't need any more the device list. Free it */

	char filter[50] = "udp";

	sprintf((char *)filter, "udp && (dst host %hhu.%hhu.%hhu.%hhu) && (src portrange %hu-%hu)",
		config->pc_ip.byte1,
		config->pc_ip.byte2,
		config->pc_ip.byte3,
		config->pc_ip.byte4,
		config->min_port,
		config->max_port);

	printf("%s'\n", filter);

	struct bpf_program prog;
	err = pcap_compile(sniffer->handle, &prog, filter, true, PCAP_NETMASK_UNKNOWN);

	if (err != 0)
	{
		printf("%s\n", "Failed to compile filter program!");
		goto smells_nasty;
	}

	err = pcap_setfilter(sniffer->handle, &prog);

	if (err != 0)
	{
		printf("%s\n", "Failed to set filter program!");
		goto smells_nasty;
	}

	pthread_attr_t attrib;
	pthread_attr_init(&attrib);

	int thread_err = pthread_create(&sniffer->thread, &attrib,
		&start_sniffing_cock_thread, (void *)sniffer->handle);

	if (thread_err != 0)
	{
		printf("%s\n", "Failed to create thread!");
		goto smells_nasty;
	}

	// Success
	sniffer->is_thread_running = true;
	status = CONNECTION_STATUS_SUCCEEDED;
	sniffer->is_sniffing = true;

	printf("%s\n", "Successfully created sniffer thread!");


	pthread_attr_destroy(&attrib);

smells_nasty:
	pcap_freealldevs(alldevs);
	
	return status;
}


int main(int argc, char *argv[])
{
	int err;
	config_t config;
	sniffer_t sniffer;

	config.min_port = 0;
	config.max_port = 65535;

	zero_default_sniffer(&sniffer);

	const char *pcap_version = pcap_lib_version();
	printf("Npcap version: %s\n", pcap_version);
	/* init gui state */
	// struct nk_context ctx;
	// nk_init_fixed(&ctx, calloc(1, MAX_MEMORY), MAX_MEMORY, &font);


	unsigned int width = 1280, height = 720;

	glfwInit();

	
	glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
	//glfwWindowHint(GLFW_OPENGL_DEBUG_CONTEXT, GLFW_TRUE);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
	glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);

	GLFWwindow *win = glfwCreateWindow(width, height, "Escape From Tarkov Boy Radar", NULL, NULL);


	if (win == NULL)
	{
		// Some kind of error creating the window
		printf("Error creating window!\n");
		return 1;
	}

	printf("Created a window!\n");

	glfwMakeContextCurrent(win);

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


		struct nk_font_config font_config;
		font_config.pixel_snap = true;
		font_config.oversample_v = 1;
		font_config.oversample_h = 1;


		struct nk_font *font = nk_font_atlas_add_from_file(atlas,
			"../data/fonts/AnonymousPro-Regular.ttf", 13, &font_config);

		nk_style_load_all_cursors(ctx, atlas->cursors);
		nk_style_set_font(ctx, &font->handle);
		nk_glfw3_font_stash_end();
	}

	static char s_dev_ip_str[16] = { 0 };
	static char s_pc_ip_str[16] = { 0 };

	static int s_max_ip_len = 16;
	static bool s_pressed_connect = false;
	static connect_status_t s_connect_status;

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
			NK_WINDOW_MOVABLE|NK_WINDOW_NO_SCROLLBAR|NK_WINDOW_TITLE))
		{

			nk_layout_row_dynamic(ctx, 20, 1);
			nk_label(ctx, "Network device IP:",NK_TEXT_CENTERED);

			//nk_edit_string(ctx, NK_EDIT_FIELD, s_dev_ip_str, &s_dev_ip_len, s_dev_ip_len, nk_filter_default);
			nk_edit_string_zero_terminated(ctx,NK_EDIT_FIELD, s_dev_ip_str, s_max_ip_len, nk_filter_default);

			//printf("%s\n", s_dev_ip_str);
			nk_label(ctx, "Target IP:",NK_TEXT_CENTERED);

			nk_edit_string_zero_terminated(ctx,NK_EDIT_FIELD, s_pc_ip_str, s_max_ip_len, nk_filter_default);
			
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

				if (s_pressed_connect)
				{
					success = s_connect_status == CONNECTION_STATUS_SUCCEEDED;
					switch (s_connect_status)
					{
						case CONNECTION_STATUS_COULD_NOT_FIND_DEVICE: message = "Couldn't find device!"; break;
						case CONNECTION_STATUS_SUCCEEDED: message = "Successful connection!"; break;
					}
				}

				nk_label(ctx, message, NK_TEXT_CENTERED);
			}

			nk_layout_row_dynamic(ctx, 20, 2);

			if (nk_button_label(ctx, "Sniff cock")) 
			{
				/* event handling */
				s_pressed_connect = true;

				// Set ip from text box, to config struct
				sscanf((const char *)s_dev_ip_str, "%hhu.%hhu.%hhu.%hhu",
					&config.dev_ip.byte1,
					&config.dev_ip.byte2,
					&config.dev_ip.byte3,
					&config.dev_ip.byte4);

				sscanf((const char *)s_pc_ip_str, "%hhu.%hhu.%hhu.%hhu",
					&config.pc_ip.byte1,
					&config.pc_ip.byte2,
					&config.pc_ip.byte3,
					&config.pc_ip.byte4);

				s_connect_status = sniff_cock(&sniffer, &config);
			}

			if (nk_button_label(ctx, "Kill cock sniffer"))
			{
				kill_cock_sniffer(&sniffer);
				printf("Cock has been slayed!\n");
			}

		}
		nk_end(ctx);

		nk_glfw3_render(NK_ANTI_ALIASING_ON, 65535, 65535);
		
		glfwSwapBuffers(win);


		glfwPollEvents();
	}

	nk_glfw3_shutdown();
	glfwTerminate();

	return 0;
}