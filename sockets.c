/**
 * Very basic example showing usage of access point mode and the DHCP server.
 * The ESP in the example runs a telnet server on 172.16.0.1 (port 23) that
 * outputs some status information if you connect to it, then closes
 * the connection.
 *
 * This example code is in the public domain.
 */
#include <espressif/esp_common.h>
#include <esp/uart.h>

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <FreeRTOS.h>
#include <task.h>

#include <esp8266.h>
#include <queue.h>
#include <lwip/api.h>

#include <lwip/err.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/netdb.h>
#include <lwip/dns.h>

#include <ssid_config.h>
#include "espressif/user_interface.h"

#define CALLBACK_DEBUG

#ifdef CALLBACK_DEBUG
#define debug(s, ...) printf("%s: " s "\n", "Cb:", ## __VA_ARGS__)
#else
#define debug(s, ...)
#endif

#define vTaskDelayMs(ms)	vTaskDelay((ms)/portTICK_PERIOD_MS)
#define UNUSED_ARG(x)	(void)x

#define ECHO_PORT_1 50
#define ECHO_PORT_2 100
#define EVENTS_QUEUE_SIZE 100

const int rele1 = 15;
const int rele2 = 0;
const int rele3 = 5;
const int rele4 = 16;
const int rele5 = 13;

QueueHandle_t xQueue_events;
typedef struct {
    struct netconn *nc ;
    uint8_t type ;
} netconn_events;

static const char * const auth_modes [] = {
    [AUTH_OPEN]         = "Open",
    [AUTH_WEP]          = "WEP",
    [AUTH_WPA_PSK]      = "WPA/PSK",
    [AUTH_WPA2_PSK]     = "WPA2/PSK",
    [AUTH_WPA_WPA2_PSK] = "WPA/WPA2/PSK"
};

/*
 * This function will be call in Lwip in each event on netconn
 */
static void netCallback(struct netconn *conn, enum netconn_evt evt, uint16_t length)
{
    //Show some callback information (debug)
    //debug("sock:%u\tsta:%u\tevt:%u\tlen:%u\ttyp:%u\tfla:%02X",
            //(uint32_t)conn, conn->state, evt, length, conn->type, conn->flags);

    netconn_events events ;

    //If netconn got error, it is close or deleted, dont do treatments on it.
    if (conn->pending_err) {
        return;
    }
    //Treatments only on rcv events.
    switch (evt) {
		case NETCONN_EVT_RCVPLUS:
			events.nc = conn ;
			events.type = evt ;
			break;
		default:
			return;
    }

    //Send the event to the queue
    xQueueSend(xQueue_events, &events, 100);
}

/*
 *  Initialize a server netconn and listen port
 */
static void set_tcp_server_netconn(struct netconn **nc, uint16_t port, netconn_callback callback)
{
    if(nc == NULL)
    {
        debug("%s: netconn missing .\n",__FUNCTION__);
        return;
    }
    *nc = netconn_new_with_callback(NETCONN_TCP, netCallback);
    if(!*nc) {
        debug("Status monitor: Failed to allocate netconn.\n");
        return;
    }
    netconn_set_nonblocking(*nc,NETCONN_FLAG_NON_BLOCKING);
    //netconn_set_recvtimeout(*nc, 10);
    netconn_bind(*nc, IP_ADDR_ANY, port);
    netconn_listen(*nc);
}

/*
 *  Close and delete a socket properly
 */
static void close_tcp_netconn(struct netconn *nc)
{
	debug("WiFi: tcp netconn close\n\r");
    nc->pending_err = ERR_CLSD; // It is hacky way to be sure than callback will don't do treatment on a netconn closed and deleted
    netconn_close(nc);
    netconn_delete(nc);
}

static void scan_done_cb(void *arg, sdk_scan_status_t status)
{
    char ssid[33]; // max SSID length + zero byte

    if (status != SCAN_OK)
    {
        debug("Error: WiFi scan failed\n");
        return;
    }

    struct sdk_bss_info *bss = (struct sdk_bss_info *)arg;
    // first one is invalid
    bss = bss->next.stqe_next;

    debug("\n----------------------------------------------------------------------------------\n");
    debug("                             Wi-Fi networks\n");
    debug("----------------------------------------------------------------------------------\n");

    while (NULL != bss)
    {
        size_t len = strlen((const char *)bss->ssid);
        memcpy(ssid, bss->ssid, len);
        ssid[len] = 0;

        debug("%32s (" MACSTR ") RSSI: %02d, security: %s\n", ssid,
            MAC2STR(bss->bssid), bss->rssi, auth_modes[bss->authmode]);

        bss = bss->next.stqe_next;
    }
}

static void socketsTask(void *pvParameters)
{
	uint8_t status  = 0;
	UNUSED_ARG(pvParameters);
	struct netconn *nc = NULL; // To create servers
	struct netbuf *netbuf = NULL; // To store incoming Data
	struct netconn *nc_in = NULL; // To accept incoming netconn
	char buf[50];
	char* buffer;
	uint16_t len_buf;
	netconn_events events;
	struct ip_info static_ip_info;
	struct sdk_station_config config = {
		.ssid = WIFI_SSID,
		.password = WIFI_PASS,
		.bssid_set = 0
	};

	gpio_enable(rele1, GPIO_OUTPUT);
	gpio_enable(rele2, GPIO_OUTPUT);
	gpio_enable(rele3, GPIO_OUTPUT);
	gpio_enable(rele4, GPIO_OUTPUT);
	gpio_enable(rele5, GPIO_OUTPUT);

	set_tcp_server_netconn(&nc, ECHO_PORT_1, netCallback);
	debug("Server netconn %u ready on port %u.\n",(uint32_t)nc, ECHO_PORT_1);
	set_tcp_server_netconn(&nc, ECHO_PORT_2, netCallback);
	debug("Server netconn %u ready on port %u.\n",(uint32_t)nc, ECHO_PORT_2);

	debug("ssid: %s\n", config.ssid);
	debug("password: %s\n", config.password);

	sdk_wifi_station_disconnect();
	sdk_wifi_set_opmode(NULL_MODE);
	vTaskDelay(500);
	sdk_wifi_station_dhcpc_stop();
	debug("dhcp status : %d", sdk_wifi_station_dhcpc_status());
	IP4_ADDR(&static_ip_info.ip, 192, 168, 0 ,200);
	IP4_ADDR(&static_ip_info.gw, 192, 168, 0, 1);
	IP4_ADDR(&static_ip_info.netmask, 255, 255, 255, 0);
	debug("static ip set status : %d", sdk_wifi_set_ip_info(STATION_IF, &static_ip_info));
	vTaskDelay(500);
	sdk_wifi_set_opmode(STATION_MODE);
	sdk_wifi_station_set_config(&config);
	sdk_wifi_station_connect();

	while (status != STATION_GOT_IP) {
		sdk_wifi_station_scan(NULL, scan_done_cb);
		vTaskDelayMs(5000);
		status = sdk_wifi_station_get_connect_status();
		debug("%s: status = %d\n\r", __func__, status );
		switch (status) {
			case STATION_WRONG_PASSWORD: {
				debug("WiFi: wrong password\n\r");
				break;
			}
			case STATION_NO_AP_FOUND: {
				debug("WiFi: AP not found\n\r");
				break;
			}
			case STATION_CONNECT_FAIL: {
				debug("WiFi: connection failed\r\n");
				break;
			}
			case STATION_GOT_IP: {
				debug("WiFi: Connected\n\r");
				break;
			}
		}
	}
	if (status == STATION_GOT_IP)
		while (1) {

		xQueueReceive(xQueue_events, &events, portMAX_DELAY); // Wait here an event on netconn

		if (events.nc->state == NETCONN_LISTEN) // If netconn is a server and receive incoming event on it
		{
			debug("Client incoming on server %u.\n", (uint32_t)events.nc);
			int err = netconn_accept(events.nc, &nc_in);
			if (err != ERR_OK)
			{
				if(nc_in)
					netconn_delete(nc_in);
			}
			debug("New client is %u.\n",(uint32_t)nc_in);
			ip_addr_t client_addr; //Address port
			uint16_t client_port; //Client port
			netconn_peer(nc_in, &client_addr, &client_port);
			snprintf(buf, sizeof(buf), "Your address is %d.%d.%d.%d:%u.\r\n",
					ip4_addr1(&client_addr), ip4_addr2(&client_addr),
					ip4_addr3(&client_addr), ip4_addr4(&client_addr),
					client_port);
			netconn_write(nc_in, buf, strlen(buf), NETCONN_COPY);
		}
		else if(events.nc->state != NETCONN_LISTEN) // If netconn is the client and receive data
		{
			err_t err = (netconn_recv(events.nc, &netbuf));
			//debug("************ err = %d", err);
			switch (err) {
				case ERR_OK: { // data incoming ?
					do {
						netbuf_data(netbuf, (void*)&buffer, &len_buf);
						//netconn_write(events.nc, buffer, strlen(buffer), NETCONN_COPY);
						debug("Client %u send: %s\n",(uint32_t)events.nc, buffer);
						if (strstr(buffer, "releon1") != 0) {
							gpio_write(rele1, 1);
							netconn_write(events.nc, "Rele 1 on\n", strlen("Rele 1 on\n"), NETCONN_COPY);
							debug("Rele 1 on");
						} else if (strstr(buffer, "releoff1") != 0) {
							gpio_write(rele1, 0);
							netconn_write(events.nc, "Rele 1 off\n", strlen("Rele 1 off\n"), NETCONN_COPY);
							debug("Rele 1 off");
						} else if (strstr(buffer, "releon2") != 0) {
							gpio_write(rele2, 1);
							netconn_write(events.nc, "Rele 2 on\n", strlen("Rele 2 on\n"), NETCONN_COPY);
							debug("Rele 2 on");
						} else if (strstr(buffer, "releoff2") != 0) {
							gpio_write(rele2, 0);
							netconn_write(events.nc, "Rele 2 off\n", strlen("Rele 2 off\n"), NETCONN_COPY);
							debug("Rele 2 off");
						} else if (strstr(buffer, "releon3") != 0) {
							gpio_write(rele3, 1);
							netconn_write(events.nc, "Rele 3 on\n", strlen("Rele 3 on\n"), NETCONN_COPY);
							debug("Rele 3 on");
						} else if (strstr(buffer, "releoff3") != 0) {
							gpio_write(rele3, 0);
							netconn_write(events.nc, "Rele 3 off\n", strlen("Rele 3 off\n"), NETCONN_COPY);
							debug("Rele 3 off");
						} else if (strstr(buffer, "releon4") != 0) {
							gpio_write(rele4, 1);
							netconn_write(events.nc, "Rele 4 on\n", strlen("Rele 4 on\n"), NETCONN_COPY);
							debug("Rele 4 on");
						} else if (strstr(buffer, "releoff4") != 0) {
							gpio_write(rele4, 0);
							netconn_write(events.nc, "Rele 4 off\n", strlen("Rele 4 off\n"), NETCONN_COPY);
							debug("Rele 4 off");
						} else if (strstr(buffer, "releon5") != 0) {
							gpio_write(rele5, 1);
							netconn_write(events.nc, "Rele 5 on\n", strlen("Rele 5 on\n"), NETCONN_COPY);
							debug("Rele 5 on");
						} else if (strstr(buffer, "releoff5") != 0) {
							gpio_write(rele5, 0);
							netconn_write(events.nc, "Rele 5 off\n", strlen("Rele 5 off\n"), NETCONN_COPY);
							debug("Rele 5 off");
						} else if (strstr(buffer, "status") != 0) {
							char str[50];
							sprintf(str, "R1=%d, R2=%d, R3=%d, R4=%d, R5=%d\n",
									gpio_read(rele1),
									gpio_read(rele2),
									gpio_read(rele3),
									gpio_read(rele4),
									gpio_read(rele5));
							netconn_write(events.nc, str, strlen(str), NETCONN_COPY);
							debug("%s", str);
						}
					}
					while (netbuf_next(netbuf) >= 0);
					netbuf_delete(netbuf);
					break;
				}
				case ERR_CONN: { // Not connected
					debug("Not connected netconn %u, close it \n",(uint32_t)events.nc);
					close_tcp_netconn(events.nc);
					break;
				}
				default: {
					debug("Error read netconn %u\n",(uint32_t)events.nc);
				}
			}
		}
	}
}

void user_init(void)
{
    gpio_set_iomux_function(2, IOMUX_GPIO2_FUNC_UART1_TXD);
    uart_set_baud(0, 115200);
	debug("SDK version:%s\n", sdk_system_get_sdk_version());

	//Create a queue to store events on netconns
	xQueue_events = xQueueCreate(EVENTS_QUEUE_SIZE, sizeof(netconn_events));
    xTaskCreate(socketsTask, "socketsTask", 512, NULL, 2, NULL);
}
