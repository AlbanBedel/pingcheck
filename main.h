/* pingcheck - Check connectivity of interfaces in OpenWRT
 *
 * Copyright (C) 2015 Bruno Randolf <br1@einfach.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <libubox/runqueue.h>
#include <libubox/uloop.h>
#include <stdbool.h>

#define MAX_IFNAME_LEN	   256
#define MAX_HOSTNAME_LEN   256
#define MAX_PROTO_LEN      16
#define MAX_NUM_INTERFACES 8
#define SCRIPTS_TIMEOUT	   10	/* 10 sec */
#define UBUS_TIMEOUT	   3000 /* 3 sec */

enum online_state {
	UNKNOWN,
	DOWN,
	UP_WITHOUT_DEFAULT_ROUTE,
	UP,
	OFFLINE,
	ONLINE
};

struct scripts_proc {
	struct runqueue_process proc;
	struct ping_intf* intf;
	enum online_state state;
};

struct ping_proto {
	const char *name;
	int socktype;
	bool (*init)(struct ping_intf* pi);
	void (*uninit)(struct ping_intf* pi);
	bool (*send)(struct ping_intf* pi);
	void (*recv)(struct ping_intf* pi, unsigned int events);
};

struct ping_intf {
	/* public state */
	char name[MAX_IFNAME_LEN];
	char device[MAX_IFNAME_LEN];
	enum online_state state;
	unsigned int cnt_sent;
	unsigned int cnt_succ;
	unsigned int last_rtt; /* in ms */
	unsigned int max_rtt;  /* in ms */

	/* config items */
	int conf_interval;
	int conf_timeout;
	char conf_hostname[MAX_HOSTNAME_LEN];
	int conf_host; /* resolved IP */
	char conf_proto[MAX_PROTO_LEN];
	int conf_tcp_port;
	int conf_panic_timeout; /* minutes */
	bool conf_ignore_ubus;
	bool conf_disabled;

	/* internal state for ping */
	const struct ping_proto *proto;
	struct uloop_fd ufd;
	struct uloop_timeout timeout_offline;
	struct uloop_timeout timeout_send;
	struct timespec time_sent;

	/* Storage for protocol specific stuff */
	void *proto_data;

	/* internal state for scripts */
	struct scripts_proc scripts_on;
	struct scripts_proc scripts_off;
};

// utils.c
long timespec_diff_ms(struct timespec start, struct timespec end);

// ping.c
bool ping_init(struct ping_intf* pi);
int  ping_fd(struct ping_intf* pi);
bool ping_has_fd(struct ping_intf* pi);
bool ping_add_fd(struct ping_intf* pi, int fd, unsigned int flags);
void ping_close_fd(struct ping_intf* pi);
bool ping_send(struct ping_intf* pi);
void ping_received(struct ping_intf* pi);
void ping_received_from(struct ping_intf* pi, int fd);
void ping_stop(struct ping_intf* pi);
const struct ping_proto* ping_get_protocol(const char *name);

// ubus.c
bool ubus_init(void);
bool ubus_listen_network_events(void);
int ubus_interface_get_status(const char* name, char* device,
							  size_t device_len);
bool ubus_register_server(void);
void ubus_finish(void);

// uci.c
int uci_config_pingcheck(struct ping_intf* intf, int len);

// scripts.c
void scripts_init(void);
void scripts_run(struct ping_intf* pi, enum online_state state_new);
void scripts_run_panic(void);
void scripts_finish(void);

// main.c
void notify_interface(const char* interface, const char* action);
struct ping_intf* get_interface_by_fd(int fd);
struct ping_intf* get_interface(const char* interface);
const char* get_status_str(enum online_state state);
enum online_state get_global_status();
int get_online_interface_names(const char** dest, int destLen);
int get_all_interface_names(const char** dest, int destLen);
void state_change(enum online_state state_new, struct ping_intf* pi);
void reset_counters(const char* interface);
