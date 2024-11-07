/* pingcheck - Check connectivity of interfaces in OpenWRT
 *
 * Copyright (C) 2024 Alban Bedel <albeu@free.fr>
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
#include "main.h"
#include "log.h"

#include <arpa/inet.h>
#include <err.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

/* The pinger can run in unicast or broadcast mode:
 *
 * 1. Unicast
 *
 *    The unicast mode is suited if only a few devices ping the same
 *    target. The initial probe is sent to the broadcast address with
 *    the host address as source, so only this host get the reply.
 *    After a reply has been received the following requests are sent
 *    directly to the target address. If a reply is not received the
 *    broadcast address is used again to recover as soon as possible.
 *
 * 2. Broadcast mode
 *
 *    The broadcast mode is better suited if many devices need to ping
 *    the same target. In this mode the probes have both the source
 *    and destination set to the broadcast address. This way all devices
 *    receive the reply when a single one send a request.
 *
 * In both modes the next probe is rescheduled if another probe is seen
 * with the broadcast address as source.
 *
 */

struct arp_ping {
	struct sockaddr_ll local_addr;
	struct sockaddr_ll remote_addr;
};

struct arp_ip4 {
	uint16_t          htype;
	uint16_t          ptype;
	uint8_t           hlen;
	uint8_t           plen;
	uint16_t          oper;
	struct ether_addr sha;
	in_addr_t         spa;
	struct ether_addr tha;
	in_addr_t         tpa;
} __attribute__((packed));

static const struct ether_addr eth_broadcast_addr = {
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
};

static bool eth_addr_eq(const struct ether_addr *a,
						const struct ether_addr *b) {
	return memcmp(a, b, sizeof(struct ether_addr)) == 0;
}

static bool arp_ping_init(struct ping_intf* pi)
{
	struct sockaddr_ll addr = {};
	struct ifreq req = {};
	struct arp_ping *arp;
	int err, fd;

	if (!pi->device[0]) {
		LOG_ERR("%s: a device must be configured for ARP ping", pi->name);
		return false;
	}

	// Make the local address from the device informations
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ARP);
	addr.sll_halen = ETH_ALEN;

	// But we need a socket to get the device infos
	fd = open_socket(addr.sll_family, SOCK_DGRAM,
					 addr.sll_protocol, pi->device);
	if (fd < 0) {
		return false;
	}

	// Get the interface index
	snprintf(req.ifr_name, IFNAMSIZ, "%.*s", IFNAMSIZ-1, pi->device);
	err = ioctl(fd, SIOCGIFINDEX, &req);
	if (err < 0) {
		warn("%s: failed to get interface index", pi->device);
		close(fd);
		return false;
	}
	addr.sll_ifindex = req.ifr_ifindex;

	// In broadcast mode we use the broadcast address
	// otherwise we need to get the address of the interface
	if (pi->conf_arp_broadcast) {
		memcpy(addr.sll_addr, &eth_broadcast_addr, addr.sll_halen);
	} else {
		err = ioctl(fd, SIOCGIFHWADDR, &req);
		if (err < 0) {
			warn("%s: failed to get hardware address", pi->device);
			close(fd);
			return false;
		}
		memcpy(addr.sll_addr, req.ifr_hwaddr.sa_data, addr.sll_halen);
	}

	// Create our data struct, if that fails we probably can't format
	// an error message either.
	arp = calloc(sizeof(*arp), 1);
	if (arp == NULL) {
		close(fd);
		return false;
	}

	arp->local_addr = addr;
	arp->remote_addr = addr;
	// Initialy we always send to the broadcast address
	memcpy(arp->remote_addr.sll_addr, &eth_broadcast_addr, addr.sll_halen);

	// Register the fd to read the incoming messages
	if (!ping_add_fd(pi, fd, ULOOP_READ)) {
		close(fd);
		free(arp);
		return false;
	}

	pi->proto_data = arp;
	return true;
}

static void arp_ping_uninit(struct ping_intf* pi)
{
	ping_close_fd(pi);
	if (pi->proto_data) {
		free(pi->proto_data);
		pi->proto_data = NULL;
	}
}

static bool arp_ping_send(struct ping_intf* pi)
{
	struct arp_ping *arp = pi->proto_data;
	struct arp_ip4 probe = {};
	int ret;

	if (!arp || !ping_has_fd(pi)) {
		LOG_ERR("%s: ping not initialized", pi->name);
		return false;
	}

	probe.htype = htons(ARPHRD_ETHER);
	probe.ptype = htons(ETH_P_IP);
	probe.hlen  = sizeof(probe.sha),
	probe.plen  = sizeof(probe.spa),
	probe.oper  = htons(ARPOP_REQUEST);
	memcpy(&probe.sha, arp->local_addr.sll_addr, sizeof(probe.sha));
	probe.tpa   = pi->conf_host;

	ret = sendto(pi->ufd.fd, &probe, sizeof(probe), 0,
				 (struct sockaddr*)&arp->remote_addr,
				 sizeof(arp->remote_addr));
	// Update the remote address to the broadcast address so we'll
	// send to the broadcasts address again if we don't get a reply.
	memcpy(arp->remote_addr.sll_addr, &eth_broadcast_addr,
		   arp->remote_addr.sll_halen);
	if (ret <= 0) {
		warn("%s: sendto", pi->name);
		return false;
	}
	return true;
}

static void arp_ping_recv(struct ping_intf* pi,
						  __attribute__((unused)) unsigned int events)
{
	struct arp_ping *arp = pi->proto_data;
	struct arp_ip4 resp = {};
	int ret;

	ret = recv(ping_fd(pi), &resp, sizeof(resp), 0);
	if (ret < (int)sizeof(resp)) {
		warn("%s: received too short packet", pi->name);
		return;
	}

	// Check that it is ARP for IPv4
	if (resp.htype != htons(ARPHRD_ETHER) || resp.ptype != htons(ETH_P_IP) ||
		resp.hlen != sizeof(resp.sha) || resp.plen != sizeof(resp.spa))
		return;

	// If someone else sent a probe
	if (resp.oper == htons(ARPOP_REQUEST) && resp.spa == INADDR_ANY &&
		// for the host we watch
		resp.tpa == (uint32_t)pi->conf_host &&
		// with the broadcast address as source
		eth_addr_eq(&resp.sha, &eth_broadcast_addr)) {
		// we can just reschule our own send as we should see the reply
		ping_reschedule_send(pi);
		ping_set_time_sent(pi);
		return;
	}

	// We are only interested in replies about the host we query
	if (resp.oper != htons(ARPOP_REPLY) || resp.spa != (uint32_t)pi->conf_host)
		return;

	// In unicast mode update the remote address from the response
	// TODO: Check that we got a valid MAC
	if (!pi->conf_arp_broadcast)
		memcpy(arp->remote_addr.sll_addr, &resp.sha, sizeof(resp.sha));

	ping_received(pi);
}

const struct ping_proto arp_ping_proto = {
	.name = "arp",
	.socktype = SOCK_DGRAM,
	.init = arp_ping_init,
	.uninit = arp_ping_uninit,
	.send = arp_ping_send,
	.recv = arp_ping_recv,
};
