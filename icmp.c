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
#include "main.h"
#include "log.h"

/* keep libc includes before linux headers for musl compatibility */
#include <netinet/in.h>

#include <err.h>
#include <linux/icmp.h>
#include <linux/ip.h>

static int pid = -1;

/* standard 1s complement checksum */
static unsigned short checksum(void* b, int len)
{
	unsigned short* buf = b;
	unsigned int sum = 0;
	unsigned short result;

	for (sum = 0; len > 1; len -= 2) {
		sum += *buf++;
	}
	if (len == 1) {
		sum += *(unsigned char*)buf;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

static int icmp_init(const char* ifname)
{
	pid = getpid();

	return open_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP, ifname);
}

static bool icmp_echo_send(int fd, int dst_ip, int cnt)
{
	char buf[500];
	int ret;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = 0;
	addr.sin_addr.s_addr = dst_ip;

	struct icmphdr* icmp = (struct icmphdr*)buf;

	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = htons(pid + fd);
	icmp->un.echo.sequence = htons(cnt);
	icmp->checksum = 0;
	icmp->checksum = checksum(buf, sizeof(struct icmphdr));

	ret = sendto(fd, &buf, sizeof(struct icmphdr), 0, (struct sockaddr*)&addr,
				 sizeof(addr));
	if (ret <= 0) {
		warn("sendto");
		return false;
	}
	return true;
}

static int icmp_echo_receive(int fd)
{
	char buf[500];
	int ret;

	ret = recv(fd, buf, sizeof(buf), 0);
	if (ret < (int)(sizeof(struct icmphdr) + sizeof(struct iphdr))) {
		warn("received packet too short");
		return -1;
	}

	struct iphdr* ip = (struct iphdr*)buf;
	struct icmphdr* icmp = (struct icmphdr*)(buf + ip->ihl * 4);

	int csum_recv = icmp->checksum;
	icmp->checksum = 0; // need to zero before calculating checksum
	int csum_calc = checksum(icmp, sizeof(struct icmphdr));
	int received_fd = ntohs(icmp->un.echo.id) - pid;
	if (csum_recv == csum_calc &&		// checksum correct
		icmp->type == ICMP_ECHOREPLY && // correct type
		received_fd >= 0) {				// handle could be valid
		return received_fd;
	}
	return -1;
}

static bool icmp_ping_init(struct ping_intf* pi)
{
	int fd = icmp_init(pi->device);
	if (fd < 0)
		return false;

	if (!ping_add_fd(pi, fd, ULOOP_READ)) {
		close(fd);
		return false;
	}
	return true;
}

static bool icmp_ping_send(struct ping_intf* pi)
{
	if (!ping_has_fd(pi)) {
		LOG_ERR("ping not init on '%s'", pi->name);
		return false;
	}
	return icmp_echo_send(ping_fd(pi), pi->conf_host, pi->cnt_sent);
}

static void icmp_ping_recv(struct ping_intf* pi,
						   __attribute__((unused)) unsigned int events)
{
	int recv_fd = ping_fd(pi);
	int from_fd = icmp_echo_receive(recv_fd);

	if (from_fd < 0)
		return;

	if (from_fd == recv_fd)
		ping_received(pi);
	else
		ping_received_from(pi, from_fd);
}

const struct ping_proto icmp_ping_proto = {
	.name = "icmp",
	.socktype = SOCK_DGRAM,
	.init = icmp_ping_init,
	.send = icmp_ping_send,
	.recv = icmp_ping_recv,
};
