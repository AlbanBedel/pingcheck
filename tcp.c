/* pingcheck - Check connectivity of interfaces in OpenWRT
 *
 * Copyright (C) 2016 Bruno Randolf <br1@einfach.org>
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
#include <errno.h>
#include <string.h>

static int tcp_connect(const char* ifname, int dst, int port)
{
	int fd = open_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, ifname);
	if (fd < 0)
		return -1;

	/* connect */
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = dst;

	int ret = connect(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
	if (ret == -1 && errno != EINPROGRESS) {
		warn("TCP: could not connect");
		return -1;
	}

	return fd;
}

static bool tcp_check_connect(int fd)
{
	int err;
	socklen_t len = sizeof(err);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
	return err == 0;
}

/* for "ping" using TCP it's enough to just open a connection and see if the
 * connect fails or succeeds. If the host is unavailable or there is no
 * connectivity the connect will fail, otherwise it will succeed. This will be
 * checked in the uloop socket callback above */
static bool tcp_ping_send(struct ping_intf* pi)
{
	if (ping_has_fd(pi)) {
		// LOG_DBG("TCP connection timed out '%s'", pi->name);
		ping_close_fd(pi);
	}

	/* add socket handler to uloop.
	 * when connect() finishes, select indicates writability */
	int ret = tcp_connect(pi->device, pi->conf_host, pi->conf_tcp_port);
	if (ret > 0 && !ping_add_fd(pi, ret, ULOOP_WRITE)) {
		LOG_ERR("Could not add uloop fd %d for '%s'", ret, pi->name);
		return false;
	}
	return true;
}

static void tcp_ping_recv(struct ping_intf* pi,
						  __attribute__((unused)) unsigned int events)
{
	/* with TCP, the handler is called when connect() succeds or fails.
	 *
	 * if the connect takes longer than the ping interval, it is timed
	 * out and assumed failed before we open the next regular connection,
	 * and this handler is not called. but if the interval is large and
	 * in other cases, this handler can be called for failed connections,
	 * and to be sure we need to check if connect was successful or not.
	 *
	 * after that we just close the socket, as we don't need to send or
	 * receive any data */
	bool succ = tcp_check_connect(ping_fd(pi));
	ping_close_fd(pi);
	// printf("TCP connected %d\n", succ);
	if (succ)
		ping_received(pi);
}

const struct ping_proto tcp_ping_proto = {
	.name = "tcp",
	.socktype = SOCK_STREAM,
	.send = tcp_ping_send,
	.recv = tcp_ping_recv,
};
