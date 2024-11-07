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
#include "log.h"
#include "main.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* uloop callback when received something on a ping socket */
static void ping_fd_handler(struct uloop_fd* fd,
							__attribute__((unused)) unsigned int events)
{
	struct ping_intf* pi = container_of(fd, struct ping_intf, ufd);

	if (pi->conf_proto == ICMP) {
		int received_fd = icmp_echo_receive(fd->fd);
		if (received_fd == -1) {
			return;
		} else {
			if (fd->fd != received_fd) {
				struct ping_intf* interface = get_interface_by_fd(received_fd);
				if (interface != NULL) {
					pi = container_of(&interface->ufd, struct ping_intf, ufd);
				} else {
					printf("ICMP echo received for different handle that was not found %d\n", received_fd);
					return;
				}
			}
		}
	} else if (pi->conf_proto == TCP) {
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
		bool succ = tcp_check_connect(fd->fd);
		ping_close_fd(pi);
		// printf("TCP connected %d\n", succ);
		if (!succ) {
			return;
		}
	}

	// LOG_DBG("Received pong on '%s'", pi->name);
	pi->cnt_succ++;

	/* calculate round trip time */
	struct timespec time_recv;
	clock_gettime(CLOCK_MONOTONIC, &time_recv);
	pi->last_rtt = timespec_diff_ms(pi->time_sent, time_recv);
	if (pi->last_rtt > pi->max_rtt) {
		pi->max_rtt = pi->last_rtt;
	}

	/* online just confirmed: move timeout for offline to later
	 * and give the next reply an extra window of two times the last RTT */
	uloop_timeout_set(&pi->timeout_offline,
					  pi->conf_timeout * 1000 + pi->last_rtt * 2);

	state_change(ONLINE, pi);
}

/* uloop timeout callback when we did not receive a ping reply for a certain
 * time */
static void uto_offline_cb(struct uloop_timeout* t)
{
	struct ping_intf* pi = container_of(t, struct ping_intf, timeout_offline);
	state_change(OFFLINE, pi);
}

/* uloop timeout callback when it's time to send a ping */
static void uto_ping_send_cb(struct uloop_timeout* t)
{
	struct ping_intf* pi = container_of(t, struct ping_intf, timeout_send);
	ping_send(pi);
	/* re-schedule next sending */
	uloop_timeout_set(t, pi->conf_interval * 1000);
}

bool ping_init(struct ping_intf* pi)
{
	int ret;

	if (pi->ufd.fd != 0) {
		LOG_ERR("Ping on '%s' already init", pi->name);
		return true;
	}

	if (!pi->conf_ignore_ubus) {
		ret = ubus_interface_get_status(pi->name, pi->device, MAX_IFNAME_LEN);
		if (ret < 0) {
			LOG_INF("Interface '%s' not found or error", pi->name);
			pi->state = UNKNOWN;
			return false;
		} else if (ret == 0) {
			LOG_INF("Interface '%s' not up", pi->name);
			pi->state = DOWN;
			return false;
		} else if (ret == 1) {
			LOG_INF("Interface '%s' (%s) has no default route but local one",
					pi->name, pi->device);
			pi->state = UP_WITHOUT_DEFAULT_ROUTE;
		} else if (ret == 2) {
			pi->state = UP;
		}
	} else {
		pi->state = UP;
	}

	LOG_INF("Init %s ping on '%s' (%s)", pi->conf_proto == TCP ? "TCP" : "ICMP",
			pi->name, pi->device);

	/* init ICMP socket. for TCP we open a new socket every time */
	if (pi->conf_proto == ICMP) {
		ret = icmp_init(pi->device);
		if (ret < 0) {
			return false;
		}

		/* add socket handler to uloop */
		if (!ping_add_fd(pi, ret, ULOOP_READ))
			return false;
	}

	/* regular sending of ping (start first in 1 sec) */
	pi->timeout_send.cb = uto_ping_send_cb;
	ret = uloop_timeout_set(&pi->timeout_send, 1000);
	if (ret < 0) {
		LOG_ERR("Could not add uloop send timeout for '%s'", pi->name);
		return false;
	}

	/* timeout for offline state, if no reply has been received
	 *
	 * add 900ms to the timeout to give the last reply a chance to arrive
	 * before the timeout triggers, in case the timout is a multiple of
	 * interval. this will later be adjusted to the last RTT
	 */
	pi->timeout_offline.cb = uto_offline_cb;
	ret = uloop_timeout_set(&pi->timeout_offline,
							pi->conf_timeout * 1000 + 900);
	if (ret < 0) {
		LOG_ERR("Could not add uloop offline timeout for '%s'", pi->name);
		return false;
	}

	/* reset counters */
	pi->cnt_sent = 0;
	pi->cnt_succ = 0;
	pi->last_rtt = 0;
	pi->max_rtt = 0;

	return true;
}

int ping_fd(struct ping_intf* pi)
{
	return ping_has_fd(pi) ? pi->ufd.fd : -1;
}

bool ping_has_fd(struct ping_intf* pi)
{
	return pi->ufd.registered;
}

bool ping_add_fd(struct ping_intf* pi, int fd, unsigned int flags)
{
	int ret;

	if (fd < 0) {
		LOG_ERR("can't register invalid fd for '%s'", pi->name);
		return false;
	}

	if (ping_has_fd(pi)) {
		LOG_ERR("fd already registered for '%s'", pi->name);
		return false;
	}

	pi->ufd.fd = fd;
	pi->ufd.cb = ping_fd_handler;
	ret = uloop_fd_add(&pi->ufd, flags);
	if (ret < 0) {
		LOG_ERR("Could not add uloop fd %d for '%s'", fd, pi->name);
		return false;
	}
	return true;
}

void ping_close_fd(struct ping_intf* pi)
{
	if (ping_has_fd(pi)) {
		uloop_fd_delete(&pi->ufd);
		close(pi->ufd.fd);
		pi->ufd.fd = -1;
	}
}

static bool ping_resolve(struct ping_intf* pi)
{
	struct addrinfo hints;
	struct addrinfo* addr;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = pi->conf_proto == ICMP ? SOCK_DGRAM : SOCK_STREAM;

	int r = getaddrinfo(pi->conf_hostname, NULL, &hints, &addr);
	if (r < 0 || addr == NULL) {
		LOG_ERR("Failed to resolve '%s'", pi->conf_hostname);
		return false;
	}

	/* use only first address */
	struct sockaddr_in* sa = (struct sockaddr_in*)addr->ai_addr;
	printf("Resolved %s to %s\n", pi->conf_hostname,
		   inet_ntoa((struct in_addr)sa->sin_addr));
	pi->conf_host = sa->sin_addr.s_addr;

	freeaddrinfo(addr);
	return true;
}

/* for "ping" using TCP it's enough to just open a connection and see if the
 * connect fails or succeeds. If the host is unavailable or there is no
 * connectivity the connect will fail, otherwise it will succeed. This will be
 * checked in the uloop socket callback above */
static bool ping_send_tcp(struct ping_intf* pi)
{
	if (ping_has_fd(pi)) {
		// LOG_DBG("TCP connection timed out '%s'", pi->name);
		ping_close_fd(pi);
	}

	int ret = tcp_connect(pi->device, pi->conf_host, pi->conf_tcp_port);
	if (ret > 0) {
		/* add socket handler to uloop.
		 * when connect() finishes, select indicates writability */
		if (!ping_add_fd(pi, ret, ULOOP_WRITE))
			return false;
	}
	return true;
}

bool ping_send(struct ping_intf* pi)
{
	bool ret = false;

	/* resolve at least every 10th time */
	if (pi->conf_host == 0 || pi->state != ONLINE || pi->cnt_sent % 10 == 0) {
		if (!ping_resolve(pi)) {
			return false;
		}
	}

	/* either send ICMP ping or start TCP connection */
	if (pi->conf_proto == ICMP) {
		if (!ping_has_fd(pi)) {
			LOG_ERR("ping not init on '%s'", pi->name);
			return false;
		}
		ret = icmp_echo_send(ping_fd(pi), pi->conf_host, pi->cnt_sent);
	} else if (pi->conf_proto == TCP) {
		ret = ping_send_tcp(pi);
	}

	/* common code */
	if (ret) {
		pi->cnt_sent++;
		clock_gettime(CLOCK_MONOTONIC, &pi->time_sent);
	} else {
		LOG_ERR("Could not send ping on '%s'", pi->name);
	}
	return ret;
}

void ping_stop(struct ping_intf* pi)
{
	uloop_timeout_cancel(&pi->timeout_offline);
	uloop_timeout_cancel(&pi->timeout_send);
	ping_close_fd(pi);
}
