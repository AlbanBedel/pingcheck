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

#include <err.h>
#include <string.h>
#include <linux/if.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

long timespec_diff_ms(struct timespec start, struct timespec end)
{
	return (end.tv_sec - start.tv_sec) * 1000
		   + (end.tv_nsec - start.tv_nsec) / 1000000;
}

int open_socket(int domain, int type, int protocol, const char *ifname)
{
	int fd, ret;

	if (ifname != NULL && strlen(ifname) >= IFNAMSIZ) {
		warn("ifname too long");
		return -1;
	}

	fd = socket(domain, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
	if (fd < 0) {
		warn("Could not open socket");
		return -1;
	}

	/* bind to interface */
	if (ifname != NULL) {
		struct ifreq ifr = {};
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
		ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
		if (ret < 0) {
			warn("could not bind to '%s'", ifname);
			close(fd);
			return -1;
		}
	}

	return fd;
}
