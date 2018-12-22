#ifndef __BOOTP_H
#define __BOOTP_H

/**
 * \brief Affichage synthétique de BOOTP/DHCP
 */
void afficherBootpSynthe(char *appdump);

/**
 * \brief Affichage complet de BOOTP/DHCP
 */
void afficherBootpComplet(char *appdump);


/* @(#) $Header: /tcpdump/master/tcpdump/bootp.h,v 1.19 2008-04-22 09:46:03 hannes Exp $ (LBL) */
/*
 * Bootstrap Protocol (BOOTP).  RFC951 and RFC1048.
 *
 * This file specifies the "implementation-independent" BOOTP protocol
 * information which is common to both client and server.
 *
 * Copyright 1988 by Carnegie Mellon.
 *
 * Permission to use, copy, modify, and distribute this program for any
 * purpose and without fee is hereby granted, provided that this copyright
 * and permission notice appear on all copies and supporting documentation,
 * the name of Carnegie Mellon not be used in advertising or publicity
 * pertaining to distribution of the program without specific prior
 * permission, and notice be given in supporting documentation that copying
 * and distribution is by permission of Carnegie Mellon and Stanford
 * University.  Carnegie Mellon makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */
struct bootp {
	u_int8_t	bp_op;		/* packet opcode type */
	u_int8_t	bp_htype;	/* hardware addr type */
	u_int8_t	bp_hlen;	/* hardware addr length */
	u_int8_t	bp_hops;	/* gateway hops */
	u_int32_t	bp_xid;		/* transaction ID */
	u_int16_t	bp_secs;	/* seconds since boot began */
	u_int16_t	bp_flags;	/* flags - see bootp_flag_values[] in print-bootp.c */
	struct in_addr	bp_ciaddr;	/* client IP address */
	struct in_addr	bp_yiaddr;	/* 'your' IP address */
	struct in_addr	bp_siaddr;	/* server IP address */
	struct in_addr	bp_giaddr;	/* gateway IP address */
	u_int8_t	bp_chaddr[16];	/* client hardware address */
	u_int8_t	bp_sname[64];	/* server host name */
	u_int8_t	bp_file[128];	/* boot file name */
	u_int8_t	bp_vend[64];	/* vendor-specific area */
} UNALIGNED;

/* DHCP Message types (values for TAG_DHCP_MESSAGE option) */
#define		DHCPDISCOVER    1
#define		DHCPOFFER	    2
#define		DHCPREQUEST	    3
#define		DHCPDECLINE	    4
#define		DHCPACK		    5
#define		DHCPNAK		    6
#define		DHCPRELEASE	    7
#define		DHCPINFORM	    8

#endif