/*
 * Simple example program to log packets received with the ulog
 * watcher of ebtables.
 *
 * usage:
 * Add the appropriate ebtables ulog rule, e.g. (0 < NLGROUP < 33):
 *   ebtables -A FORWARD --ulog-nlgroup NLGROUP
 * Start this application somewhere:
 *   test_ulog NLGROUP
 *
 * compile with make test_ulog KERNEL_INCLUDES=<path_to_kernel_include_dir>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include <asm/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
/* #include "ebtables_u.h" */
/* #include "ethernetdb.h" */
#include <linux/if.h>
#include <linux/netfilter_bridge/ebt_ulog.h>

/* <linux/if_vlan.h> doesn't hand this to userspace :-( */
#define VLAN_HLEN 4
struct vlan_hdr {
	unsigned short TCI;
	unsigned short encap;
};

static struct sockaddr_nl sa_local =
{
	.nl_family = AF_NETLINK,
	.nl_groups = 1,
};

static struct sockaddr_nl sa_kernel =
{
	.nl_family = AF_NETLINK,
	.nl_pid = 0,
	.nl_groups = 1,
};

/* static const char *hookstr[NF_BR_NUMHOOKS] = */
/* { */
/*         [NF_BR_POST_ROUTING] "POSTROUTING", */
/*          [NF_BR_PRE_ROUTING] "PREROUTING", */
/*            [NF_BR_LOCAL_OUT] "OUTPUT", */
/*             [NF_BR_LOCAL_IN] "INPUT", */
/*             [NF_BR_BROUTING] "BROUTING", */
/*              [NF_BR_FORWARD] "FORWARD" */
/* }; */

#define DEBUG_QUEUE 0
#define BUFLEN 65536
static char buf[BUFLEN];
static int sfd = -1;

/* Get the next ebt_ulog packets as a NULL terminated pointer array,
 * talk to the kernel if necessary */
ebt_ulog_packet_msg_t **
ulog_get_packet(void)
{
        struct nlmsghdr *nlh = NULL;
        int len, remain_len;
        int pkts_per_msg = 0;
	ebt_ulog_packet_msg_t *msg;
	socklen_t addrlen = sizeof(sa_kernel);
        const int array_chunk_size = 16;
        ebt_ulog_packet_msg_t **array;
        size_t array_len;
        size_t array_size;

recv_new:
        if (pkts_per_msg && DEBUG_QUEUE)
            printf("PACKETS IN LAST MSG: %d\n", pkts_per_msg);
        pkts_per_msg = 0;
        len = recvfrom(sfd, buf, BUFLEN, 0,
                       (struct sockaddr *)&sa_kernel, &addrlen);
        if (errno == EINTR)
            goto recv_new;
        if (addrlen != sizeof(sa_kernel)) {
            printf("addrlen %d != %d\n", addrlen,
                   sizeof(sa_kernel));
            exit(-1);
        }
        if (len == -1) {
            perror("recvmsg");
            exit(-1);
        }
        nlh = (struct nlmsghdr *)buf;
        if (nlh->nlmsg_flags & MSG_TRUNC || len > BUFLEN) {
            printf("Packet truncated");
            exit(-1);
        }
        if (!NLMSG_OK(nlh, BUFLEN)) {
            perror("Netlink message parse error\n");
            return NULL;
        }

        if (!nlh)
            return NULL;

          /* Alloc return array */
        array = malloc(sizeof(void *)*array_chunk_size);
        array_size = array_chunk_size;
        array_len = 0;

        while (nlh) {
            msg = NLMSG_DATA(nlh);
              /* Realloc array if necessary */
            if (array_len >= array_size - 1) {
                    array_size += array_chunk_size;
                    array = realloc(array, sizeof(void *)*array_size);
            }
              /* Add msg to array */
            array[array_len++] = msg;

            remain_len = (len - ((char *)nlh - buf));
            if (nlh->nlmsg_flags & NLM_F_MULTI && nlh->nlmsg_type != NLMSG_DONE)
		nlh = NLMSG_NEXT(nlh, remain_len);
            else
		nlh = NULL;

            pkts_per_msg++;
        }
        /* end of array marker */
        array[array_len] = NULL;
	return array;
}

  /* Start listening to ulog on group @group; Returns the netlink file
   * descriptor, for poll/select monitoring */
int ulog_init(int group)
{
	int i/*, curr_len , pktcnt = 0 */;
	int rcvbufsize = BUFLEN;
/* 	ebt_ulog_packet_msg_t *msg; */
/* 	struct ethhdr *ehdr; */
/* 	struct ethertypeent *etype; */
/* 	struct protoent *prototype; */
/* 	struct iphdr *iph; */
/* 	struct icmphdr *icmph; */
/* 	struct tm* ptm; */
/* 	char time_str[40], *ctmp; */

        if (sfd != -1) {
            fprintf(stderr, "already initialized");
            return sfd;
        }

        sa_local.nl_groups = sa_kernel.nl_groups = 1 << (group - 1);
	sa_local.nl_pid = getpid();
	sfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_NFLOG);
	if (!sfd) {
		perror("socket");
		exit(-1);
	}

	if (bind(sfd, (struct sockaddr *)(&sa_local), sizeof(sa_local)) == -1) {
		perror("bind");
		exit(-1);
	}
	i = setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &rcvbufsize,
	               sizeof(rcvbufsize));
        return sfd;
}

/* 	while (1) { */
/* 		if (!(msg = ulog_get_packet())) */
/* 			continue; */

/* 		if (msg->version != EBT_ULOG_VERSION) { */
/* 			printf("WRONG VERSION: %d INSTEAD OF %d\n", */
/* 			       msg->version, EBT_ULOG_VERSION); */
/* 			continue; */
/* 		} */
/* 		printf("PACKET NR: %d\n", ++pktcnt); */
/* 		iph = NULL; */
/* 		curr_len = ETH_HLEN; */

/* 		printf("INDEV=%s\nOUTDEV=%s\nPHYSINDEV=%s\nPHYSOUTDEV=%s\n" */
/* 		       "PREFIX='%s'", msg->indev, msg->outdev, msg->physindev, */
/* 		       msg->physoutdev, msg->prefix); */

/* 		ptm = localtime(&msg->stamp.tv_sec); */
/* 		strftime (time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", ptm); */
/* 		printf("\nARRIVAL TIME: %s\nMARK=%lu\nHOOK=%s\n", time_str, */
/* 		       msg->mark, hookstr[msg->hook]); */

/* 		if (msg->data_len < curr_len) { */
/* 			printf("====>Packet smaller than Ethernet header " */
/* 			       "length<====\n"); */
/* 			goto letscontinue; */
/* 		} */

/* 		printf("::::::::ETHERNET:HEADER::::::::\n"); */

/* 		ehdr = (struct ethhdr *)msg->data; */
/* 		printf("MAC SRC=%s\n", ether_ntoa((const struct ether_addr *) */
/* 		       ehdr->h_source)); */
/* 		printf("MAC DST=%s\nETHERNET PROTOCOL=", ether_ntoa( */
/* 		       (const struct ether_addr *)ehdr->h_dest)); */
/* 		etype = getethertypebynumber(ntohs(ehdr->h_proto)); */
/* 		if (!etype) */
/* 			printf("0x%x\n", ntohs(ehdr->h_proto)); */
/* 		else */
/* 			printf("%s\n", etype->e_name); */

/* 		if (ehdr->h_proto == htons(ETH_P_8021Q)) { */
/* 			struct vlan_hdr *vlanh = (struct vlan_hdr *) */
/* 			                          (((char *)ehdr) + curr_len); */
/* 			printf("::::::::::VLAN:HEADER::::::::::\n"); */
/* 			curr_len += VLAN_HLEN; */
/* 			if (msg->data_len < curr_len) { */
/* 				printf("====>Packet only contains partial " */
/* 				       "VLAN header<====\n"); */
/* 				goto letscontinue; */
/* 			} */

/* 			printf("VLAN TCI=%d\n", ntohs(vlanh->TCI)); */
/* 			printf("VLAN ENCAPS PROTOCOL="); */
/* 			etype = getethertypebynumber(ntohs(vlanh->encap)); */
/* 			if (!etype) */
/* 				printf("0x%x\n", ntohs(vlanh->encap)); */
/* 			else */
/* 				printf("%s\n", etype->e_name); */
/* 			if (ehdr->h_proto == htons(ETH_P_IP)) */
/* 				iph = (struct iphdr *)(vlanh + 1); */
/* 		} else if (ehdr->h_proto == htons(ETH_P_IP)) */
/* 			iph = (struct iphdr *)(((char *)ehdr) + curr_len); */
/* 		if (!iph) */
/* 			goto letscontinue; */

/* 		curr_len += sizeof(struct iphdr); */
/* 		if (msg->data_len < curr_len || msg->data_len < */
/* 		    (curr_len += iph->ihl * 4 - sizeof(struct iphdr))) { */
/* 			printf("====>Packet only contains partial IP " */
/* 			       "header<====\n"); */
/* 			goto letscontinue; */
/* 		} */

/* 		printf(":::::::::::IP:HEADER:::::::::::\n"); */
/* 		printf("IP SRC ADDR="); */
/* 		for (i = 0; i < 4; i++) */
/* 			printf("%d%s", ((unsigned char *)&iph->saddr)[i], */
/* 			   (i == 3) ? "" : "."); */
/* 		printf("\nIP DEST ADDR="); */
/* 		for (i = 0; i < 4; i++) */
/* 			printf("%d%s", ((unsigned char *)&iph->daddr)[i], */
/* 			   (i == 3) ? "" : "."); */
/* 		printf("\nIP PROTOCOL="); */
/* 		if (!(prototype = getprotobynumber(iph->protocol))) */
/* 			printf("%d\n", iph->protocol); */
/* 		else */
/* 			printf("%s\n", prototype->p_name); */

/* 		if (iph->protocol != IPPROTO_ICMP) */
/* 			goto letscontinue; */

/* 		icmph = (struct icmphdr *)(((char *)ehdr) + curr_len); */
/* 		curr_len += 4; */
/* 		if (msg->data_len < curr_len) { */
/* truncated_icmp: */
/* 			printf("====>Packet only contains partial ICMP " */
/* 			       "header<====\n"); */
/* 			goto letscontinue; */
/* 		} */
/* 		if (icmph->type != ICMP_ECHO && icmph->type != ICMP_ECHOREPLY) */
/* 			goto letscontinue; */

/* 		curr_len += 4; */
/* 		if (msg->data_len < curr_len) */
/* 			goto truncated_icmp; */
/* 		/\* Normally the process id, it's sent out in machine */
/* 		 * byte order *\/ */

/* 		printf("ICMP_ECHO IDENTIFIER=%u\n", icmph->un.echo.id); */
/* 		printf("ICMP_ECHO SEQ NR=%u\n", ntohs(icmph->un.echo.sequence)); */

/* letscontinue: */
/* 		printf("===>Total Packet length: %d, of which we examined " */
/* 		       "%d bytes\n", msg->data_len, curr_len); */
/* 		printf("###############################\n" */
/* 		       "######END#OF##PACKET#DUMP######\n" */
/* 		       "###############################\n"); */
/* 	} */

/* 	return 0; */
/* } */

