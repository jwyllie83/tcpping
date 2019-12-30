/*
Copyright (c) 2010, 2011, 2012, 2014 Jim Wyllie
Copyright (c) 2004, Steven Kehlet
Copyright (c) 2011, Ethan Blanton
Copyright (c) 2011, Mateusz Viste
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.
3. The names of all tcpping copyright holders may not be used to endorse
   or promote products derived from this software without specific prior
   written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifdef linux
#define __FAVOR_BSD
#endif
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <libnet.h>
#include <sys/wait.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>

#define tcp_flag_isset(tcpptr, flag) (((tcpptr->th_flags) & (flag)) == (flag))

/* Define the types of packets that we're sniffing for on the wire */
#define UNINTERESTING 0
#define SYN_FROM_US 1
#define SYNACK_FROM_THEM 2
#define ICMP_TIMEEXCEEDED 3

struct in_addr src_ip;
int ttl = 64;
char *myname;
pid_t child_pid;
int keep_going = 1;
int verbose = 0;
int notify_fd;
struct timeval tv_timxceed;
int sequence_offset = 0;
char *dest_name;
in_addr_t dest_ip = 0;
u_short dest_port = 80;
u_short src_port = 0;

float min_ping = -1;
float avg_ping = 0;
float max_ping = 0;
int total_syns = 0;
int total_synacks = 0;
int total_rsts = 0;
int successful_pings = 0;

/* Global handle to libnet -- libnet1 requires only one instantiation per process */
libnet_t *l;
libnet_ptag_t tcp_pkt;
libnet_ptag_t ip_pkt;

/* There are problems with duplicate SYN/ACK packets and other oddities with
 * firewalls and established connections.  Rather than solve all of them, I'm
 * just going to count the first sequence-number response and ignore all
 * others.
 * 
 * Rather than store state for all results, we'll just have rolling state for a
 * 32-bit bitmask.  I guess something can go wrong but it will definitely be
 * more accurate than what we have today with negative loss rates :)
 */
int32_t seen_response_bitflags = 0;

/* Keep track of a recent history of packet send times to accurately calculate
 * when packets were received
 */

#define PACKET_HISTORY 1024
struct timeval sent_times[PACKET_HISTORY];

void handle_sigalrm(int junk)
{
	/* do nothing */
}

/* wait for child to exit so the user's prompt doesn't
   come back before the stats */
void handle_sigint(int junk)
{
	waitpid(child_pid, NULL, 0);
	libnet_destroy(l);
	exit(0);
}

/* Some functions relating to keeping track of sequence state */

unsigned int tcpseq_to_orderseq(unsigned int tcpseq)
{
	return (unsigned int)((tcpseq - sequence_offset) / 100);
}

int get_seenflag(unsigned int tcpseq)
{
	unsigned int orderseq = tcpseq_to_orderseq(tcpseq);
	return ((seen_response_bitflags >> (orderseq % 32)) & 1);
}

void set_seenflag(unsigned int tcpseq, int flag)
{
	unsigned int orderseq = tcpseq_to_orderseq(tcpseq);
	unsigned int shift = orderseq % 32;

	if (flag > 0) {
		seen_response_bitflags = seen_response_bitflags | (1 << shift);
	} else {
		if (get_seenflag(tcpseq) == 1) {
			seen_response_bitflags = seen_response_bitflags ^ (1 << shift);
		}
	}
}

/* Sleep for a given number of milliseconds */
int msleep(long duration)
{
	struct timespec wait_time;
	struct timespec remainder;

	wait_time.tv_sec = duration / 1000;
	wait_time.tv_nsec = (long)(duration % 1000) * 1000000;

	return nanosleep(&wait_time, &remainder);
}

/* Function to determine the millisecond-difference between two timestamps */
long timestamp_difference(const struct timeval *one, const struct timeval *two)
{
	long difference = 0;
	difference += ((one->tv_sec - two->tv_sec) * 1000);
	difference += ((one->tv_usec - two->tv_usec) / 1000);
	return difference;
}

/* Function to validate that the given device is a valid one according to pcap;
 * used for setuid safety to validate the device name.  device_name is
 * untrusted here.
 */
int check_device_name(char *device_name)
{
	pcap_if_t *interface_list = NULL;
	pcap_if_t *current_interface = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	int r;

	/* Use pcap to fetch all of the devices for capturing */
	r = pcap_findalldevs(&interface_list, errbuf);
	if (r == -1) {
		fprintf(stderr, "pcap_findalldevs returned -1: %s\n", errbuf);
		exit(1);
	}

	/* No devices?  Guess this isn't a valid one */
	if (interface_list == NULL) {
		return 0;
	}

	/* Check the list of interfaces */
	for (
		current_interface = interface_list;
		current_interface != NULL;
		current_interface = current_interface -> next ) {

		if (strncmp(current_interface->name, device_name, strlen(current_interface->name)) == 0
			&& device_name[strlen(current_interface->name)] == '\0') {
			pcap_freealldevs(interface_list);
			return 1;
		}
	}

	/* No matches?  Fail out */
	pcap_freealldevs(interface_list);
	return 0;
}

void sanitize_environment()
{
#ifdef _SVID_SOURCE
	clearenv();
#elif _XOPEN_SOURCE
	clearenv();
#else
	extern char **environ;
	environ = NULL;
#endif
}

void print_stats(int junk)
{
	printf("\n");
	
	printf("--- %s TCP ping statistics ---\n", dest_name);
	total_syns = (total_syns != 0 ? total_syns : 1);
	printf("%d SYN packets transmitted, %d SYN/ACKs and %d RSTs received, %.1f%% packet loss\n", 
		total_syns, total_synacks, total_rsts, 
		(1 - (successful_pings*1.0/total_syns))*100);
	printf("round-trip min/avg/max = %.3f/%.3f/%.3f ms\n",
		min_ping, avg_ping, max_ping);

	exit(0);
}

char *inet_ntoa2(in_addr_t addr)
{
	struct in_addr iaddr;
	iaddr.s_addr = addr;
	return inet_ntoa(iaddr);
}

void show_packet(struct ip *ip, struct tcphdr *tcp, const struct pcap_pkthdr *header, const u_char *packet)
{
	int r;
	struct timeval tv;
	char flags[32];

	r = gettimeofday(&tv, NULL);

	if (r < 0) {
		perror("gettimeofday");
		exit(1);
	}

	if (tcp) {
		snprintf(flags, sizeof(flags), "[%s%s%s%s%s%s]", 
			 (tcp_flag_isset(tcp, TH_FIN) ? "F" : ""),
			 (tcp_flag_isset(tcp, TH_SYN) ? "S" : ""),
			 (tcp_flag_isset(tcp, TH_RST) ? "R" : ""),
			 (tcp_flag_isset(tcp, TH_PUSH) ? "P" : ""),
			 (tcp_flag_isset(tcp, TH_ACK) ? "A" : ""),
			 (tcp_flag_isset(tcp, TH_URG) ? "U" : "")
		 );
	}

	printf("%ld.%ld", tv.tv_sec, tv.tv_usec);
	printf(" %s", inet_ntoa(ip->ip_src));

	if (tcp) {
		printf(":%d", ntohs(tcp->th_sport));
	}

	printf(" -> %s", inet_ntoa(ip->ip_dst));

	if (tcp) {
		printf(":%d %s", ntohs(tcp->th_dport), flags);
	}

	printf(" Length: %u", header->caplen);
	printf("\n");

	/* If we *really* want to be verbose, give us the packet and our delineations */
	if (verbose >= 2) {
		int i;
		printf("\tPacket:");
		for (i = 0; i < header->caplen; ++i) {
			printf(" %02X", packet[i]);
		}
		printf("\n");
	}
}

/* Determine if this is a valid packet that we care about */
int get_packet_type(struct ip *ip, struct tcphdr *tcp, struct icmp *icmp)
{
	/* In English:  "SYN packet that we sent out" */
	if (ip->ip_dst.s_addr == dest_ip && ip->ip_p == IPPROTO_TCP && tcp_flag_isset(tcp, TH_SYN)) {
		return SYN_FROM_US;
	}

	/* In English:  "Response packet we're interested in, from the other host" */
	else if (ip->ip_src.s_addr == dest_ip && ip->ip_p == IPPROTO_TCP &&
			(
				(tcp_flag_isset(tcp, TH_SYN) && tcp_flag_isset(tcp, TH_ACK)) || 
				tcp_flag_isset(tcp, TH_RST)
			)
		) {
			return SYNACK_FROM_THEM;
	}

	/* In English: "Response packet we're interested in, but it's a Time Exceeded from some other host */
	else if (ip->ip_dst.s_addr == src_ip.s_addr && ip->ip_p == IPPROTO_ICMP && icmp->icmp_type == ICMP_TIMXCEED) {
		return ICMP_TIMEEXCEEDED;
	}

	return 0;
}

/* callback to pcap_loop() */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	int r, i;
	int seqno, packetno;
	struct ip *ip = NULL;
	struct tcphdr *tcp = NULL;
	struct icmp *icmp = NULL;
	float ms;
	char *units = "ms";
	char *flags;
	struct timeval tv_synack;
	struct timeval *tv_syn;

	int frame_offset = 0;
	int size_ip = sizeof(struct ip);
	int size_tcp = sizeof(struct tcphdr);
	int packet_type = 0;

	/* It looks like there's a "feature" somewhere where you don't
	 * necessarily get Ethernet headers, or can't count on the underlying device to
	 * give you anything consistent (or anything at all).  For example, a Mac OS X
	 * loopback will give you 4 bytes of header.  Loopback on Linux won't give you
	 * any frame headers.  Internet on some will give you Ethernet, but not
	 * necessarily.  I kicked around some solutions (none worked great).  The best
	 * was to simply iterate and move the header around and determine if any of the
	 * moves make this a packet I care about.  If so, parse it like that.  If not,
	 * move on.  This seems "good enough" to work in virtually all cases with few
	 * false positives. */
	for (frame_offset = 0; (frame_offset + size_ip + size_tcp) <= header->caplen; ++frame_offset) {
		ip = (struct ip*)(packet + frame_offset);
		tcp = (struct tcphdr*)(packet + frame_offset + size_ip);
		icmp = (struct icmp*)(packet + frame_offset + size_ip);

		packet_type = get_packet_type(ip, tcp, icmp);
		if (packet_type != UNINTERESTING) {
			break;
		}
	}

	if (verbose) {
		show_packet(ip, ip->ip_p == IPPROTO_TCP ? tcp : NULL, header, packet);
		printf("\tSeen flags: ");
		for (i = 0; i < 32; ++i) {
			printf("%d", (seen_response_bitflags >> i) & 1);
		}
		printf("\n");
	}

	if (packet_type == UNINTERESTING) {
		if (verbose > 1) {
			printf("\tHeader probing didn't find a valid packet, dropping...\n");
			return;
		}
	}

	/* SYN packet that we sent out? */
	if (packet_type == SYN_FROM_US) {
		/* Store the send time of the packet */

		seqno = ntohl(tcp->th_seq);
		packetno = tcpseq_to_orderseq(ntohl(tcp->th_seq));
		memcpy(&(sent_times[packetno % PACKET_HISTORY]), &(header->ts), sizeof(struct timeval));

		total_syns++;
	}

	/* SYN/ACK returned from them? */
	else if (packet_type == SYNACK_FROM_THEM) {
		r = gettimeofday(&tv_synack, NULL);
		if (r < 0) {
			perror("gettimeofday");
			exit(1);
		}

		/* Clear some of the rolling buffer.  This isn't perfect, but
 		 * it's not bad. */
		set_seenflag(ntohl(tcp->th_ack) + 1800, 0);
		set_seenflag(ntohl(tcp->th_ack) + 1700, 0);
		set_seenflag(ntohl(tcp->th_ack) + 1600, 0);
		set_seenflag(ntohl(tcp->th_ack) + 1500, 0);

		/* If we've seen this particular packet, back out of the room slowly
		 * and close the door */
		if ((ip->ip_p == IPPROTO_TCP) && get_seenflag(ntohl(tcp->th_ack))) {
			if (verbose) {
				printf("Ignored packet; already seen one with seq=%d\n", 
					tcpseq_to_orderseq(ntohl(tcp->th_ack) - 1));
			}

			return;
		}

		/* Mark that we saw this packet */
		set_seenflag(ntohl(tcp->th_ack), 1);

		/* Figure out when this particular packet was sent */
		seqno = tcpseq_to_orderseq(ntohl(tcp->th_ack) - 1);
		tv_syn = &(sent_times[seqno % PACKET_HISTORY]);
		ms = (tv_synack.tv_sec - tv_syn->tv_sec) * 1000;
		ms += (tv_synack.tv_usec - tv_syn->tv_usec)*1.0/1000;

		/* Do some analysis on the returned packet... */
		if (ms > 1000) {
			units = "s";
			ms /= 1000;
		}

		if (tcp_flag_isset(tcp, TH_SYN)) {
			flags = "SYN/ACK";
			total_synacks++;
		}

		else {
			flags = "RST";
			total_rsts++;
		}

		/* Raise the flag to the user that we saw it... */
		printf("%s from %s: seq=%u ttl=%d time=%.3f%s\n", 
			flags,
			inet_ntoa(ip->ip_src), 
			tcpseq_to_orderseq(ntohl(tcp->th_ack) - 1),
			ip->ip_ttl,
			ms, units
		);

		if (ms < min_ping || min_ping == -1) {
			min_ping = ms;
		}

		if (ms > max_ping) {
			max_ping = ms;
		}
		
		avg_ping = ((avg_ping * successful_pings) + ms)/(successful_pings+1);
		successful_pings++;

		/* tell parent to continue */
		write(notify_fd, "foo", 3);

	}

	/* In English: "Response packet we're interested in, but it's a Time Exceeded from some other host */
	else if (packet_type == ICMP_TIMEEXCEEDED) {

		struct ip *retip;
		struct tcphdr *rettcp;

		retip = (struct ip*)(packet + frame_offset + size_ip + 8);
		rettcp = (struct tcphdr *)(packet + frame_offset + size_ip + 8 + size_ip);

		/* After we build the headers for ICMP, check the hosts / protocol / etc. */
		if (retip->ip_dst.s_addr == dest_ip && retip->ip_p == IPPROTO_TCP && 
			tcp_flag_isset(rettcp, TH_SYN)) {

			r = gettimeofday(&tv_timxceed, NULL);
			if (r < 0) {
				perror("gettimeofday");
				exit(1);
			}
			/* Figure out when this particular packet was sent */
			seqno = tcpseq_to_orderseq(ntohl(tcp->th_ack) - 1);
			tv_syn = &(sent_times[seqno % PACKET_HISTORY]);
			ms = (tv_synack.tv_sec - tv_syn->tv_sec) * 1000;
			ms += (tv_synack.tv_usec - tv_syn->tv_usec)*1.0/1000;

			if (ms > 1000) {
				units = "s";
				ms /= 1000;
			}

			/* Extracting the sequence number would be unreliable as only
			 * 64 bits of the TCP header are required to be present. */
			printf("Time to live exceeded from %s: ttl=%d time=%.3f%s\n",
				   inet_ntoa(ip->ip_src),
				   ip->ip_ttl,
				   ms, units
			);

			/* tell parent to continue */
			write(notify_fd, "foo", 3);
		}
	}
}

void sniff_packets(char *device_name)
{
	 int r;
	 pcap_t *handle;
	 char errbuf[PCAP_ERRBUF_SIZE];
	 char filter_expression[1024];
	 struct bpf_program filter;
	 bpf_u_int32 mask;
	 bpf_u_int32 net;

	 r = pcap_lookupnet(device_name, &net, &mask, errbuf);
	 if (r < 0) {
		 fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
		 exit(1);
	 }
	 
	 handle = pcap_open_live(device_name, BUFSIZ, 0, 0, errbuf);
	 if (!handle) {
		 fprintf(stderr, "pcap_open_live: %s\n", errbuf);
		 exit(1);
	 }

	 /* set non-blocking */
#ifdef BIOCIMMEDIATE
	 r = 1;
	 ioctl(pcap_fileno(handle), BIOCIMMEDIATE, &r);
#else
	 r = pcap_setnonblock(handle, 1, errbuf);
#endif
	if (r < 0) {
		fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
		exit(1);
	}

	 /* compile and apply the filter_expression */
	snprintf(filter_expression, sizeof(filter_expression), 
		"(host %s and port %u) or icmp[icmptype] == icmp-timxceed",
		inet_ntoa2(dest_ip), dest_port
	);

	if (verbose) {
		printf("pcap filter expression: %s\n", filter_expression);
	}

	r = pcap_compile(handle, &filter, filter_expression, 0, mask);
	if (r < 0) {
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
		exit(1);
	}

	r = pcap_setfilter(handle, &filter);
	if (r < 0) {
		fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
		exit(1);
	}

	/* wake up parent, we're ready */
	write(notify_fd, "foo", 3);

	/* begin sniffing */
	r = pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);
}

/*
 * Find a device name given an IPv4 dotted-quad
 * Could be made to work with IPv6 without much effort
 * It doesn't matter right now, but this uses inet_ntoa, which isn't
 * re-entrant.  So, don't start with the threading.  I doubt this is the only
 * thing here that isn't thread-safe, but there ya go.
 *
 * Will allocate memory for the return device name, so be sure to free it
 */
char* find_device(char *dq)
{
	/* Get all of the if headers... */
	int errs = 0;
	unsigned short family = 0;
	struct ifaddrs* alladdrs = NULL;
	struct ifaddrs* currentaddr = NULL;
	struct sockaddr_in *iaddr = NULL;
	char *test_dq = NULL;
	char *found_name = NULL;

	errs = getifaddrs(&alladdrs);
	if (errs != 0) {
		return NULL;
	}

	/*
	 * Loop through the returned device-families
	 * (unit of iteration is device-family, so you can get a device many times)
	 */
	for (currentaddr = alladdrs; currentaddr != NULL; currentaddr = currentaddr -> ifa_next) {
		if (currentaddr->ifa_addr == NULL) continue;

		family = currentaddr->ifa_addr->sa_family;
		if (family == AF_INET) {
			iaddr = (struct sockaddr_in *)currentaddr->ifa_addr;
			test_dq = inet_ntoa(iaddr->sin_addr);
			if (strncmp(dq, test_dq, strlen(test_dq)) == 0) {
				found_name = strdup(currentaddr->ifa_name);
				break;
			}
		}
	}

	freeifaddrs(alladdrs);
	return found_name;
}

/*
 * Given a destination, will return the source IP on the system used to route
 * there.  Makes use of non-reentrant functions.  Initializes the memory used
 * in the return variable, so you'll want to free it later.
 */
char *find_source_ip(char *dq)
{
	char *source_dq;

	/* Basically you just make the OS do it with a dummy socket... */
	int test_fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in dest, source;
	socklen_t socket_length = sizeof(source);

	/* Build the destination... */
	bzero(&dest, sizeof(struct sockaddr_in));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(2942);	/* "random" port */
	if (inet_pton(AF_INET, dq, &(dest.sin_addr)) != 1) return NULL;

	/* Try to "connect" to the UDP socket and retrieve the source socket... */
	if(connect(test_fd, (struct sockaddr *)&dest, sizeof(dest)) != 0) return NULL;
	if(getsockname(test_fd, (struct sockaddr *)&source, &socket_length) != 0) return NULL;
	close(test_fd);

	/* ... and convert that source socket to a dotted-quad */
	source_dq = strdup(inet_ntoa(source.sin_addr));
	return source_dq;
}


void inject_syn_packet(int sequence)
{
	int c;
	int r;
	u_short s = src_port ? src_port : random() % 65536;

	/* Build the custom TCP header.  We have a weird hack here:
	 * We use the sequence number to define the packet order
	 */

	struct timeval tv;
	r = gettimeofday(&tv, NULL);
	if (r < 0) {
		perror("gettimeofday");
		exit(1);
	}

	r = libnet_build_tcp(
		s,                                                /* source port */
		dest_port,                                        /* destination port */
		sequence_offset + (sequence*100),                 /* sequence number */
		0,                                                /* acknowledgement num */
		TH_SYN,                                           /* control flags */
		32768,                                            /* window size */
		0,                                                /* checksum */
		0,                                                /* urgent pointer */
		LIBNET_TCP_H,                                     /* TCP packet size */
		NULL,                                             /* payload */
		0,                                                /* payload size */
		l,                                                /* libnet handle */
		tcp_pkt                                           /* libnet packet ref */
	);

	if (r == -1) {
		fprintf(stderr, "libnet_build_tcp: %s\n", libnet_geterror(l));
		exit(1);
	}

	/* custom IP header; I couldn't get autobuild_ipv4 to work */
	r = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_TCP_H,                /* packet length */
		0,                                           /* tos */
		htons((l->ptag_state) & 0x0000ffff),         /* IP id */
		0,                                           /* fragmentation */
		ttl,                                         /* TTL */
		IPPROTO_TCP,                                 /* encap protocol */
		0,                                           /* checksum */
		src_ip.s_addr,                               /* source IP */
		dest_ip,                                     /* destination IP */
		NULL,                                        /* payload */
		0,                                           /* payload size */
		l,                                           /* libnet pointer */
		ip_pkt                                       /* libnet packet ref */
	);

	if (r == -1) {
		fprintf(stderr, "libnet_autobuild_ipv4: %s\n", libnet_geterror(l));
		exit(1);
	}

	/* send it */
	c = libnet_write(l);
	if (c == -1) {
		fprintf(stderr, "libnet_write: %s\n", libnet_geterror(l));
		exit(1);
	}

	/* Get ready for the next packet */
	libnet_clear_packet(l);
}

void usage()
{
	fprintf(stderr, "%s: [-v] [-c count] [-p destport] [-i interval] [-I interface] [-t ttl] [-S srcaddress] [-P srcport] remote_host\n", myname);
	exit(0);
}

int main(int argc, char *argv[])
{
	/* Create a safe environment for setuid safety */
	sanitize_environment();

	int r;
	int c;
	char *device_name = NULL;
	int count = -1;
	long interval = 1000;
	struct hostent *he;
	int pipefds[2];
	char junk[256];
	int sequence = 1;
	char *src_quad = NULL;

	myname = argv[0];
	char *dest_quad = NULL;
	char *dest_host = NULL;

	bzero(&src_ip, sizeof(struct in_addr));

	while ((c = getopt(argc, argv, "c:p:i:vI:t:S:P:h")) != -1) {
		switch (c) {
			case 'c':
				count = atoi(optarg);
				break;
			case 'p':
				dest_port = atoi(optarg);
				break;
			case 'i':
				interval = (long)(atof(optarg) * 1000.0);
				if (interval <= 0) {
					fprintf(stderr, "Invalid interval\n");
					exit(1);
				}
				break;
			case 'I':
				device_name = optarg;
				if (check_device_name(device_name) == 0) {
					fprintf(stderr, "Invalid capture device\n");
					exit(1);
				}
				break;
			case 'v':
				++verbose;
				break;
			case 't':
				ttl = atoi(optarg);
				if (ttl < 1 || ttl > 255) {
					fprintf(stderr, "Invalid TTL\n");
				}
				break;
			case 'S':
				src_quad = optarg;
				if (inet_aton(src_quad, &src_ip) == 0) {
					fprintf(stderr, "Invalid source address\n");
				}
				break;
			case 'P':
				src_port = atoi(optarg);
				break;
			case 'h':
			default:
				usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
	}

	if (geteuid() != 0) {
		fprintf(stderr, "You must run %s as root.\n", myname);
		exit(1);
	}

	dest_host = argv[0];
	he = gethostbyname(dest_host);
	if (!he) {
		herror("gethostbyname");
		exit(1);
	}

	if (!he->h_addr) {
		fprintf(stderr, "No address associated with name: %s\n", argv[0]);
		exit(1);
	}

	bcopy(he->h_addr, &dest_ip, sizeof(dest_ip));
	if (dest_ip == INADDR_NONE) {
		perror("bad address");
		exit(1);
	}

	/* Get the dotted-quad from the resolved address as we need it later */
	struct in_addr dest_addr;
	bzero(&dest_addr, sizeof(struct in_addr));
	dest_addr.s_addr = dest_ip;
	dest_quad = inet_ntoa(dest_addr);
	if (dest_quad == NULL) {
		perror("Unable to convert returned address to dotted-quad; try pinging by IP address");
		exit(1);
	}
	dest_quad = strdup(dest_quad);

	/* Figure out the source IP if we didn't specify one */
	if (src_ip.s_addr == 0) {
		src_quad = find_source_ip(dest_quad);
		if (src_quad == NULL) {
			fprintf(stderr, "Unable to calculate source IP for tcp pings (needed for device capture).  Try specifying a source IP address with -S\n");
			exit(1);
		}

		if (inet_aton(src_quad, &src_ip) == 0) {
			fprintf(stderr, "Unable to compute source IP from calculated source dotted quad: %s\n", src_quad);
			exit(1);
		}
	}

	/* Figure out the source device name if we didn't specify one */
	if (device_name == NULL) {
		device_name = find_device(src_quad);
		if (device_name == NULL) {
			fprintf(stderr, "Unable to calculate if device from source IP (%s).  Is the source IP you specified bound to a device?\n", src_quad);
			exit(1);
		}
	}

	/* set up the libnet pointer and stack */
	char errbuf[LIBNET_ERRBUF_SIZE];

	l = libnet_init(LIBNET_RAW4, device_name, errbuf);
	if (l == NULL) {
		fprintf(stderr, "libnet_init: %s", errbuf);
		exit(1); 
	}

	dest_name = he->h_name;
	printf("TCP PING %s (%s:%u)\n", dest_name, 
		   dest_quad, dest_port
	);

	/* start seq# somewhere random so we're not SO obvious */
	srandom(time(NULL));
	sequence_offset = random();

	/* pipe is to synchronize with our child */
	r = pipe(pipefds);
	if (r < 0) {
		perror("pipe");
		exit(1);
	}

	r = fcntl(pipefds[0], F_SETFL, O_NONBLOCK);
	if (r < 0) {
		perror("fcntl (nonblock)");
		exit(1);
	}

	child_pid = fork();
	if (child_pid < 0) {
		perror("fork");
		exit(1);
	}

	/* The parent is to send packets until an alarm, cnt, or Ctrl+C */
	if (child_pid) {
		close(pipefds[1]);

		/* wait for child sniffer to be ready */
		for (;;) {
			r = read(pipefds[0], junk, sizeof(junk));
			if (r > 0) {
				break;
			}

			msleep(200);
		}

		signal(SIGINT, handle_sigint);

		/* Event loop: either send, or whatever */
		for (;;) {
			inject_syn_packet(sequence++);
			msleep(interval);

			/* See if we sent too many packets */
			if (--count == 0) {
				/* tell child to display stats */
				kill(child_pid, SIGINT);
				/* make sure we wait until it died and closed */
				kill(getpid(), SIGINT);
				break;
			}

			/* If we got here, we got a different errval than a non-block.  Fail out */
			r = read(pipefds[0], junk, sizeof(junk));
			if (r == -1 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
				/* child died */
				fprintf(stderr, "child exited.\n");
				exit(1);
			}
		}
	}

	/* The child is to receive packets until terminated by the parent */
	else {
		close(pipefds[0]);
		notify_fd = pipefds[1];
		signal(SIGINT, print_stats);

		sniff_packets(device_name);

		free(device_name);
	}

	return(0);
}
