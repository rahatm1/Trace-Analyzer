/* Modified From: http://inst.eecs.berkeley.edu/~ee122/fa07/projects/p2files/packet_parser.c*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pcap.h>
#include <limits.h>
#include <stdbool.h>
#include <math.h>
#include <sys/types.h>
#include "util.h"
int hopCnt = 0;

#define BUFFER_SIZE 120
#define HOP_SIZE 64
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
pcap_t* build_filter(char* fileName, char *errbuf, struct bpf_program *fp, char *filter_exp);
double calcAvgRTT(struct timeval starttime[], struct timeval endtime, int length);
double calcDeviation(struct timeval starttime[], struct timeval endtime, int length, double average);
short getPort(const unsigned char *packet);

/* Break down a TCP packet and extract relevant Information */
void process_TCP(const unsigned char *packet, struct timeval ts,
			unsigned int capture_len, struct ip **ip)
{
	unsigned int IP_header_length;

	/* For simplicity, we assume Ethernet encapsulation. */
	if (capture_len < sizeof(struct ether_header))
	{
		/* We didn't even capture a full Ethernet header, so we
		 * can't analyze this any further.
		 */
		too_short(ts, "Ethernet header");
		return;
	}

	/* Skip over the Ethernet header. */
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);

	if (capture_len < sizeof(struct ip))
	{
		/* Didn't capture a full IP header */
		too_short(ts, "IP header");
		return;
	}

	*ip = (struct ip*) packet;
	IP_header_length = (*ip)->ip_hl * 4;	/* ip_hl is in 4-byte words */

	if (capture_len < IP_header_length)
	{
		/* didn't capture the full IP header including options */
		too_short(ts, "IP header with options");
		return;
	}

    char *src_addr = malloc(BUFFER_SIZE);
    strcpy(src_addr, inet_ntoa((*ip)->ip_src));

    char *dst_addr = malloc(BUFFER_SIZE);
    strcpy(dst_addr, inet_ntoa((*ip)->ip_dst));
}

bool isUnique(char *tmp, char **hops)
{
    for (int i = 0; i < hopCnt; i++) {
        if (strcmp(tmp, hops[i]) == 0)
        {
            return false;
        }
    }
    return true;
}


int main(int argc, char *argv[])
{
	pcap_t *pcap;
	struct bpf_program fp;		/* The compiled filter expression */
    const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;

	/* Skip over the program name. */
	++argv; --argc;

	/* We expect exactly one argument, the name of the file to dump. */
	if ( argc != 1 )
	{
		fprintf(stderr, "program requires one argument, the trace file\n");
		exit(1);
	}

    //Find a packet with TTL=1 to find src_node and dst_node
    char filter_exp[BUFFER_SIZE] = "icmp[icmptype] == icmp-echo or ip proto \\udp and not udp port 1900";	/* The filter expression */
    pcap = build_filter(argv[0], errbuf, &fp, filter_exp);

    struct ip *ip;
    char src_node[BUFFER_SIZE];
    char dst_node[BUFFER_SIZE];
    while ((packet = pcap_next(pcap, &header)) != NULL)
    {
        process_TCP(packet, header.ts, header.caplen, &ip);
        if (ip->ip_ttl == 1)
        {
            strcpy(src_node, inet_ntoa(ip->ip_src));
            strcpy(dst_node, inet_ntoa(ip->ip_dst));
            break;
        }
    }

    printf("The IP address of the source node: %s\n", src_node);
    printf("The IP address of ultimate destination node: %s\n", dst_node);

    //Search for packets with ICMP time exceeded
    char icmp_template[] = "icmp[icmptype] == icmp-timxceed and dst host %s";
    sprintf(filter_exp, icmp_template, src_node);
    pcap = build_filter(argv[0], errbuf, &fp, filter_exp);

    //Hops Array
    char **hops = (char **) malloc(HOP_SIZE * sizeof(char *));
	while ((packet = pcap_next(pcap, &header)) != NULL)
    {
        process_TCP(packet, header.ts, header.caplen, &ip);

        char *tmp = malloc(BUFFER_SIZE);
        strcpy(tmp, inet_ntoa(ip->ip_src));
        if (isUnique(tmp, hops))
        {
            hops[hopCnt] = tmp;
            hopCnt++;
        }
    }

    printf("The IP addresses of the intermediate destination nodes:\n");
    for (int i = 0; i<hopCnt; i++) {
        printf("\troute %d: %s\n", i+1, hops[i]);
    }
    printf("\n");

    //Save all protocol headers to boolean array
    strcpy(filter_exp, "icmp[icmptype] == icmp-echo or ip proto \\udp and not udp port 1900");	/* The filter expression */
    pcap = build_filter(argv[0], errbuf, &fp, filter_exp);

    bool protocol_header[256] = {0};
    while ((packet = pcap_next(pcap, &header)) != NULL)
    {
        process_TCP(packet, header.ts, header.caplen, &ip);
        protocol_header[ip->ip_p] = true;
    }

    bool windows = false;
    printf("The values in the protocol field of IP headers:\n");
    for (int i = 0; i < 256; i++) {
        if ((i == 1) && (protocol_header[i])) {
            printf("\t1: ICMP\n");
            windows = true;
        }
        else if ((i == 17) && (protocol_header[i])) printf("\t17: UDP\n");
        else if (protocol_header[i]) printf("\t%d:\n", i);
    }
    printf("\n");

    //Get Fragments and offset
    char filter_template[] = "src host %s and dst host %s";
    sprintf(filter_exp, filter_template, src_node, dst_node);
    pcap = build_filter(argv[0], errbuf, &fp, filter_exp);

    int numFragment = 0;
    int lastFragOffset = 0;
    while ((packet = pcap_next(pcap, &header)) != NULL)
    {
        process_TCP(packet, header.ts, header.caplen, &ip);
        if ((ntohs(ip->ip_off) & IP_MF))
        {
            numFragment++;
        }
        else
        {
            lastFragOffset = (ntohs(ip->ip_off) & IP_OFFMASK) * 8;
            break;
        }
    }

    printf("The number of fragments created from the original datagram is: %d\n", numFragment);
    printf("The offset of the last fragment is: %d\n", lastFragOffset);
    printf("\n");


    //Calculate RTT here
    struct timeval starttime[numFragment+1];
    struct timeval endtime;
    char *cur_addr = malloc(BUFFER_SIZE);
    for (int hop = 0; hop <= hopCnt; hop++) {
        int x = 0;
        unsigned short port = 0;
        short cur_icmp_id = 0;
        short cur_icmp_seq = 0;
        //Match ICMP/UDP request send with TTL=X
        if (windows)
        {
            strcpy(filter_exp, "icmp[icmptype] == icmp-echo");	/* The filter expression */
        }
        else
        {
            strcpy(filter_exp, "ip proto \\udp and not udp port 1900");
        }
        pcap = build_filter(argv[0], errbuf, &fp, filter_exp);

        while ((packet = pcap_next(pcap, &header)) != NULL)
        {
            process_TCP(packet, header.ts, header.caplen, &ip);
            if (ip->ip_ttl == hop+1)
            {
                starttime[x] = header.ts;
                x++;
                packet += sizeof(struct ether_header);
                if (windows)
                {
                    packet += ip->ip_hl * 4;
                    struct icmp *temp_icmp = (struct icmp *) packet;
                    cur_icmp_id = ntohs(temp_icmp->icmp_id);
                    cur_icmp_seq = ntohs(temp_icmp->icmp_seq);
                }
                else
                {
                    //gets destination port
                    if (port == 0) port = getPort(packet);
                }
                if (x > numFragment) break;
            }
        }

        //Match ICMP response for this TTL with time exceeded
        char icmp_template[] = "icmp[icmptype] == icmp-timxceed and dst host %s";
        sprintf(filter_exp, icmp_template, src_node);

        //ultimate node
        if (hop == hopCnt)
        {
            char final_template[] = "(icmp[icmptype] == icmp-echoreply or icmp[icmptype] == icmp-unreach) and (src %s and dst %s)";
            sprintf(filter_exp, final_template, dst_node, src_node);
        }

        pcap = build_filter(argv[0], errbuf, &fp, filter_exp);

        while ((packet = pcap_next(pcap, &header)) != NULL)
        {
            process_TCP(packet, header.ts, header.caplen, &ip);
            packet += sizeof(struct ether_header);
            if (windows)
            {
                packet += ip->ip_hl * 4;
                if (hop != hopCnt) packet += sizeof(struct icmp);
                struct icmp *temp_icmp = (struct icmp *) packet;
                if ((ntohs(temp_icmp->icmp_id) == cur_icmp_id) &&
                    (ntohs(temp_icmp->icmp_seq) == cur_icmp_seq))
                    {
                        strcpy(cur_addr, inet_ntoa(ip->ip_src));
                        endtime = header.ts;
                        break;
                    }
            }
            else
            {
                packet += sizeof(struct icmp);
                if (port == (unsigned short) getPort(packet))
                {
                    strcpy(cur_addr, inet_ntoa(ip->ip_src));
                    endtime = header.ts;
                    break;
                }
            }
        }

        if ((endtime.tv_sec == 0) && (endtime.tv_usec == 0))
        {
            continue;
        }

        double avg_time = calcAvgRTT(starttime, endtime, numFragment+1);
        double std_dev = calcDeviation(starttime, endtime, numFragment+1, avg_time);

        printf("The avg RTT between %s and %s is: %.2f ms, the s.d. is: %f ms\n", src_node, cur_addr, avg_time, std_dev);
        memset(&endtime, 0, sizeof(endtime));
    }
	// terminate
	return 0;
}

short getPort(const unsigned char *packet)
{
    unsigned int IP_header_length;
    struct ip *temp_ip = (struct ip *) packet;
    IP_header_length = temp_ip->ip_hl * 4;	/* ip_hl is in 4-byte words */
    packet += IP_header_length;
    struct udphdr *temp_udp = (struct udphdr *) packet;
    return htons(temp_udp->uh_dport);
}

double calcDeviation(struct timeval starttime[], struct timeval endtime, int length, double average)
{
    double time_difference;
    double squared_sum = 0;
    for (int i = 0; i < length; i++) {
        time_difference = getDuration(&starttime[i], &endtime);
        squared_sum += (time_difference-average) * (time_difference-average);
    }
    return sqrt(squared_sum/length);
}

double calcAvgRTT(struct timeval starttime[], struct timeval endtime, int length)
{
    double totalTime = 0;
    for (int i = 0; i < length; i++) {
        totalTime += getDuration(&starttime[i], &endtime);
    }
    return totalTime/length;
}

/* Opens file, compiles and sets filter provided by filter_exp */
pcap_t* build_filter(char* fileName, char *errbuf, struct bpf_program *fp, char *filter_exp)
{
    pcap_t *pcap;

    pcap = pcap_open_offline(fileName, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "error reading pcap file: %s\n", errbuf);
        exit(1);
    }

    if(pcap_compile(pcap, fp, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        exit(2);
    }

    if (pcap_setfilter(pcap, fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        exit(2);
    }
    return pcap;
}
