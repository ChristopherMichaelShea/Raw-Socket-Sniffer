#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#define MAX_PACKET_LEN 2048
#define MAX_FLOWS 1000

struct Flow
{
    char source_ip_address[16];
    char dest_ip_address[16];
    uint16_t source_port;
    uint16_t dest_port;
    uint8_t ip_protocol;
    int packet_count;
};

struct Flow flows[MAX_FLOWS];
int number_of_unique_flows = 0;

void PrintFlows()
{
    printf("Flow List:\n");
    if (number_of_unique_flows == 0)
    {
        return;
    }
    for (int i = 0; i < number_of_unique_flows; i++)
    {
        printf("%s:%d <-> %s:%d %d => %d\n", flows[i].source_ip_address, flows[i].source_port, flows[i].dest_ip_address, flows[i].dest_port, flows[i].ip_protocol, flows[i].packet_count);
    }
}

void SignalHandler(int signo)
{
    PrintFlows();
    alarm(10);
}

int CreateRawSocket()
{
    int rawsock;
    if ((rawsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1)
    {
        perror("Error creating raw socket: ");
        exit(-1);
    }
    return rawsock;
}

int BindRawSocketToInterface(char *interface, int rawsock, int protocol)
{
    struct sockaddr_ll sll;
    struct ifreq ifr;

    bzero(&sll, sizeof(sll));
    bzero(&ifr, sizeof(ifr));

    /* First Get the Interface Index */
    if (strlen(interface) >= IFNAMSIZ)
    {
        fprintf(stderr, "Interface name is too long\n");
        close(rawsock);
        return -1;
    }

    strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);
    if ((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
    {
        perror("Error getting Interface index");
        close(rawsock);
        return -1;
    }
    /* Bind our raw socket to this interface */

    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(protocol);
    if ((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll))) == -1)
    {
        perror("Error binding raw socket to interface");
        close(rawsock);
        return -1;
    }
    return 1;
}

void UpdateFlowList(struct Flow current_flow)
{
    int matching_flow_found = 0;
    for (int i = 0; i < number_of_unique_flows; i++)
    {
        if (strcmp(flows[i].source_ip_address, current_flow.source_ip_address) == 0 &&
            strcmp(flows[i].dest_ip_address, current_flow.dest_ip_address) == 0 &&
            flows[i].source_port == current_flow.source_port &&
            flows[i].dest_port == current_flow.dest_port &&
            flows[i].ip_protocol == current_flow.ip_protocol)
        {
            flows[i].packet_count++;
            matching_flow_found = 1;
            break;
        }
    }

    if (!matching_flow_found)
    {
        if (number_of_unique_flows < MAX_FLOWS)
        {
            strncpy(flows[number_of_unique_flows].source_ip_address, current_flow.source_ip_address, 16);
            strncpy(flows[number_of_unique_flows].dest_ip_address, current_flow.dest_ip_address, 16);
            flows[number_of_unique_flows].source_port = current_flow.source_port;
            flows[number_of_unique_flows].dest_port = current_flow.dest_port;
            flows[number_of_unique_flows].ip_protocol = current_flow.ip_protocol;
            flows[number_of_unique_flows].packet_count = 1;
            number_of_unique_flows++;
        }
        else
        {
            fprintf(stderr, "Max flow limit reached. Ignoring new flows.\n");
        }
    }
}

void ParsePacketHeader(unsigned char *packet, int packet_length)
{
    struct ethhdr *ethernet_header;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    struct in_addr dest_ip_address;
    struct in_addr source_ip_address;

    if (packet_length < (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
    {
        fprintf(stderr, "TCP Header not present\n");
        return;
    }

    ethernet_header = (struct ethhdr *)packet;

    if (ntohs(ethernet_header->h_proto) != ETH_P_IP)
    {
        fprintf(stderr, "Not an IP packet\n");
        return;
    }

    ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

    dest_ip_address.s_addr = ip_header->daddr;
    source_ip_address.s_addr = ip_header->saddr;

    struct Flow current_flow;

    strcpy(current_flow.source_ip_address, inet_ntoa(source_ip_address));
    strcpy(current_flow.dest_ip_address, inet_ntoa(dest_ip_address));

    current_flow.ip_protocol = ip_header->protocol;

    if (current_flow.ip_protocol == IPPROTO_TCP)
    {
        tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header->ihl + 4);

        current_flow.source_port = ntohs(tcp_header->source);
        current_flow.dest_port = ntohs(tcp_header->dest);
    }
    else if (current_flow.ip_protocol == IPPROTO_UDP)
    {
        udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);

        current_flow.source_port = ntohs(udp_header->source);
        current_flow.dest_port = ntohs(udp_header->dest);
    }
    else
    {
        fprintf(stderr, "Not a TCP or UDP packet\n");
    }

    UpdateFlowList(current_flow);
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("Invalid number of arguments\n"
               "Usage: %s <interface>\n",
               argv[0]);
        return 1;
    }

    unsigned char packet[MAX_PACKET_LEN];
    int packet_len;
    struct sockaddr_ll socket_address;
    int socket_address_size = sizeof(socket_address);

    int raw_socket = CreateRawSocket();
    if (BindRawSocketToInterface(argv[1], raw_socket, ETH_P_IP) == -1)
    {
        fprintf(stderr, "Error binding raw socket to interface. Exiting.\n");
        close(raw_socket);
        return 1;
    }

    signal(SIGALRM, SignalHandler);
    alarm(10);

    while (1)
    {
        if ((packet_len = recvfrom(raw_socket, packet, MAX_PACKET_LEN, 0, (struct sockaddr *)&socket_address, &socket_address_size)) == -1)
        {
            perror("Recv from returned -1: ");
            exit(-1);
        }
        else
        {
            ParsePacketHeader(packet, packet_len);
        }
    }
    close(raw_socket);
    return 0;
}
