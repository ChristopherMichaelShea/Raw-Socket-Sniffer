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

/* Global variables for use with signal*/
struct Flow flows[MAX_FLOWS];
int number_of_unique_flows = 0;
int terminate_program = 0;

void PrintFlows()
{
    printf("Flow List:\n");
    if (number_of_unique_flows == 0)
    {
        return;
    }
    for (int i = 0; i < number_of_unique_flows; i++)
    {
        if (flows[i].ip_protocol == IPPROTO_UDP || flows[i].ip_protocol == IPPROTO_TCP)
        {
            printf("%s:%d <-> %s:%d %d => %d\n", flows[i].source_ip_address, flows[i].source_port, flows[i].dest_ip_address, flows[i].dest_port, flows[i].ip_protocol, flows[i].packet_count);
        }
        else
        {
            printf("%s <-> %s %d => %d\n", flows[i].source_ip_address, flows[i].dest_ip_address, flows[i].ip_protocol, flows[i].packet_count);
        }
    }
}

void SignalHandler(int signo)
{
    if (signo == SIGALRM)
    {
        PrintFlows();
        alarm(10);
    }
    /* Exits main while-loop on termination to allow for resource clean up (close socket)*/
    else if (signo == SIGINT || signo == SIGTERM)
    {
        terminate_program = 1;
    }
}

int CreateRawSocket()
{
    int raw_socket;

    /* PF_Packet to access OSI Layer 2*/
    /* ETH_P_IP to allow only IPv4 packets*/
    if ((raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1)
    {
        perror("Error creating raw socket");
        close(raw_socket);
        exit(-1);
    }
    return raw_socket;
}

int BindRawSocketToInterface(char *interface, int raw_socket, int protocol)
{
    struct sockaddr_ll socket_address;
    struct ifreq interface_request;

    /* Ensures that the structures are initially empty before populating*/
    bzero(&socket_address, sizeof(socket_address));
    bzero(&interface_request, sizeof(interface_request));

    /* Validate interface*/
    strncpy((char *)interface_request.ifr_name, interface, IFNAMSIZ);
    if ((ioctl(raw_socket, SIOCGIFINDEX, &interface_request)) == -1)
    {
        perror("Error getting interface index");
        close(raw_socket);
        return -1;
    }

    socket_address.sll_family = AF_PACKET;
    socket_address.sll_ifindex = interface_request.ifr_ifindex;
    socket_address.sll_protocol = htons(protocol);

    /* Bind raw socket to interface*/
    if ((bind(raw_socket, (struct sockaddr *)&socket_address, sizeof(socket_address))) == -1)
    {
        perror("Error binding raw socket to interface");
        close(raw_socket);
        return -1;
    }
    return 1;
}

void UpdateFlowList(struct Flow current_flow)
{
    /* Increments count on matching flows*/
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

    /* Adds new flow if no matching flow is found*/
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
            fprintf(stderr, "Max flow limit reached.\n");
            terminate_program = 1;
        }
    }
}

void ParsePacketHeader(unsigned char *packet, int packet_length)
{
    struct ethhdr *ethernet_header;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    if (packet_length < (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
    {
        fprintf(stderr, "IP protocol header not present\n");
        return;
    }

    ethernet_header = (struct ethhdr *)packet;

    if (ntohs(ethernet_header->h_proto) != ETH_P_IP)
    {
        fprintf(stderr, "Not an IPv4 packet\n");
        return;
    }

    struct Flow current_flow;
    struct in_addr dest_ip_address;
    struct in_addr source_ip_address;

    ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

    dest_ip_address.s_addr = ip_header->daddr;
    source_ip_address.s_addr = ip_header->saddr;

    strcpy(current_flow.source_ip_address, inet_ntoa(source_ip_address));
    strcpy(current_flow.dest_ip_address, inet_ntoa(dest_ip_address));

    current_flow.ip_protocol = ip_header->protocol;

    if (current_flow.ip_protocol == IPPROTO_TCP)
    {
        tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);

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
        current_flow.source_port = 0;
        current_flow.dest_port = 0;
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
    else if (strlen(argv[1]) >= IFNAMSIZ)
    {
        fprintf(stderr, "Interface name is too long\n");
        return -1;
    }

    unsigned char packet[MAX_PACKET_LEN];
    int packet_len;
    struct sockaddr_ll socket_address;
    int socket_address_size = sizeof(socket_address);

    int raw_socket = CreateRawSocket();
    if (BindRawSocketToInterface(argv[1], raw_socket, ETH_P_IP) == -1)
    {
        fprintf(stderr, "Error binding raw socket to interface.\n");
        close(raw_socket);
        return 1;
    }

    signal(SIGALRM, SignalHandler);
    signal(SIGINT, SignalHandler); // Handle Ctrl+C (SIGINT)
    signal(SIGTERM, SignalHandler);
    alarm(10);

    while (!terminate_program)
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
