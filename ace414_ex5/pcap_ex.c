#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

typedef struct net_flow {
  char *src_ip;
  char *dst_ip;
  u_int src_p;
  u_int dst_p;
  char *protocol;

  struct net_flow *next;
} net_flow;

typedef struct tcp_packet {
  net_flow *flow;
  struct tcphdr *tcp;
  int payload;

  struct tcp_packet *next;
} tcp_packet;

void process_offline(char *, char *);
void process_live(char *, char *);
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_tcp_packet(const u_char *, int);
void print_udp_packet(const u_char *, int);

void insert_unique_transmission(net_flow *);
net_flow * make_netflow_node(char *, char *, u_int, u_int, u_int);
net_flow * insert_transmission(net_flow *, net_flow *);
int search_transmission(net_flow *, net_flow *);
int compare_netflows(net_flow *, net_flow *);

tcp_packet * make_tcp_node(net_flow *, struct tcphdr *, int);
tcp_packet * insert_tcp(tcp_packet *, tcp_packet *);
int check_retransmission(tcp_packet *, tcp_packet *);

void pcap_terminate(int);
void pcap_results();
void usage();

struct sockaddr_in source, dest;

pcap_t *handle;
net_flow *n_flows = NULL;
tcp_packet *tcp_packs = NULL;

int tcp_bytes = 0, udp_bytes = 0;
int tcp = 0, udp = 0, total = 0, others = 0;
int tcp_fl = 0, udp_fl = 0, total_fl = 0;

bool onFile;

/* 
 * Program's main function.
 */
int main(int argc, char **argv) {

  int opt;
  char *pcap_filename = NULL;
  char *interface = NULL;
  char *filter = NULL;

  remove("log.txt");

  while ((opt = getopt(argc, argv, "i:r:f:h")) != -1) {
    switch(opt) {
      case 'i':
        interface = strdup(optarg);
        process_live(interface, filter);
        break;
      case 'r':
        pcap_filename = strdup(optarg);
        process_offline(pcap_filename, filter);
        break;
      case 'f':
        filter = strdup(optarg);
        break;
      case 'h':
      default:
        usage();
    }
  }

  free(pcap_filename);

  return 0;
}

/* 
 * Processes a .pcap file and extracts information for each packet.
 */
void process_offline(char *pcap_file, char *filter) {

  struct bpf_program fp;
  bpf_u_int32 maskp;
  bpf_u_int32 netp; 
  char err[100];

  printf("Reading file %s for offline packet capturing...\n", pcap_file);
  handle = pcap_open_offline(pcap_file, err);

  if (!handle) {
    fprintf(stderr, "Couldn't open file %s: %s\n", pcap_file, err);
    exit(EXIT_FAILURE);
  }

  if(pcap_compile(handle, &fp, filter, 0, netp) == -1) {
    fprintf(stderr,"Error calling pcap_compile\n");
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr,"Error setting filter.\n");
    exit(EXIT_FAILURE);
  }

  onFile = false;
  pcap_loop(handle, -1, process_packet, NULL);

  pcap_results();
  pcap_close(handle);

  return;
}

/* 
 * Processes a live network interface and extracts information for each packet.
 */
void process_live(char *interface, char *filter) {

  pcap_if_t *alldevsp;
  struct bpf_program fp;
  bpf_u_int32 maskp;
  bpf_u_int32 netp; 
  char err[100];

  pcap_lookupnet(interface, &netp, &maskp, err);

  printf("Reading interface %s for live packet capturing...\n", interface);
  handle = pcap_open_live(interface, BUFSIZ, 0, 1000, err);

  if (!handle) {
    fprintf(stderr, "Couldn't read device %s: %s\n", interface, err);
    exit(EXIT_FAILURE);
  }

  if(pcap_compile(handle, &fp, filter, 0, netp) == -1) {
    fprintf(stderr, "Error calling pcap_compile\n");
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Error setting filter.\n");
    exit(EXIT_FAILURE);
  }

  onFile = true;
  signal(SIGINT, pcap_terminate);
  pcap_loop(handle, -1, process_packet, NULL);

  pcap_results();
  pcap_freecode(&fp);

  return;
}

/* 
 * Processes a packet at a time based on its protocol (TCP or UDP).
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
  
  int size = header->len;

  struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
  ++total;

  switch(iph->protocol) {
    // TCP protocols
    case 6:
      ++tcp;
      print_tcp_packet(buffer, size);
      break;
    // UDP protocols
    case 17:
      ++udp;
      print_udp_packet(buffer, size);
      break;
    // excluded protocols
    default:
      ++others;
      break;
  }
}

/* 
 * Prints TCP packet's information, and checks if it has been retransmited or not.
 */
void print_tcp_packet(const u_char *buffer, int len) {

  unsigned short iphdrlen;
  char * retr = "";

  struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
  iphdrlen = iph->ihl*4;

  memset(&source, 0, sizeof(source));
  source.sin_addr.s_addr = iph->saddr;
	
  memset(&dest, 0, sizeof(dest));
  dest.sin_addr.s_addr = iph->daddr;
  
  struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
  int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

  net_flow *trans = make_netflow_node(inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr), ntohs(tcph->source), ntohs(tcph->dest), iph->protocol);
  insert_unique_transmission(trans);

  tcp_packet *tcp = make_tcp_node(trans, tcph, len - header_size);
  tcp_packs = insert_tcp(tcp_packs, tcp);

  if (check_retransmission(tcp_packs->next, tcp)) {
    retr = "-Retransmitted-";
  }

  tcp_bytes += len;

  if (onFile) {
    FILE *f = fopen("log.txt", "a");

    if (f == NULL) {
        fprintf(stderr,"Error opening file.\n");
        exit(EXIT_FAILURE);
    }

    fprintf(f, "src IP address (port): %15s (%5u) | dst IP address (port): %15s (%5u) | Protocol: TCP | Header size: %5u [b] | Payload size: %5u [b] | Payload address: %15p | %s\n",
      inet_ntoa(source.sin_addr), ntohs(tcph->source), inet_ntoa(dest.sin_addr), ntohs(tcph->dest), header_size, len - header_size, buffer + header_size, retr
    );

    fclose(f);
  }
  else {
    printf("src IP address (port): %15s (%5u) | dst IP address (port): %15s (%5u) | Protocol: TCP | Header size: %5u [b] | Payload size: %5u [b] | Payload address: %15p | %s\n",
      inet_ntoa(source.sin_addr), ntohs(tcph->source), inet_ntoa(dest.sin_addr), ntohs(tcph->dest), header_size, len - header_size, buffer + header_size, retr
    );
  }

  return;
}

/*
 * Prints UDP packet's information.
 */
void print_udp_packet(const u_char *buffer, int len) {

  unsigned short iphdrlen;

  struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
  iphdrlen = iph->ihl*4;

  memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

  struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
  int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(udph);

  net_flow *trans = make_netflow_node(inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr), ntohs(udph->source), ntohs(udph->dest), iph->protocol);
  insert_unique_transmission(trans);

  udp_bytes += len;

  if (onFile) {
    FILE *f = fopen("log.txt", "a");

    if (f == NULL) {
        fprintf(stderr,"Error opening file.\n");
        exit(EXIT_FAILURE);
    }

    fprintf(f, "src IP address (port): %15s (%5u) | dst IP address (port): %15s (%5u) | Protocol: UDP | Header size: %5u [b] | Payload size: %5u [b] | Payload address: %15p |\n",
      inet_ntoa(source.sin_addr), ntohs(udph->source), inet_ntoa(dest.sin_addr), ntohs(udph->dest), header_size, len-header_size, buffer + header_size
    );

    fclose(f);
  }
  else {
    printf("src IP address (port): %15s (%5u) | dst IP address (port): %15s (%5u) | Protocol: UDP | Header size: %5u [b] | Payload size: %5u [b] | Payload address: %15p |\n",
      inet_ntoa(source.sin_addr), ntohs(udph->source), inet_ntoa(dest.sin_addr), ntohs(udph->dest), header_size, len-header_size, buffer + header_size
    );
  }

  return;
}

/* 
 * Prints resulting statistics.
 */
void pcap_results() {

  printf("\n\t\t-Statistics-\n\n");

  printf(
    "Net Flows captured:\n"
    "\t-Total net flows: %d\n"
    "\t-TCP net flows: %d\n"
    "\t-UDP net flows: %d\n",
    total_fl, tcp_fl, udp_fl);

  printf(
    "Packets captured:\n"
    "\t-Total packets: %d (excluded packets: %d)\n"
    "\t-TCP packets: %d\n"
    "\t-UDP packets: %d\n",
    total, others, tcp, udp);

  printf(
    "Bytes received:\n"
    "\t-TCP bytes: %d\n"
    "\t-UDP bytes: %d\n",
    tcp_bytes, udp_bytes);
}

/*
 * Inserts a node to a list, if it is not found in it, and updates the corresponding statistics.
 */
void insert_unique_transmission(net_flow *trans) {

  if (!search_transmission(n_flows, trans)) {
    n_flows = insert_transmission(n_flows, trans);
    ++total_fl;
    (strcmp(trans->protocol, "TCP") == 0) ? ++tcp_fl : ++udp_fl;
  }
}

/*
 * Initializes a net flow node with the attributes set as arguments.
 */
net_flow * make_netflow_node(char *src_ip, char *dst_ip, u_int src_p, u_int dst_p, u_int prot) {

  char * protocol = (prot == 6) ? "TCP" : "UDP";

  net_flow* node = (net_flow*)malloc(sizeof(net_flow));
  node->src_ip = src_ip;
  node->dst_ip = dst_ip;
  node->src_p = src_p;
  node->dst_p = dst_p;
  node->protocol = protocol;

  return node;
}

/*
 * Inserts a transmission node to a list recursively.
 */
net_flow * insert_transmission(net_flow *flows, net_flow *fl) {

  if (flows == NULL) 
    return fl;
  else
    flows->next = insert_transmission(flows->next, fl);
  
  return flows;
}

/*
 * Searches for a transmission node in a list recursively. If found, returns 1 else 0.
 */
int search_transmission(net_flow *flows, net_flow *fl) {

  if (flows == NULL)
    return 0;
  
  if (compare_netflows(flows, fl))
    return 1;
  else
    return search_transmission(flows->next, fl);
}

/*
 * Compares network flows. If flows are the same, returns 1 else 0.
 */
int compare_netflows(net_flow *flow1, net_flow *flow2) {

  return flow1->dst_p == flow2->dst_p 
    && flow1->src_p == flow2->src_p 
    && strcmp(flow1->dst_ip, flow2->dst_ip) == 0 
    && strcmp(flow1->src_ip, flow2->src_ip) == 0 
    && strcmp(flow1->protocol, flow2->protocol) == 0;
}

/*
 * Initializes a TCP node with the attributes set as arguments.
 */
tcp_packet * make_tcp_node(net_flow *flow, struct tcphdr *tcp, int payload) {

  tcp_packet *packet = (tcp_packet *)malloc(sizeof(tcp_packet));
  packet->flow = flow;
  packet->tcp = tcp;
  packet->payload = payload;
  packet->next = NULL;

  return packet;
}

/*
 * Inserts TCP transmission on top of list.
 */
tcp_packet * insert_tcp(tcp_packet *packets, tcp_packet *tcp) {

  if (packets == NULL)
    return tcp;
  else {
    tcp->next = packets;
    return tcp;
  }
}

/*
 * Checks if a packet has been retransmitted.
 */
int check_retransmission(tcp_packet *packets, tcp_packet *trans) {

  if (packets == NULL)
    return 0;
  
  if (compare_netflows(packets->flow, trans->flow) 
    && packets->tcp->seq - 1 != trans->tcp->ack_seq
    && packets->tcp->seq + packets->payload > trans->tcp->seq
    && (trans->tcp->syn == 1 || trans->tcp->fin == 1 || trans->payload > 0))
    return 1;
  else
    return check_retransmission(packets->next, trans);
}

/* 
 * Terminates packet capturing procedure.
 */
void pcap_terminate(int sig) {

    pcap_breakloop(handle);
    pcap_close(handle);
}

/* 
 * Prints usage information.
 */
void usage() {

  printf("\t\t-Usage-\n\n");

  printf(
    "Options:\n"
    "\t-i Network interface name (e.g., eth0)\n"
    "\t-r Packet capture filename (e.g., test.pcap)\n"
    "\t-f Filter expression (e.g., port 8080)\n"
    "\t-h Help message\n"
  );

  printf(
    "Execution examples:\n"
    "\t./pcap_ex -i eth0 (save the packets in log.txt)\n"
    "\t./pcap_ex -r test_pcap_5mins.pcap (print the outputs in terminal)\n"
    "\t./pcap_ex -f “port 8080” -i eth0\n"
  );

  exit(EXIT_FAILURE);
}
