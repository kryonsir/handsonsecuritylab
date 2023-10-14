#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/tcp.h>
/*
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#define TARGET_IP "10.9.0.5"
*/

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};
/*
struct icmpheader{
  unsigned char	icmph_type:8,
  			icmph_code:0;
  unsigned short int	icmph_id:8,
  			icmph_checksum;
  unsigned short int	icmph_seqnum:7;
}  
*/
// 计算校验和
/*
unsigned short in_cksum(unsigned short *addr, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)addr;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}
*/
void print_tcp_data(const u_char *packet, int data_len) {
    struct tcphdr *tcp_header = (struct tcphdr*)(packet);
    int tcp_header_length = tcp_header->doff * 4;
    const u_char *tcp_data = packet + tcp_header_length;
    int tcp_data_length = data_len - tcp_header_length;

    if (tcp_data_length > 0) {
        char *data_str = malloc(tcp_data_length + 1);
        memcpy(data_str, tcp_data, tcp_data_length);
        data_str[tcp_data_length] = '\0';  // 添加字符串结束符

        // 将字节流转换为ASCII字符串
        for (int i = 0; i < tcp_data_length; i++) {
            if (data_str[i] < 32 || data_str[i] > 126) {
                data_str[i] = '.';  // 将非可打印字符替换为 '.'
            }
        }

        printf("TCP Data: %s\n", data_str);

        free(data_str);
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));   
    
    /*
    // 打印数据部分
    int data_len = ntohs(ip->iph_len) - sizeof(struct ipheader);  // 计算数据长度
    const u_char *data = packet + sizeof(struct ethheader) + sizeof(struct ipheader); // 数据部分的指针

    printf("   Data:\n");
    for (int i = 0; i < data_len; i++) {
      printf("%02x ", data[i]);
      if ((i + 1) % 16 == 0) {
        printf("\n");
      }
    
    printf(" ");
  }
  */
    int data_len=header->len;
    // 打印TCP数据
    print_tcp_data(packet, data_len);
    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n\n");
            return;
        default:
            printf("   Protocol: others\n\n");
            return;
    }
  }
}
/*
void spoof(handle){
  struct ipheader ip_h;
  struct icmpheader icmp_h;
  //    icmp_header.checksum = in_cksum((unsigned short *)&icmp_header, sizeof(struct icmphdr)); // 计算 ICMP 头部校验
  char packet[sizeof(struct ipheader) + sizeof(struct icmpheader)];
  memcpy(packet, &ip_h, sizeof(struct ipheader));
  memcpy(packet + sizeof(struct ipheader), &icmp_h, sizeof(struct icmpheader));
  
  icmp_h.icmph_checksum=in_cksum=((unsigned short * )&icmp_h , sizeof(struct icmpheader));
  
  memcpy(packet + sizeof(struct ipheader), &icmp_h, sizeof(struct icmpheader));
  
  if (pcap_sendpacket(handle, (const u_char *)packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Couldn't send packet: %s\n", pcap_geterr(handle));
        return 1;
    }
    
  pcap_close(handle);
  return 0
}
*/

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	//char filter_exp[] = "port 23";	/* The filter expression */
	//char filter_exp[] = "icmp";
	char filter_exp[]="tcp and dst portrange 10-100";
	
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	printf("%s\n", dev);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	
	/* Grab a packet */
	//packet = pcap_next(handle, &header);
	/* Print its length */
	//printf("Jacked a packet with length of [%d]\n", header.len);
	
	
	/* And close the session */
	//pcap_close(handle);
	// Step 3: Capture packets
	printf("start to sniff...\n");
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);   //Close the handle
	return(0);
}
