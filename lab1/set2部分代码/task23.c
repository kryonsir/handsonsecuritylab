#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "myheader.h"


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader));

    printf("From: %s ", inet_ntoa(ip->iph_sourceip));   
    printf("To: %s ", inet_ntoa(ip->iph_destip));
    if (ip->iph_protocol == IPPROTO_ICMP)
        printf("protocal: ICMP\n");
    else
        printf("protocal: Others\n");
    
    struct icmpheader *icmp_pkt = (struct icmpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));                                                

    if (ip->iph_protocol == IPPROTO_ICMP) {

        char buffer[1500];
        memset(buffer, 0, 1500);

        /*********************************************************
             Step 1: Fill in the ICMP header.
            ********************************************************/
        struct icmpheader *icmp = (struct icmpheader *)
                                    (buffer + sizeof(struct ipheader));
        icmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.
        icmp->icmp_code = 0;
        icmp->icmp_id   = icmp_pkt->icmp_id;
        icmp->icmp_seq  = icmp_pkt->icmp_seq;
        printf("icmp id: %d, seq: %d\n", ntohs(icmp_pkt->icmp_id), ntohs(icmp_pkt->icmp_seq));

        // Calculate the checksum for integrity
        icmp->icmp_chksum = 0;
        icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                        sizeof(struct icmpheader));

        /*********************************************************
             Step 2: Fill in the IP header.
            ********************************************************/
        struct ipheader *ipp = (struct ipheader *) buffer;
        ipp->iph_ver = 4;
        ipp->iph_ihl = 5;
        ipp->iph_ttl = 64;
        ipp->iph_sourceip.s_addr = ip->iph_destip.s_addr;
        ipp->iph_destip.s_addr = ip->iph_sourceip.s_addr;
        ipp->iph_protocol = IPPROTO_ICMP;
        ipp->iph_len = htons(sizeof(struct ipheader) +
                            sizeof(struct icmpheader));
        printf("send tt source :%s\n", inet_ntoa(ipp->iph_sourceip));
        printf("send tt dest: %s\n", inet_ntoa(ipp->iph_destip));

        /*********************************************************
             Step 3: Finally, send the spoofed packet
            ********************************************************/
        // icmp_pkt->icmp_type = 0;
        // icmp_pkt->icmp_code = 0;
        // icmp->icmp_chksum = 0;
        // icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
        //                                 sizeof(struct icmpheader));
        send_raw_ip_packet (ipp);

    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp[icmptype]==icmp-echo";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
  printf("listening on network card, ret: %p...\n", handle);

  // Step 2: Compile filter_exp into BPF psuedo-code
  printf("try to compile filter...\n");
  pcap_compile(handle, &fp, filter_exp, 0, net);
  printf("try to set filter...\n");
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  printf("start to sniff...\n");
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}


