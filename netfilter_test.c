#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
typedef struct ip_header
{
    uint8_t ip_hdr_len : 4;
    uint8_t ip_version : 4;			//4bit
    uint8_t ip_tos;
    uint16_t total_len;			//2byte
    uint16_t identifi;			//2byte
    uint8_t ip_off : 5;         //5bit

    uint8_t ip_rf : 1;			//reserved fragment flag
    uint8_t ip_mf : 1;
    uint8_t ip_df : 1;			//don't fragment flag
    uint8_t ip_off2;			//mask for fragmenting bits

    uint8_t ip_TTL	;			//1byte
    uint8_t ip_proto;			//1byte
    uint16_t ip_hdr_CheckSum;		//2byte
    uint64_t ip_src;			//4byte
    uint64_t ip_dst;			//4byte
}IP_HDR;

typedef struct tcp_header
{
    uint16_t tcp_sport;
    uint16_t tcp_dport;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    //little endian
    uint8_t data_reserved :4;
    uint8_t data_offset :4;
    uint8_t fin : 1;
    uint8_t syn : 1;
    uint8_t rst : 1;
    uint8_t psh : 1;
    uint8_t ack : 1;
    uint8_t urg : 1;
    uint8_t ecn : 1;
    uint8_t cwr : 1;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_Pointer;
}TCP_HDR;

typedef struct url
{
    u_char url[100];
    int url_len;
}URL;
IP_HDR* ip_hdr;
TCP_HDR* tcp_hdr;
URL* url;
u_char* data;
int real_flag=0;

int PrintTcpPacket(u_char* Buffer, int size)
{
    //pcap 포맷안의 글로벌 헤더 제외 - 패킷헤더의 시작주소

    unsigned short iphdrlen;
    int i = 0;
    int header_size = 0, tcphdrlen, data_size;

    ip_hdr = (IP_HDR *)(Buffer);
    iphdrlen = ip_hdr->ip_hdr_len * 4;

    tcp_hdr = (TCP_HDR*)(Buffer + iphdrlen);
    tcphdrlen = tcp_hdr->data_offset * 4;

    data = (Buffer + iphdrlen + tcphdrlen);
    data_size = (size - iphdrlen - tcphdrlen);

    // http인 패킷만 캡쳐.
    printf("%d",data_size);
    if ((int)ntohs(tcp_hdr->tcp_dport) == 80 || (int)ntohs(tcp_hdr->tcp_sport) == 80)
    {
        //PrintIpHeader(Buffer, size);
        int k;
        for (k = 0; k < data_size; k++)
        {
            //if (k % 16 == 0)
               // printf("\n");
           // printf("%02x ", data[k]);

        }
	if(data_size>0)
	{
		//printf("=============%x %x %x=========\n",data[22],data[23],data[24]);
		//printf("=============%x %x %x=========\n",url->url[0],url->url[1],url->url[2]);
		//printf("%d",url->url_len);
		if(!memcmp(data+22,url->url,url->url_len))
		{
			
		   // printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
		    return -3;
		}
	}
    }
	return 0;


}
int find_sexypakcet(unsigned char* packet, int size) {
    /*
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
    */
    int flag=0;
    ip_hdr=(IP_HDR*)packet;

    switch(ip_hdr->ip_proto)
        {
            case 6: //TCP Protocol
            flag=PrintTcpPacket(packet,size);
            break;
            default:
            break;
        }
	printf("flag: %d\n",flag);

 return flag;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    int flag=0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
    {
        printf("payload_len=%d ", ret);
        real_flag = find_sexypakcet(data,ret);
    }

    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");

    if(real_flag ==-3)
    {
	//printf("mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm\n");
	printf("==================================================================================================================\n");
	printf("\t\t\t\n\n\nThis is porno site!!!!!!!!!!!!!!!!!!!!!!\n\n\n");
	printf("==================================================================================================================\n");
	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    else
    {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
   
}

void usage()
{
  printf("syntax: error \n");
  printf("sample: promgram www.gilgil.net\n");
}

int main(int argc, char **argv)
{

    if (argc < 2)
    {
      usage();
      return -1;
    }

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    url=(URL*)malloc(sizeof(URL));
    u_char* domain=argv[1];
    int j=0;
    url->url_len=0;

    for(;;)
    {
        if(!domain[j])
        {
		break;
        }

        url->url[j]=domain[j];
        url->url_len=j;
   
        j++;
    }


    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

