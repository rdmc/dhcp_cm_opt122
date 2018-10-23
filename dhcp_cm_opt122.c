/* dhcp_cm_opt122.c - DHCP Opt 122 subopt 1 Packet Mangling for Cable Modems */

/*
 * written rdmc Oct 2014
 * (C) 2014 NOS AÇORES
 *
 * This program is free software; you can redistribut it and/or modify
 * it under the terms of the GNU General Public Licence version 2 as
 * published by the Free Software Fundadtion. 
 * 
 * "dhcp_cm_opt122" is a netfilter hock kernel module that
 * for any packet, check if it is a DHCP (udp 67), and if the yiaddr
 * is in owers CMs neteworks (10.212.0.0/15). Then check if it have
 * the option 122 sub option 1 "", and change to the cmts primary interface address.
 * default action is to let all packets thruogh.
 *
 * v2: jul 2015, change  for new primary addresses 2x 10.212.x.0/17 and 4x 10.213.x.0/18 
 * v3: oct 2018, change  for new primary addresses 1x 10.212.0.0/16 and 4x 10.213.x.0/18  !!! need to change for ANGRA CMTS 3
 */
 

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#undef __KERNEL__
#include <linux/netfilter_ipv4.h>
#define __KERNEL__

#include <net/ip.h>
#include <net/checksum.h>


MODULE_AUTHOR("rdmc, ricardo.cabrl@nos-acores.pt");
MODULE_DESCRIPTION("DHCP Opt 122 Subopt 1 Packet Mangling for Cable Modems");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0");

#define KERN_CONT   ""

#define IP_HDR_LEN      20
#define UDP_HDR_LEN     8
#define TOT_HDR_LEN     28
  
#define DHCP_CHADDR_LEN (16)
#define DHCP_SNAME_LEN  (64)
#define DHCP_FILE_LEN   (128)
#define DHCP_VEND_LEN   (308)
#define DHCP_OPTION_MAGIC_NUMBER (0x63825363)

#define DHCP_OPTION_FIELD   (0)
#define DHCP_FILE_FIELD     (1)
#define DHCP_SNAME_FIELD    (2)


// struct from freeradius.org - proto_dhcp/dhcp.c
typedef struct dhcp_packet {
        uint8_t     opcode;
        uint8_t     htype;
        uint8_t     hlen;
        uint8_t     hops;
        uint32_t    xid;    /* 4 */
        uint16_t    secs;   /* 8 */
        uint16_t    flags;
        uint32_t    ciaddr; /* 12 */
        uint32_t    yiaddr; /* 16 */
        uint32_t    siaddr; /* 20 */
        uint32_t    giaddr; /* 24 */
        uint8_t     chaddr[DHCP_CHADDR_LEN]; /* 28 */
        uint8_t     sname[DHCP_SNAME_LEN]; /* 44 */
        uint8_t     file[DHCP_FILE_LEN]; /* 108 */
        uint32_t    option_format; /* 236 */  // Magic Cookie
        uint8_t     options[DHCP_VEND_LEN];
} dhcp_packet_t;

typedef struct dhcp_option_t {
        uint8_t     code;
        uint8_t     length;
} dhcp_option_t;


// forward declarations
static uint8_t *dhcp_get_option(dhcp_packet_t *packet, size_t packet_size,
                unsigned int option);               


static unsigned int out_hookfn(unsigned int hooknum,            //"const struct nf_hook_ops *ops" for kernel > 2.6.2x
                        struct sk_buff *skb,                  //""struct sk_buf*"  for kernel > 2.6.2x
                        const struct net_device *in, 
                        const struct net_device *out, 
                        int (*okfn)(struct sk_buff *))

{
        struct iphdr    *iph;
        struct udphdr   *udph;
        struct dhcp_packet  *dhcp;      
        uint8_t *data;
        uint8_t *opt;    
        size_t  udp_len, iph_len, dhcp_len;

        union ipv4 {
                uint32_t ip;
                uint8_t  data[4];
        } yiaddr;       

        if ((skb == NULL ) || (skb_linearize(skb) < 0)) 
                return NF_ACCEPT;
                                
        iph = (struct iphdr *) skb_header_pointer (skb, 0, 0, NULL);
        iph_len = iph->ihl * 4;

        if ((iph == NULL) || (iph->protocol != IPPROTO_UDP)) 
                return NF_ACCEPT;       

        iph_len = iph->ihl * 4;                    
        udph = (struct udphdr *) skb_header_pointer (skb, iph_len, 0, NULL);                        

        // dhcp /bootps ?
        if (udph && (ntohs(udph->source) == 67)) {

                data = (uint8_t *) skb->data + iph_len + sizeof(struct udphdr);
                dhcp = (struct dhcp_packet *) data;
                dhcp_len = skb->len - iph_len - sizeof(struct udphdr);
                
                if (dhcp_len < 300)     // ignore dhcp packet too short
                        return NF_ACCEPT;
        
                yiaddr.ip = dhcp->yiaddr;

                // for a cable modem ? (yiaddr in CM ranges)
                if ((yiaddr.data[0] == 10) && ((yiaddr.data[1] & 0xFE) == 212))  {                
                        
                        // have dhcp option 122, suboption 1 ?
                        opt = dhcp_get_option(dhcp, dhcp_len, 122);
                        if (opt && (opt[1] >= 6) && (opt[2] == 1) && (opt[3] == 4)) {
                               
				//printk(KERN_INFO "dhcp_cm_opt122: got dhcp packt with opt 122.\n"); 

                                if (! skb_make_writable(skb, skb->len)) {
                                        //printk(KERN_INFO "dhcp_cm_opt122: skb_make_writable Failed.\n"); 
                                        return NF_ACCEPT;
                                }
                                // re-fetch the skb->data pointers after skb_make_writable

                                iph = (struct iphdr *) skb_header_pointer (skb, 0, 0, NULL);                        
                                iph_len = iph->ihl * 4;                                
                
                                udph = (struct udphdr *) skb_header_pointer (skb, iph_len, 0, NULL);
                                udp_len = skb->len - iph_len;
                                
                                data = (uint8_t *) skb->data + iph_len + sizeof(struct udphdr);
                                dhcp = (struct dhcp_packet *) data;
                                dhcp_len = skb->len - iph_len - sizeof(struct udphdr);
                                              
                                yiaddr.ip = dhcp->yiaddr;
                                
                                opt = dhcp_get_option(dhcp, dhcp_len, 122);                                
                                if ((opt == NULL) || (opt[1] < 6) || (opt[2] != 1) || (opt[3] != 4)) {
                                        // WTF ? 
                                        return NF_ACCEPT;
                                }

				/*
				// v1:
                                // rewrite dhcp option  122 suboption 1 
                                //  Primary DHCP Server - 10.x.0.1
                                opt[4] = 10;   
                                opt[5] = yiaddr.data[1];
                                opt[6] = 0;
                                opt[7] = 1;
				*/                                  
                               
				// v2:
                                // rewrite dhcp option  122 suboption 1 
                                //  Primary DHCP Server - 2x 10.212.x.1/17 and 4x 10.213.x.1/18
 
                                //v3:
                                // rewrite dhcp option  122 suboption 1
                                // Primary DHCP Server - 1x 10.212.0.1/16 and 4x 10.213.x.1/18

                                opt[4] = 10;   
                                opt[5] = yiaddr.data[1];								
                                opt[6] = yiaddr.data[2] & 0x80;
				if (yiaddr.data[1] == 212) {
	                        	/* opt[6] = yiaddr.data[2] & 0x80; */
	                        	opt[6] = yiaddr.data[2] & 0x00;
				} 
				else { // tiaddr.data[1]== 213
                                	opt[6] = yiaddr.data[2] & 0xC0;
				}
                                opt[7] = 1;
                                                                 
                                           
                                // calculete upd checksum
                                
                                /*  Don't care...
                                udph->check = 0;
                                udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, 
                                                                 udp_len, IPPROTO_UDP, 
                                                                 csum_partial((unsigned char *)udph, udp_len, 0)); 
                                */
                                        
                        
                        } // has opt 122 sub 1                              

                } // yiaddr for a Cable Modem         
                        
        } // dhcp pkt

//accept:
       return NF_ACCEPT;
}


/*
 * the folowing function code is from:
 * freeradius.org - proto_dhcp/dhcp.c
 *
 *  (c) 2008 The FreeRADIUS server project
 */

static uint8_t *dhcp_get_option(dhcp_packet_t *packet, size_t packet_size,
                unsigned int option)                
{
        int overload = 0;
        int field = DHCP_OPTION_FIELD;
        size_t where, size;
        uint8_t *data = packet->options;

        where = 0;
        size = packet_size - offsetof(dhcp_packet_t, options);
        data = &packet->options[where];

        while (where < size) {
                if (data[0] == 0) { /* padding */
                        where++;
                        continue;
                }

                if (data[0] == 255) { /* end of options */
                        if ((field == DHCP_OPTION_FIELD) &&
                            (overload & DHCP_FILE_FIELD)) {
                                data = packet->file;
                                where = 0;
                                size = sizeof(packet->file);
                                field = DHCP_FILE_FIELD;
                                continue;

                        } else if ((field == DHCP_FILE_FIELD) &&
                                    (overload && DHCP_SNAME_FIELD)) {
                                data = packet->sname;
                                where = 0;
                                size = sizeof(packet->sname);
                                field = DHCP_SNAME_FIELD;
                                continue;
                        }

                        return NULL;
                }

                /*
                 *  We MUST have a real option here.
                 */
                if ((where + 2) > size) {
                        //fr_strerror_printf("Options overflow field at %u",
                        //           (unsigned int) (data - (uint8_t *) packet));
                        return NULL;
                }

                if ((where + 2 + data[1]) > size) {
                        //fr_strerror_printf("Option length overflows field at %u",
                        //           (unsigned int) (data - (uint8_t *) packet));
                        return NULL;
                }

                if (data[0] == option) return data;

                if (data[0] == 52) { /* overload sname and/or file */
                        overload = data[3];
                }

                where += data[1] + 2;
                data += data[1] + 2;
        }

        return NULL;
}


/*
 *  netfilter hock & kernel module stuff
 */


static struct nf_hook_ops nfho_out __read_mostly = {
        //.pf       = NFPROTO_IPV4,
        .pf         = AF_INET,
        .priority = 1,
        .hooknum  = NF_IP_LOCAL_OUT,
        .hook     = out_hookfn,
};


static void mangle_cleanup(void)
{
        nf_unregister_hook(&nfho_out);
}

static void __exit mangle_fini(void)
{
        printk(KERN_INFO "module dhcp_opt122, cleanup...\n");
        mangle_cleanup();
}


static int __init mangle_init(void)
{
        int ret = 0;
        printk(KERN_INFO "module dhcp_cm_opt123, init...\n");

        ret = nf_register_hook(&nfho_out);
        if (ret) {
            printk(KERN_ERR "dhcp_cm_opt122: failed to register");
            mangle_cleanup();
        }

        return ret;
}


module_init(mangle_init);
module_exit(mangle_fini);

//EOF
