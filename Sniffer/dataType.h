#ifndef TRANS_STRUCTDATA_H
#define TRANS_STRUCTDATA_H

/***** 帧首部 ******/
/* 6字节mac地址 */
typedef struct mac_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address;


/* 以太网帧首部 */
typedef struct frame_header{
	mac_address dmac;
	mac_address smac;
	u_short ethertype;
}frame_header;
/********************/


/***** ip协议分析 *****/
/*4字节ip地址*/
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/*IPv4 首部*/
typedef struct ip_header{
	u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
	u_char  tos;            // 服务类型(Type of service)
	u_short tlen;           // 总长(Total length)
	u_short identification; // 标识(Identification)
	u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	u_char  ttl;            // 存活时间(Time to live)
	u_char  proto;          // 协议(Protocol)
	u_short crc;            // 首部校验和(Header checksum)
	ip_address  saddr;      // 源地址(Source address)
	ip_address  daddr;      // 目的地址(Destination address)
	u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;


/* UDP首部 */
typedef struct udp_header{
	u_short sport;          // 源端口(Source port)
	u_short dport;          // 目的端口(Destination port)
	u_short len;            // UDP数据包长度(Datagram length)
	u_short crc;            // 校验和(Checksum)
}udp_header;

/* DNS数据结构定义 */
typedef struct dns_header{
	u_short id;    //会话标识
	u_short flag;  //标志
	u_short qnum;  //问题数
	u_short anRR;  //回答，资源记录数
	u_short auRR;  //授权，资源记录数
	u_short addRR; //附加，资源记录数
}dns_header;
/********************/

/* TCP首部 */
typedef struct tcp_header{
	u_short sport;		/* 源端口 */
	u_short dport;		/* 目的端口 */
	u_int   snum;		/* 序列号 */
	u_int   anum;		/* 确认序列号 */
	u_short dataoffset; /* 偏移量及保留字节 */
	u_short windows;	/* 16位窗口大小 */
	u_short chksum;		/* 校验和 */
	u_short urgentpt;	/* 紧急指针 */
}tcp_header;

/* ICMP首部 */
typedef struct icmp_header{
	u_char type;
	u_char code;
	u_short checksum;
	u_short id;
	u_short sequence;
}icmp_header;

/* IGMP首部 */
typedef struct igmp_header{
	u_char ver : 4;
	u_char type : 4;
	u_char rst;
	u_short checksum;
	u_int add;
}igmp_header;

/***** arp数据结构定义 *****/
/* arp帧结构（请求/应答） */
typedef struct arp_header{
	u_short HardwareType;   //硬件类型
	u_short ProtocolType;   //协议类型
	u_char HardwareAddLen;  //硬件地址长度
	u_char ProtocolAddLen;  //协议地址长度
	u_short OperationField;  //操作字段
	mac_address srcmac;     //源mac地址
	ip_address srcip;       //源ip地址
	mac_address dstmac;     //目的mac地址
	ip_address dstip;       //目的ip地址
}arp_header;

/* arp包结构 */
typedef struct arp_packet{
	frame_header fh;
	arp_header ap;
}arp_packet;
/********************/

#endif // TRANS_STRUCTDATA_H
