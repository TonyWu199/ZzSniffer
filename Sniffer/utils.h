/* 该头文件主要是关于网络抓包的一些常用工具函数 */
#ifndef UITLS_H
#define UITLS_H

#include "pcap.h"
#include "QDebug"
#include "stdio.h"

/* 获取所有网卡,并显示在comboBox_NIC中
 * 参数：无
 * 返回值：pcap_t* 网卡链表
 */
static pcap_if_t * getAllDevs(){
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	if(pcap_findalldevs(&alldevs,errbuf)==-1)//无法找到网卡列表
	{
		fprintf(stderr,"error in pcap_findalldevs_ex: %s\n",errbuf);
		exit(1);
	}
//	for(d = alldevs; d!=NULL; d=d->next){
//		ui->comboBox_NIC->addItem(d->description);
//	}

	return alldevs;
}


#endif // UITLS_H
