#define HAVE_REMOTE
#include "string"
#include "pcap.h"
#include "QDebug"
#include "utils.h"
#include "capture_thread.h"

extern QList< QList <u_char> > info_qlist;
extern int flag;

CaptureThread::CaptureThread(){
}

CaptureThread::~CaptureThread(){
	wait();
	quit();
}

void CaptureThread::set_NIC(const char * NIC){
	char_NIC = NIC;
}

void CaptureThread::set_filter(const char * filter){
	char_filter = filter;
}

void CaptureThread::run(){
		//抓获的变量
		struct pcap_pkthdr *header;    //接收到的数据包的头部
		const u_char *pkt_data;        //接收到的数据包的内容
		int res;                       //表示是否接收到了数据包
		pcap_t *adhandle;              //捕捉实例,是pcap_open返回的对象
		char errbuf[PCAP_ERRBUF_SIZE]; //错误缓冲区,大小为256
		pcap_if_t *alldevs;
		pcap_if_t *d;


		//分析的变量
		time_t local_tv_sec;
		struct tm * ltime;
		char timestr[16];
		u_int netmask;        //掩码
		struct bpf_program fcode;

		/* 跳转到指定的设备 */
		alldevs = getAllDevs();
		for(d = alldevs; strcmp(d->name, char_NIC) == 0; d = d->next)
			/* 打开适配器 */
			if(NULL == (adhandle = pcap_open(char_NIC, 65536,  PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf))){
				//if(NULL == (adhandle = pcap_open("{09F4C128-2A03-4D3C-96FC-00FF095A90BC}", 65536,  PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf))){
				qDebug("Can't open NIC");
			}else{
				if(d->addresses != NULL)
					/* 获得接口第一个地址的掩码 */
					netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
				else
					/* 如果接口没有地址，那么我们假设一个C类的掩码 */
					netmask = 0xffffff;

				pcap_compile(adhandle, &fcode, char_filter, 1, netmask);
				pcap_setfilter(adhandle, &fcode);

                while((res = pcap_next_ex(adhandle,&header,&pkt_data)) >= 0){
					if(res == 0){
						//返回值为0代表接受数据包超时，重新循环继续接收
						continue;
					}else if(flag == 1){  //暂停的时候不抓包
						pcap_compile(adhandle, &fcode, char_filter, 1, netmask);
						pcap_setfilter(adhandle, &fcode);

						/* 转换时间格式 */
						local_tv_sec = header->ts.tv_sec;
						ltime = localtime(&local_tv_sec);
						strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);


						QList<u_char> tmp_list;
						for(int i=0;i<header->len;i++){
							tmp_list.append(pkt_data[i]);
						}
						info_qlist.append(tmp_list);

						emit send_packet(timestr, header->len, pkt_data);
					}
				}
			}
}



