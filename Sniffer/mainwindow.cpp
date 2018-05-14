#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "filterwidget.h"
#include "capture_thread.h"

#include "QDebug"
#include "QScrollBar"
#include "QHeaderView"
#include "QTableWidgetItem"
#include "QList"
#include "QTreeWidget"
#include "set"
#include "utils.h"
#include "string"

QList< QList <u_char> > info_qlist;
std::set<char> normal_char = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
							 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
							 '1','2','3','4','5','6','7','8','9','0','~','!','@','#','$','%','^','&','*','(',')','-','+','=','\\','|',
							 '[',']','{','}',';',':','"','\'',',','<','.','>','/','?'};
int flag = 1;
QString NIC_name;
int tcp_num = 0;
int udp_num = 0;
int arp_num = 0;
int icmp_num = 0;
int igmp_num = 0;
int sum = 0;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
	ui->setupUi(this);
	Designer();
	set_comboBox_NIC();

	//FilterWidget和MainWindow的通信
	connect(flt, SIGNAL(filter_set(std::string, std::string, std::string, std::string, std::string,
								   std::string, std::string, std::string, std::string, std::string)),
			this, SLOT(filter_receive(std::string, std::string, std::string, std::string, std::string,
									  std::string, std::string, std::string, std::string, std::string)));
}

MainWindow::~MainWindow()
{
    delete ui;
}

/****** 界面中一些宽度和长度的设计,并加载样式表 ******/
void MainWindow::Designer(){
	//设置splitter的默认比例
	ui->splitter->setStretchFactor(0,1);
	ui->splitter->setStretchFactor(1,7);
	ui->splitter->setStretchFactor(2,3);

	//tableWidget界面的调整
	ui->tableWidget->setSelectionBehavior(QTableWidget::SelectRows);       //最小的选择单位为行
	ui->tableWidget->setSelectionMode(QTableWidget::SingleSelection);      //一次选择只能选择一行
	ui->tableWidget->horizontalHeader()->setFixedHeight(30);               //表头高度
	ui->tableWidget->horizontalHeader()->setStyleSheet("QHeaderView::section{background:skyblue;}"); //设置表头的背景色
	ui->tableWidget->verticalHeader()->setDefaultSectionSize(25);          //行高固定为8
	ui->tableWidget->setFrameShape(QFrame::NoFrame);                       //表格无边框
	ui->tableWidget->setShowGrid(false);  //表中无线条
	ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);   //不能编辑	
	ui->tableWidget->horizontalHeader()->setStretchLastSection(true);   //自适应

	 //每一个属性列的宽度
	ui->tableWidget->setColumnWidth(0,80);
	ui->tableWidget->setColumnWidth(1,200);
	ui->tableWidget->setColumnWidth(2,200);
	ui->tableWidget->setColumnWidth(3,200);
	ui->tableWidget->setColumnWidth(4,200);
	ui->tableWidget->setColumnWidth(5,150);
	ui->tableWidget->setColumnWidth(6,80);

	//treewidget界面调整
	ui->treeWidget->setHeaderHidden(true);

	//TextEdit_Hex TextEdit_Char界面调整
	ui->textEdit_Hex->setFrameShape(QFrame::NoFrame);
	ui->treeWidget->setFrameShape(QFrame::NoFrame);

}

/***** 填充comboBox_NIC中的选项 *****/
void MainWindow::set_comboBox_NIC(){
	for(pcap_if_t * d = getAllDevs(); d!=NULL; d=d->next){
			ui->comboBox_NIC->addItem(d->name);
	}

	//使所有内容都能显示
	int max_len = 0;

	for(int idx=0; idx < ui->comboBox_NIC->count(); idx++){
		if(max_len < ui->comboBox_NIC->itemText(idx).length())
			max_len = ui->comboBox_NIC->itemText(idx).length();
	}
	int pt_val = ui->comboBox_NIC->font().pointSize();
	ui->comboBox_NIC->view()->setFixedWidth(max_len * pt_val * 1);
}

/***** 在statusBar显示comboBox中的值 *****/
void MainWindow::on_comboBox_NIC_currentTextChanged()
{
	ui->statusBar->showMessage(ui->comboBox_NIC->currentText());
}

/***** Start键触发 *****/
void MainWindow::on_actionStart_triggered()
{
	if(flag == 1){
		//抓包线程和主界面线程之间的槽函数
		connect(capturethread, SIGNAL(send_packet(char *, int, const u_char*)), this,
				SLOT(receive_packet(char *, int, const u_char*)), Qt::BlockingQueuedConnection);

		capturethread->set_NIC(ui->comboBox_NIC->currentText().toStdString().data());   //设置网卡
		capturethread->set_filter(string_filter.c_str());  //设置过滤器
		capturethread->start();
	}else{
		capturethread->set_filter(string_filter.c_str());  //设置过滤器
		flag = 1;
	}
}


/***** Stop键触发 *****/
void MainWindow::on_actionStop_triggered()
{
	//capturethread->~CaptureThread();
	flag = 0;
}

/***** Clear键触发 *****/
void MainWindow::on_actionClear_triggered()
{
	ui->tableWidget->clearContents();   //抓包之前进行tablewiidget清空
	ui->tableWidget->setRowCount(0);    //行数置0
}

/****** 工具栏-过滤器触发 ******/
void MainWindow::on_actionFilter_jump_triggered()
{
	flt->show();
}

/****** 工具栏-arp欺骗触发 ******/
void MainWindow::on_actionARP_triggered()
{
	arp->show();
}

/***** 接收子线程的抓包数据并显示在tablewidget中 *****/
void MainWindow::receive_packet(char * time, int len, const u_char* pkt_data){
	if(flag == 1){
		u_int ip_len;         //
		u_short sport,dport;  //端口
		frame_header *fh;  //以太网首部
		ip_header *ih;     //ip首部
		tcp_header *th;
		udp_header *uh;
		arp_header *ah;

		/* 获得mac地址、帧类型 */
		fh = (frame_header *)pkt_data;

		/* 转换成字符串输出 */
		char char_srcmac[50] = "";
		char char_dstmac[50] = "";
		u_short ethertype;
		char char_srcip[50] = "";
		char char_dstip[50] = "";

		//转换以太网帧中的mac地址转换
		sprintf(char_srcmac,"%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
				fh->smac.byte1,
				fh->smac.byte2,
				fh->smac.byte3,
				fh->smac.byte4,
				fh->smac.byte5,
				fh->smac.byte6);
		sprintf(char_dstmac,"%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
				fh->dmac.byte1,
				fh->dmac.byte2,
				fh->dmac.byte3,
				fh->dmac.byte4,
				fh->dmac.byte5,
				fh->dmac.byte6);



		//将协议从hex转换为对应的char*类型名称，以及ip地址转换
		char Ethertype[5] = "";
		ethertype = ntohs(fh->ethertype);
		if(ethertype == 0x0800){  //ip协议
			//获得IP数据包头部地址
			ih = (ip_header*)(pkt_data +
							  14);//以太网头部长度

			//ICMP分析
			if(ih->proto == 1){
				icmp_num++;    //icmp包数加1

				memcpy(Ethertype,"ICMP",4);
			}
			//IGMP分析
			else if(ih->proto == 2){
				igmp_num++;    //igmp包数加1

				memcpy(Ethertype,"IGMP",4);
			}
			//TCP分析
			else if(ih->proto == 6){
				tcp_num++;    //tcp包数加1

				/* 获得TCP首部的位置 */
				ip_len = (ih->ver_ihl & 0xf) * 4;
				th = (tcp_header *) ((u_char*)ih + ip_len);

				/* 将网络字节序列转换成主机字节序列 */
				sport = ntohs( th->sport );
				dport = ntohs( th->dport );

				if(sport == 80 || dport == 80){
					memcpy(Ethertype, "HTTP", 4);
				}else{
					memcpy(Ethertype, "TCP", 3);
				}

			}
			//UDP分析
			else if(ih->proto == 17){
				udp_num++;    //udp包数加1

				memcpy(Ethertype,"UDP",3);
				/* 获得UDP首部的位置 */
				ip_len = (ih->ver_ihl & 0xf) * 4;
				uh = (udp_header *) ((u_char*)ih + ip_len);

				/* 将网络字节序列转换成主机字节序列 */
				sport = ntohs( uh->sport );
				dport = ntohs( uh->dport );

				if(sport == 53 || dport == 53){
					memcpy(Ethertype, "DNS", 3);
				}else{
					memcpy(Ethertype, "UDP", 3);
				}
			}


			//转换ip包中的ip地址
			sprintf(char_srcip,"%d.%d.%d.%d:%d",
					ih->saddr.byte1,
					ih->saddr.byte2,
					ih->saddr.byte3,
					ih->saddr.byte4,
					sport);
			sprintf(char_dstip,"%d.%d.%d.%d:%d",
					ih->daddr.byte1,
					ih->daddr.byte2,
					ih->daddr.byte3,
					ih->daddr.byte4,
					dport);
		}

		//arp协议
		else if(ethertype == 0x0806){
			arp_num++;     //arp包数加1

			memcpy(Ethertype,"ARP",3);

			//获得arp数据包头部地址
			ah = (arp_header*)(pkt_data +
							   14);//以太网头部长度

			sprintf(char_srcip,"%d.%d.%d.%d",
					ah->srcip.byte1,
					ah->srcip.byte2,
					ah->srcip.byte3,
					ah->srcip.byte4);
			sprintf(char_dstip,"%d.%d.%d.%d",
					ah->dstip.byte1,
					ah->dstip.byte2,
					ah->dstip.byte3,
					ah->dstip.byte4);
		}
		//rarp协议
		else if(ethertype == 0x0835){
			memcpy(Ethertype,"RARP",4);
		}

		//设置表格中的值
		char length[10];
		itoa(len, length, 10);
		int RowCount = ui->tableWidget->rowCount();
		ui->tableWidget->insertRow(RowCount);

		ui->tableWidget->setItem(RowCount, 0, new QTableWidgetItem(time));
		ui->tableWidget->setItem(RowCount, 1, new QTableWidgetItem(char_srcip));
		ui->tableWidget->setItem(RowCount, 2, new QTableWidgetItem(char_dstip));
		ui->tableWidget->setItem(RowCount, 3, new QTableWidgetItem(char_srcmac));
		ui->tableWidget->setItem(RowCount, 4, new QTableWidgetItem(char_dstmac));
		ui->tableWidget->setItem(RowCount, 5, new QTableWidgetItem(Ethertype));
		ui->tableWidget->setItem(RowCount, 6, new QTableWidgetItem(length));

		//滚动条跟踪
		ui->tableWidget->verticalScrollBar()->setValue(RowCount);

		sum++;     //总包数加1
		//将包数量统计信息显示在界面
		ui->label_tcpnum->clear();
		ui->label_tcpnum->setText(QString::number(tcp_num, 10));
		ui->label_udpnum->clear();
		ui->label_udpnum->setText(QString::number(udp_num, 10));
		ui->label_arpnum->clear();
		ui->label_arpnum->setText(QString::number(arp_num, 10));
		ui->label_igmpnum->clear();
		ui->label_igmpnum->setText(QString::number(igmp_num, 10));
		ui->label_icmpnum->clear();
		ui->label_icmpnum->setText(QString::number(icmp_num, 10));
		ui->label_sumnum->clear();
		ui->label_sumnum->setText(QString::number(sum, 10));
	}
}

/***** 接受过滤器设置窗口传递的设置参数 *****/
void MainWindow::filter_receive(std::string choose_tcp, std::string choose_udp, std::string choose_arp, std::string choose_igmp, std::string choose_icmp,
								std::string srcip, std::string srcport, std::string dstip, std::string dstport, std::string custom){
	std::string format = "(ip and ";
	std::string r_kuohao = ")";
	std::string Or = " or ";
	string_filter = "";

	if(custom != ""){
		string_filter = custom;
		return;
	}else{
		if(choose_tcp != ""){
			string_filter += format + choose_tcp + r_kuohao;
		}
		if(choose_udp != ""){
			if(string_filter == "")
				string_filter += format + choose_udp + r_kuohao;
			else{
				string_filter += Or + format + choose_udp + r_kuohao;
			}
		}
		if(choose_arp != ""){
			if(string_filter == "")
				string_filter += std::string("arp ");
			else{
				string_filter += Or + std::string("arp ");
			}
		}
		if(choose_igmp != ""){
			if(string_filter == "")
				string_filter += format + choose_igmp + r_kuohao;
			else{
				string_filter += Or + format + choose_igmp + r_kuohao;
			}
		}
		if(choose_icmp != ""){
			if(string_filter == "")
				string_filter += format + choose_icmp + r_kuohao;
			else{
				string_filter += Or + format + choose_icmp + r_kuohao;
			}
		}
	}

	//设置类型之后用括号包裹
	if(string_filter != ""){
		string_filter = std::string("(") + string_filter + std::string(") ");
	}

	//设置ip的过滤
	if(srcip != ""){
		if(string_filter != "")
			string_filter += std::string("and (src host " + srcip + ") ");
		else
			string_filter = std::string(" (src host " + srcip + ") ");
	}
	if(srcport != ""){
		if(string_filter != "")
			string_filter += std::string("and (src port " + srcport + ") ");
		else
			string_filter = std::string(" (src port " + srcport + ") ");
	}
	if(dstip != ""){
		if(string_filter != "")
			string_filter += std::string("and (dst host " + dstip + ") ");
		else
			string_filter = std::string(" (dst host " + dstip + ") ");
	}
	if(dstport != ""){
		if(string_filter != "")
			string_filter += std::string("and (dst port " + dstport + ") ");
		else
			string_filter = std::string(" (dst port " + dstport + ") ");
	}

	qDebug() << string_filter.c_str();    //输出过滤器
}

/***** 鼠标点击，显示包信息 *****/
void MainWindow::on_tableWidget_itemClicked()
{

	//清空表格内容
	ui->textEdit_Hex->clear();


	//获取该行的pkt_data内容
	char length[4];
	int len = info_qlist[ui->tableWidget->currentRow()].size();   //获取数据包长度
	itoa(len, length, 10);
	u_char * pkt_data = new u_char[len];
	for(int i=0;i<len;i++){
		pkt_data[i] = info_qlist[ui->tableWidget->currentRow()][i];
	}


	/* pkt_data 信息Hex 显示 */
	int linenum_int = 0;
	char linenum_char[3];
	int record = 0;
	ui->textEdit_Hex->insertPlainText(QString("0x0000  "));
	for(int i = 0; i <= len; i++){
		char tmp[2];
		sprintf(tmp, "%.2X", pkt_data[i]);
		if(i % 16 == 0 && i != 0){
			ui->textEdit_Hex->insertPlainText("   ");
			for(int j=i-16; j<i; j++){
				if(normal_char.find(pkt_data[j]) == normal_char.end()){
					ui->textEdit_Hex->insertPlainText(QChar('.'));
				}else{
					ui->textEdit_Hex->insertPlainText(QChar(pkt_data[j]));
				}
				if(j == i-1){
					ui->textEdit_Hex->insertPlainText("\n");
					linenum_int ++;
					sprintf(linenum_char, "%.3X0  ", linenum_int);
					ui->textEdit_Hex->insertPlainText(QString("0x") + QString(QLatin1String(linenum_char)));
					record = j;
				}
			}
		}
		else if(i!=0)
			ui->textEdit_Hex->insertPlainText(QString(" "));
		ui->textEdit_Hex->insertPlainText(QString(QLatin1String(tmp)));
	}

	for(int i=16-(len-record) + 1; i != 0; i--)
		ui->textEdit_Hex->insertPlainText("   ");
	for(; record < len; record++){
		if(normal_char.find(pkt_data[record]) == normal_char.end())
			ui->textEdit_Hex->insertPlainText(QChar('.'));
		else
			 ui->textEdit_Hex->insertPlainText(QChar(pkt_data[record]));
	}


	/* 数据包树状图显示 */
	QTreeWidget* tree = ui->treeWidget;
	tree->clear();
	tree->show();

	QTreeWidgetItem * branch_frame;
	QTreeWidgetItem * branch_ethernet;
	QTreeWidgetItem * branch_ip;
	QTreeWidgetItem * branch_tcp;
	QTreeWidgetItem * branch_udp;
	QTreeWidgetItem * branch_icmp;
	QTreeWidgetItem * branch_igmp;
	QTreeWidgetItem * branch_http;
	QTreeWidgetItem * branch_dns;
	QTreeWidgetItem * branch_arp;



	u_int ip_len;         //
	u_short sport,dport;  //端口
	frame_header *fh;  //以太网首部
	ip_header *ih;     //ip首部
	tcp_header *th;    //tcp首部
	udp_header *uh;    //udp首部
	icmp_header *ich;  //icmp首部
	igmp_header *igh;  //igmp首部
	arp_header *ah;    //arp首部
	dns_header *dh;
	u_short ethertype;

	char char_srcmac[50] = "";
	char char_dstmac[50] = "";
	char char_srcip[50] = "";
	char char_dstip[50] = "";
	char Ethertype[4] = "";

	fh = (frame_header*)(char *)pkt_data;
	//转换以太网帧中的mac地址转换
	sprintf(char_srcmac, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
		   fh->smac.byte1,
		   fh->smac.byte2,
		   fh->smac.byte3,
		   fh->smac.byte4,
		   fh->smac.byte5,
		   fh->smac.byte6);
	sprintf(char_dstmac, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
		   fh->dmac.byte1,
		   fh->dmac.byte2,
		   fh->dmac.byte3,
		   fh->dmac.byte4,
		   fh->dmac.byte5,
		   fh->dmac.byte6);

	//统一显示以太网信息
	branch_frame = new QTreeWidgetItem(tree, QStringList(QString("Frame")));
	QTreeWidgetItem* frame_sub1 = new QTreeWidgetItem(branch_frame, QStringList(QString("Frame长度:  ") + QString(length)));
	branch_ethernet = new QTreeWidgetItem(tree, QStringList(QString("Ethernet Ⅱ    (") + QString(char_srcmac) +  QString(") => (") + QString(char_dstmac) + QString(")")));
	QTreeWidgetItem* ether_sub1 = new QTreeWidgetItem(branch_ethernet, QStringList(QString("源MAC:  ") + QString(char_srcmac)));
	QTreeWidgetItem* ether_sub2 = new QTreeWidgetItem(branch_ethernet, QStringList(QString("目的MAC:  ") + QString(char_dstmac)));

	ethertype = ntohs(fh->ethertype);
	char tmp[15] = "";    //贯穿的char字符串变量
	if(ethertype == 0x0800){
		//获得IP数据包头部地址
		ih = (ip_header*)(pkt_data +
						  14);//以太网头部长度
		ip_len = (ih->ver_ihl & 0xf) * 4;

		//转换ip包中的ip地址,无端口
		sprintf(char_srcip,"%d.%d.%d.%d",
				ih->saddr.byte1,
				ih->saddr.byte2,
				ih->saddr.byte3,
				ih->saddr.byte4);
		sprintf(char_dstip,"%d.%d.%d.%d",
				ih->daddr.byte1,
				ih->daddr.byte2,
				ih->daddr.byte3,
				ih->daddr.byte4);

		QTreeWidgetItem* ether_sub3 = new QTreeWidgetItem(branch_ethernet, QStringList(QString("协议类型: IP (0x0800)")));

		branch_ip = new QTreeWidgetItem(tree, QStringList(QString("Internet Protocol   (") + QString(char_srcip) +  QString(") => (") + QString(char_dstip) + QString(")")));
		sprintf(tmp, "%d", (ih->ver_ihl >> 4));         //版本
		QTreeWidgetItem* ip_sub1 = new QTreeWidgetItem(branch_ip, QStringList(QString("版本: ") + QString(tmp)));
		sprintf(tmp, "%d", (ih->ver_ihl & 0x0f) << 2);  //注意首部长度需要乘以4(字节)
		QTreeWidgetItem* ip_sub2 = new QTreeWidgetItem(branch_ip, QStringList(QString("首部长度: ") + QString(tmp) + QString(" Bytes")));
		sprintf(tmp, "%.4X", ih->tos);                  //服务类型
		QTreeWidgetItem* ip_sub3 =  new QTreeWidgetItem(branch_ip, QStringList(QString("服务类型: (0x") + QString(tmp) + QString(")")));
		sprintf(tmp, "%d", ih->tlen);                   //总长度
		QTreeWidgetItem* ip_sub4 = new QTreeWidgetItem(branch_ip, QStringList(QString("总长度: ") + QString(tmp) + QString(" Bytes")));
		sprintf(tmp, "%.4X", ih->identification);       //标识
		QTreeWidgetItem* ip_sub5 = new QTreeWidgetItem(branch_ip, QStringList(QString("标识: (0x") + QString(tmp) + QString(")")));
		sprintf(tmp, "%.2X", ih->flags_fo >> 5);       //标志位
		QTreeWidgetItem* ip_sub6;
		if( (ih->flags_fo >> 6) & 0x1 == 0x1){
			 ip_sub6 = new QTreeWidgetItem(branch_ip, QStringList(QString("标志位:  0x") + QString(tmp) + QString(" 未分片:该数据包是完整的数据包")));
		}else{
			ip_sub6 = new QTreeWidgetItem(branch_ip, QStringList(QString("标志位:  0x") + QString(tmp) + QString(" 已分片:该数据包不是完整的数据包")));
		}
		sprintf(tmp, "%d", (ih->flags_fo >> 5) & 0x1);
		if((ih->flags_fo >> 5) & 0x1 == 0x1){
			QTreeWidgetItem* ip_sub6_sub1 = new QTreeWidgetItem(ip_sub6, QStringList(QString(tmp) + QString(".. 保留字段: Set")));
		}else
			QTreeWidgetItem* ip_sub6_sub1 = new QTreeWidgetItem(ip_sub6, QStringList(QString(tmp) + QString(".. 保留字段: Not Set")));
		sprintf(tmp, "%d", (ih->flags_fo >> 6) & 0x1);
		if((ih->flags_fo >> 6) & 0x1 == 0x1){
			QTreeWidgetItem* ip_sub6_sub2 = new QTreeWidgetItem(ip_sub6, QStringList(QString(".") + QString(tmp) + QString(". 不分片: Set")));
		}else
			QTreeWidgetItem* ip_sub6_sub2 = new QTreeWidgetItem(ip_sub6, QStringList(QString(".") + QString(tmp) + QString(". 不分片: Not Set")));
		sprintf(tmp, "%d", (ih->flags_fo >> 7) & 0x1);
		if((ih->flags_fo >> 7) & 0x1 == 0x1){
			QTreeWidgetItem* ip_sub6_sub2 = new QTreeWidgetItem(ip_sub6, QStringList(QString("..") + QString(tmp) + QString(" 是否更多分片: Set")));
		}else
			QTreeWidgetItem* ip_sub6_sub2 = new QTreeWidgetItem(ip_sub6, QStringList(QString("..") + QString(tmp) + QString(" 是否更多分片: Not Set")));
		sprintf(tmp, "%d", ih->flags_fo >> 13);
		QTreeWidgetItem* ip_sub7 = new QTreeWidgetItem(branch_ip, QStringList(QString("片偏移: ") + QString(tmp)));
		sprintf(tmp, "%d", ih->ttl);
		QTreeWidgetItem* ip_sub8 = new QTreeWidgetItem(branch_ip, QStringList(QString("生存时间: ") + QString(tmp)));
		if(ih->proto == 1){
			memcpy(tmp,"ICMP",4);
			QTreeWidgetItem* ip_sub9 = new QTreeWidgetItem(branch_ip, QStringList(QString("协议类型: ") + QString(tmp)));
		}else if(ih->proto == 2){
			memcpy(tmp,"IGMP",4);
			QTreeWidgetItem* ip_sub9 = new QTreeWidgetItem(branch_ip, QStringList(QString("协议类型: ") + QString(tmp)));
		}else if(ih->proto == 6){
			memcpy(tmp,"TCP",3);
			tmp[3] = '\0';
			QTreeWidgetItem* ip_sub9 = new QTreeWidgetItem(branch_ip, QStringList(QString("协议类型: ") + QString(tmp)));
		}else if(ih->proto == 17){
			memcpy(tmp,"UDP",3);
			tmp[3] = '\0';
			QTreeWidgetItem* ip_sub9 = new QTreeWidgetItem(branch_ip, QStringList(QString("协议类型: ") + QString(tmp)));
		}
		sprintf(tmp, "%.4X", ntohs(ih->crc));
		QTreeWidgetItem* ip_sub10 = new QTreeWidgetItem(branch_ip, QStringList(QString("检验和: (0x") + QString(tmp) + QString(")")));
		QTreeWidgetItem* ip_sub11 = new QTreeWidgetItem(branch_ip, QStringList(QString("源地址: ") + QString(char_srcip)));
		QTreeWidgetItem* ip_sub12 = new QTreeWidgetItem(branch_ip, QStringList(QString("目的地址: ") + QString(char_dstip)));


		//ICMP分析
		if(ih->proto == 1){
			memcpy(Ethertype,"icmp",4);

			//2018年4月27日16:26:12
			/* 获得ICMP首部的位置 */
			ich = (icmp_header *) ((u_char*)ih + ip_len);

			branch_icmp = new QTreeWidgetItem(tree, QStringList(QString("Internet Control Message Protocol")));
			sprintf(tmp, "%X", ich->type);
			QTreeWidgetItem* icmp_sub1 = new QTreeWidgetItem(branch_icmp, QStringList(QString("类型: (0x") + QString(tmp) + QString(")")));
			sprintf(tmp, "%X", ich->code);
			QTreeWidgetItem* icmp_sub2 = new QTreeWidgetItem(branch_icmp, QStringList(QString("代码: (0x") + QString(tmp) + QString(")")));
			sprintf(tmp, "%X", ntohs(ich->checksum));
			QTreeWidgetItem* icmp_sub3 = new QTreeWidgetItem(branch_icmp, QStringList(QString("校验和: (0x") + QString(tmp) + QString(")")));
			sprintf(tmp, "%X", ich->id);
			QTreeWidgetItem* icmp_sub4 = new QTreeWidgetItem(branch_icmp, QStringList(QString("标识符: (0x") + QString(tmp) + QString(")")));
			sprintf(tmp, "%X", ich->sequence);
			QTreeWidgetItem* icmp_sub5 = new QTreeWidgetItem(branch_icmp, QStringList(QString("序列号: (0x") + QString(tmp) + QString(")")));


		}
		//IGMP分析
		else if(ih->proto == 2){
			memcpy(Ethertype,"igmp",4);

			//2018年4月27日16:31:16
			/* 获得IGMP首部的位置 */
			igh = (igmp_header *) ((u_char*)ih + ip_len);

			branch_igmp = new QTreeWidgetItem(tree, QStringList(QString("Internet Group Manage Protocol")));
			sprintf(tmp, "%d", igh->ver);
			QTreeWidgetItem* igmp_sub1 = new QTreeWidgetItem(branch_igmp, QStringList(QString("版本: ") + QString(tmp)));
			sprintf(tmp, "%d", igh->type);
			QTreeWidgetItem* igmp_sub2 = new QTreeWidgetItem(branch_igmp, QStringList(QString("类型: ") + QString(tmp)));
			sprintf(tmp, "%d", igh->rst);
			QTreeWidgetItem* igmp_sub3 = new QTreeWidgetItem(branch_igmp, QStringList(QString("未用: ") + QString(tmp)));
			sprintf(tmp, "%X", ntohs(igh->checksum));
			QTreeWidgetItem* igmp_sub4 = new QTreeWidgetItem(branch_igmp, QStringList(QString("校验和: (0x") + QString(tmp) + QString(")")));
			sprintf(tmp, "%X", ntohs(igh->add));
			QTreeWidgetItem* igmp_sub5 = new QTreeWidgetItem(branch_igmp, QStringList(QString("地址: (0x") + QString(tmp) + QString(")")));



		}
		//TCP分析
		else if(ih->proto == 6){
			memcpy(Ethertype,"tcp",3);

			/* 获得TCP首部的位置 */
			th = (tcp_header *) ((u_char*)ih + ip_len);

			/* 将网络字节序列转换成主机字节序列 */
			sport = ntohs( th->sport );
			dport = ntohs( th->dport );

			//2018年4月27日16:21:47
			branch_tcp = new QTreeWidgetItem(tree, QStringList(QString("Transmission Control Protocol")));
			sprintf(tmp, "%d", sport);
			QTreeWidgetItem* tcp_sub1 = new QTreeWidgetItem(branch_tcp, QStringList(QString("源端口: ") + QString(tmp)));
			sprintf(tmp, "%d", dport);
			QTreeWidgetItem* tcp_sub2 = new QTreeWidgetItem(branch_tcp, QStringList(QString("目的端口: ") + QString(tmp)));
			sprintf(tmp, "%u", ntohl(th->snum));
			QTreeWidgetItem* tcp_sub3 = new QTreeWidgetItem(branch_tcp, QStringList(QString("序列号: ") + QString(tmp)));
			sprintf(tmp, "%u", ntohl(th->anum));
			QTreeWidgetItem* tcp_sub4 = new QTreeWidgetItem(branch_tcp, QStringList(QString("确认序列号: ") + QString(tmp)));

			sprintf(tmp, "%d", (th->dataoffset >> 4 & 0xf) * 4);   //首部长度
			QTreeWidgetItem* tcp_sub5 = new QTreeWidgetItem(branch_tcp, QStringList(QString("首部长度: ") + QString(tmp) + QString("Bytes")));
			QTreeWidgetItem* tcp_sub6 = new QTreeWidgetItem(branch_tcp, QStringList(QString("标志位")));
			if((th->dataoffset >> 8) & 0x20 == 0x20){          //URG
				QTreeWidgetItem* tcp_sub6_sub1 = new QTreeWidgetItem(tcp_sub6, QStringList(QString("1..... : URG")));
			}else{
				QTreeWidgetItem* tcp_sub6_sub1 = new QTreeWidgetItem(tcp_sub6, QStringList(QString("0..... : URG")));
			}
			if((th->dataoffset >> 8) & 0x10){    //ACK
				QTreeWidgetItem* tcp_sub6_sub2 = new QTreeWidgetItem(tcp_sub6, QStringList(QString(".1.... : ACK")));
			}else{
				QTreeWidgetItem* tcp_sub6_sub2 = new QTreeWidgetItem(tcp_sub6, QStringList(QString(".0.... : ACK")));
			}
			if((th->dataoffset >> 8) & 0x08){    //PSH
				QTreeWidgetItem* tcp_sub6_sub3 = new QTreeWidgetItem(tcp_sub6, QStringList(QString("..1... : PSH")));
			}else{
				QTreeWidgetItem* tcp_sub6_sub3 = new QTreeWidgetItem(tcp_sub6, QStringList(QString("..0... : PSH")));
			}
			if((th->dataoffset >> 8) & 0x04){    //PST
				QTreeWidgetItem* tcp_sub6_sub4 = new QTreeWidgetItem(tcp_sub6, QStringList(QString("...1.. : PST")));
			}else{
				QTreeWidgetItem* tcp_sub6_sub4 = new QTreeWidgetItem(tcp_sub6, QStringList(QString("...0.. : PST")));
			}
			if((th->dataoffset >> 8) & 0x02){    //SYN
				QTreeWidgetItem* tcp_sub6_sub5 = new QTreeWidgetItem(tcp_sub6, QStringList(QString("....1. : SYN")));
			}else{
				QTreeWidgetItem* tcp_sub6_sub5 = new QTreeWidgetItem(tcp_sub6, QStringList(QString("....0. : SYN")));
			}
			if((th->dataoffset >> 8) & 0x01){    //FIN
				QTreeWidgetItem* tcp_sub6_sub5 = new QTreeWidgetItem(tcp_sub6, QStringList(QString(".....1 : FIN")));
			}else{
				QTreeWidgetItem* tcp_sub6_sub5 = new QTreeWidgetItem(tcp_sub6, QStringList(QString(".....0 : FIN")));
			}
			sprintf(tmp, "%d", ntohs(th->windows));
			QTreeWidgetItem* tcp_sub7 = new QTreeWidgetItem(branch_tcp, QStringList(QString("窗口大小: ") + QString(tmp) + QString("Bytes")));
			sprintf(tmp, "%X", ntohs(th->chksum));
			QTreeWidgetItem* tcp_sub8 = new QTreeWidgetItem(branch_tcp, QStringList(QString("校验和: (0x") + QString(tmp) + QString(")")));
			sprintf(tmp, "%X", th->urgentpt);
			QTreeWidgetItem* tcp_sub9 = new QTreeWidgetItem(branch_tcp, QStringList(QString("紧急指针: (0x") + QString(tmp) + QString(")")));


			if(sport == 80 || dport == 80){
				const char* http = (char*)(pkt_data + 54);
				branch_http = new QTreeWidgetItem(tree, QStringList(QString("HyperText Transfer Protocol")));
				QTreeWidgetItem* http_sub1 = new QTreeWidgetItem(branch_http, QStringList(QString(http)));
			}
		}
		//UDP分析
		else if(ih->proto == 17){
			memcpy(Ethertype,"udp",3);
			/* 获得UDP首部的位置 */
			uh = (udp_header *)((u_char*)ih + ip_len);

			/* 将网络字节序列转换成主机字节序列 */
			sport = ntohs( uh->sport );
			dport = ntohs( uh->dport );

			branch_udp = new QTreeWidgetItem(tree, QStringList(QString("User Datagram Protocol")));
			sprintf(tmp, "%d", sport);
			QTreeWidgetItem* udp_sub1 = new QTreeWidgetItem(branch_udp, QStringList(QString("源端口: ") + QString(tmp)));
			sprintf(tmp, "%d", dport);
			QTreeWidgetItem* udp_sub2 = new QTreeWidgetItem(branch_udp, QStringList(QString("目的端口: ") + QString(tmp)));
			sprintf(tmp, "%d", uh->len);
			QTreeWidgetItem* udp_sub3 = new QTreeWidgetItem(branch_udp, QStringList(QString("数据包长度: ") + QString(tmp)));
			sprintf(tmp, "%.4X", uh->crc);
			QTreeWidgetItem* udp_sub4 = new QTreeWidgetItem(branch_udp, QStringList(QString("检验和: (0x") + QString(tmp) + QString(")")));

			if(sport == 53 || dport == 53){
				dh = (dns_header *)((u_char*)ih + ip_len + 8);
				branch_dns = new QTreeWidgetItem(tree, QStringList(QString("Domain Name System")));
				sprintf(tmp, "%X", dh->id);
				QTreeWidgetItem* dns_sub1 = new QTreeWidgetItem(branch_dns, QStringList(QString("标识: (0x") + QString(tmp) + QString(")")));
				sprintf(tmp, "%X", ntohs(dh->flag));
				QTreeWidgetItem* dns_sub2 = new QTreeWidgetItem(branch_dns, QStringList(QString("标志: (0x") + QString(tmp) + QString(")")));
				sprintf(tmp, "%d", ntohs(dh->qnum));
				QTreeWidgetItem* dns_sub3 = new QTreeWidgetItem(branch_dns, QStringList(QString("问题数: ") + QString(tmp)));
				sprintf(tmp, "%d", ntohs(dh->anRR));
				QTreeWidgetItem* dns_sub4 = new QTreeWidgetItem(branch_dns, QStringList(QString("资源记录数: ") + QString(tmp)));
				sprintf(tmp, "%d", ntohs(dh->auRR));
				QTreeWidgetItem* dns_sub5 = new QTreeWidgetItem(branch_dns, QStringList(QString("授权资源记录数: ") + QString(tmp)));
				sprintf(tmp, "%d", ntohs(dh->addRR));
				QTreeWidgetItem* dns_sub6 = new QTreeWidgetItem(branch_dns, QStringList(QString("附加资源记录数: ") + QString(tmp)));

				//取出域名
				u_char * domain_ptr = (u_char *)ih + ip_len + 8 + 12;
				char domain[50];
				int i = 0;
				while(*domain_ptr != 0){
					int num = *domain_ptr;
					domain_ptr++;
					for(int j=0; j < num; j++){
						domain[i++] = *(domain_ptr++);
					}
					domain[i++] = '.';
				}
				domain[i-1] = '\0';

				QTreeWidgetItem* dns_sub7 = new QTreeWidgetItem(branch_dns, QStringList(QString("Queries")));
				//取出域名类型
				QString dns_type;
				u_short Type = ntohs(*(u_short *)(domain_ptr+1));
				u_short Class = ntohs(*(u_short *)(domain_ptr+3));
				QTreeWidgetItem* query_sub1 = new QTreeWidgetItem(dns_sub7, QStringList(QString("Domain Name: ") + QString(domain)));


				if (Type==1) dns_type = QString("A (1)");
				else if (Type==2) dns_type = QString("NS (2)");
				else if (Type==5) dns_type = QString("CNAME (5)");
				else if (Type==6) dns_type = QString("SOA (6)");
				else if (Type==11) dns_type = QString("WKS (11)");
				else if (Type==12) dns_type = QString("PTR (12)");
				else if (Type==13) dns_type = QString("HINFO (13)");
				else if (Type==15) dns_type = QString("MX (15)");
				else if (Type==28) dns_type = QString("AAAA (28)");
				else if (Type==252) dns_type = QString("AXFR (252)");
				else if (Type==255) dns_type = QString("ANY (255)");

				QTreeWidgetItem* query_sub2 = new QTreeWidgetItem(dns_sub7, QStringList(QString("Type: ") + dns_type));

				if(Class == 1)
					QTreeWidgetItem* query_sub3 = new QTreeWidgetItem(dns_sub7, QStringList(QString("Class: ") + QString("IN (0x0001)")));
				else
					QTreeWidgetItem* query_sub3 = new QTreeWidgetItem(dns_sub7, QStringList(QString("Class: ") + QString::number(Class)));

				int rnum = ntohs(dh->anRR) + ntohs(dh->auRR) + ntohs(dh->addRR);
				for(int i = 0; i < rnum;){
					if(i < ntohs(dh->anRR)){
						QTreeWidgetItem* dns_sub8 = new QTreeWidgetItem(branch_dns, QStringList(QString("Answer")));
						for(; i<ntohs(dh->anRR); i++){

						}

					}else if(i == ntohs(dh->anRR)){
						QTreeWidgetItem* dns_sub8 = new QTreeWidgetItem(branch_dns, QStringList(QString("Authoritative nameservers")));
						for(; i<ntohs(dh->anRR) + ntohs(dh->auRR); i++){

						}

					}else if(i == (ntohs(dh->anRR) + ntohs(dh->auRR))){
						QTreeWidgetItem* dns_sub8 = new QTreeWidgetItem(branch_dns, QStringList(QString("Addtional records")));
						for(; i<rnum; i++){

						}
					}
				}
			}
		}
	}
	//arp报文分析
	else if(ethertype == 0x0806){
		memcpy(Ethertype,"arp",3);
		QTreeWidgetItem* ether_sub3 = new QTreeWidgetItem(branch_ethernet, QStringList(QString("协议类型: ARP (0x0806)")));

		//获得arp数据包头部地址
		ah = (arp_header*)(pkt_data +
						   14);//以太网头部长度

		sprintf(char_srcip,"%d.%d.%d.%d",
				ah->srcip.byte1,
				ah->srcip.byte2,
				ah->srcip.byte3,
				ah->srcip.byte4);
		sprintf(char_dstip,"%d.%d.%d.%d",
				ah->dstip.byte1,
				ah->dstip.byte2,
				ah->dstip.byte3,
				ah->dstip.byte4);

		//2018年4月27日10:19:52
		branch_arp = new QTreeWidgetItem(tree, QStringList(QString("Address Resolution Protocol")));
		if(ah->HardwareType >> 8 == 0x1){      //硬件类型
			QTreeWidgetItem* arp_sub1 = new QTreeWidgetItem(branch_arp, QStringList(QString("硬件类型: 以太网")));
		}else{
			sprintf(tmp, "%.4X", ah->HardwareType);
			QTreeWidgetItem* arp_sub1 = new QTreeWidgetItem(branch_arp, QStringList(QString("硬件类型: (0x") + QString(tmp) + QString(")")));
		}
		if(ah->ProtocolType == 0x8){      //协议类型
			QTreeWidgetItem* arp_sub2 = new QTreeWidgetItem(branch_arp, QStringList(QString("协议类型: IP(0x0800)")));
		}else{
			sprintf(tmp, "%.4X", ah->HardwareType);
			QTreeWidgetItem* arp_sub2 = new QTreeWidgetItem(branch_arp, QStringList(QString("协议类型: (0x") + QString(tmp) + QString(")")));
		}
		sprintf(tmp, "%d",ah->HardwareAddLen);   //硬件地址长度
		QTreeWidgetItem* arp_sub3 = new QTreeWidgetItem(branch_arp, QStringList(QString("硬件地址长度: ") + QString(tmp)));
		sprintf(tmp, "%d",ah->ProtocolAddLen);   //协议地址长度
		QTreeWidgetItem* arp_sub4 = new QTreeWidgetItem(branch_arp, QStringList(QString("协议地址长度: ") + QString(tmp)));
		if(ah->OperationField >> 8 == 0x1){        //操作类型
			QTreeWidgetItem* arp_sub5 = new QTreeWidgetItem(branch_arp, QStringList(QString("操作: 请求报文")));
		}else if(ah->OperationField >> 8 == 0x2){
			QTreeWidgetItem* arp_sub5 = new QTreeWidgetItem(branch_arp, QStringList(QString("操作: 响应报文")));
		}
		//地址显示
		char tmp_add[50] = "";
		sprintf(tmp_add,"%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
				ah->srcmac.byte1,
				ah->srcmac.byte2,
				ah->srcmac.byte3,
				ah->srcmac.byte4,
				ah->srcmac.byte5,
				ah->srcmac.byte6);
		QTreeWidgetItem* arp_sub6 = new QTreeWidgetItem(branch_arp, QStringList(QString("源MAC: ") + QString(tmp_add)));
		sprintf(tmp_add,"%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
				ah->dstmac.byte1,
				ah->dstmac.byte2,
				ah->dstmac.byte3,
				ah->dstmac.byte4,
				ah->dstmac.byte5,
				ah->dstmac.byte6);
		QTreeWidgetItem* arp_sub7 = new QTreeWidgetItem(branch_arp, QStringList(QString("目的MAC: ") + QString(tmp_add)));
		sprintf(tmp_add,"%d.%d.%d.%d",
				ah->srcip.byte1,
				ah->srcip.byte2,
				ah->srcip.byte3,
				ah->srcip.byte4);
		QTreeWidgetItem* arp_sub8 = new QTreeWidgetItem(branch_arp, QStringList(QString("源IP: ") + QString(tmp_add)));
		sprintf(tmp_add,"%d.%d.%d.%d",
				ah->dstip.byte1,
				ah->dstip.byte2,
				ah->dstip.byte3,
				ah->dstip.byte4);
		QTreeWidgetItem* arp_sub9 = new QTreeWidgetItem(branch_arp, QStringList(QString("目的IP: ") + QString(char_dstip)));
	}
}


void MainWindow::on_comboBox_NIC_currentTextChanged(const QString &arg1)
{
    NIC_name = ui->comboBox_NIC->currentText();        //给全局变量设置网卡名称
}
