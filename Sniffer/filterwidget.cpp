#include "filterwidget.h"
#include "ui_filtewidget.h"
#include "QDebug"
#include "string"

FilterWidget::FilterWidget(QWidget *parent) :
	QWidget(parent),
	ui(new Ui::FilterWidget)
{
	ui->setupUi(this);
}

FilterWidget::~FilterWidget()
{
	delete ui;
}

void FilterWidget::on_pushButton_clicked()
{
	std::string choose_tcp = "";
	std::string choose_udp = "";
	std::string choose_arp = "";
	std::string choose_igmp = "";
	std::string choose_icmp = "";

	if(ui->checkBox_tcp->isChecked()){
		choose_tcp = "tcp";
	}
	if(ui->checkBox_udp->isChecked()){
		choose_udp = "udp";
	}
	if(ui->checkBox_arp->isChecked()){
		choose_arp = "arp";
	}
	if(ui->checkBox_igmp->isChecked()){
		choose_igmp = "igmp";
	}
	if(ui->checkBox_icmp->isChecked()){
		choose_icmp = "icmp";
	}

	std::string srcip = ui->lineEdit_srcip->text().toStdString();
	std::string srcport = ui->lineEdit_srcport->text().toStdString();
	std::string dstip = ui->lineEdit_dstip->text().toStdString();
	std::string dstport = ui->lineEdit_dstport->text().toStdString();
	std::string custom = ui->lineEdit_filter->text().toStdString();

	emit filter_set(choose_tcp, choose_udp, choose_arp, choose_igmp, choose_icmp,
					srcip, srcport, dstip, dstport, custom);
}

////勾选之后不能再勾选其他框
//void FilterWidget::on_checkBox_tcp_stateChanged()
//{
//	if(ui->checkBox_tcp->isChecked()){
//		ui->checkBox_udp->setEnabled(false);
//		ui->checkBox_arp->setEnabled(false);
//		ui->checkBox_igmp->setEnabled(false);
//		ui->checkBox_icmp->setEnabled(false);
//		ui->lineEdit_filter->setEnabled(false);
//	}
//	else{
//		ui->checkBox_udp->setEnabled(true);
//		ui->checkBox_arp->setEnabled(true);
//		ui->checkBox_igmp->setEnabled(true);
//		ui->checkBox_icmp->setEnabled(true);
//		ui->lineEdit_filter->setEnabled(true);
//	}
//}

//void FilterWidget::on_checkBox_udp_stateChanged()
//{
//	if(ui->checkBox_udp->isChecked()){
//		ui->checkBox_tcp->setEnabled(false);
//		ui->checkBox_arp->setEnabled(false);
//		ui->checkBox_igmp->setEnabled(false);
//		ui->checkBox_icmp->setEnabled(false);
//		ui->lineEdit_filter->setEnabled(false);
//	}
//	else{
//		ui->checkBox_tcp->setEnabled(true);
//		ui->checkBox_arp->setEnabled(true);
//		ui->checkBox_igmp->setEnabled(true);
//		ui->checkBox_icmp->setEnabled(true);
//		ui->lineEdit_filter->setEnabled(true);
//	}
//}

//void FilterWidget::on_checkBox_arp_stateChanged()
//{
//	if(ui->checkBox_arp->isChecked()){
//		ui->checkBox_tcp->setEnabled(false);
//		ui->checkBox_udp->setEnabled(false);
//		ui->checkBox_igmp->setEnabled(false);
//		ui->checkBox_icmp->setEnabled(false);
//		ui->lineEdit_filter->setEnabled(false);
//	}
//	else{
//		ui->checkBox_tcp->setEnabled(true);
//		ui->checkBox_udp->setEnabled(true);
//		ui->checkBox_igmp->setEnabled(true);
//		ui->checkBox_icmp->setEnabled(true);
//		ui->lineEdit_filter->setEnabled(true);
//	}
//}

//void FilterWidget::on_checkBox_igmp_stateChanged()
//{
//	if(ui->checkBox_igmp->isChecked()){
//		ui->checkBox_tcp->setEnabled(false);
//		ui->checkBox_udp->setEnabled(false);
//		ui->checkBox_arp->setEnabled(false);
//		ui->checkBox_icmp->setEnabled(false);
//		ui->lineEdit_filter->setEnabled(false);
//	}
//	else{
//		ui->checkBox_tcp->setEnabled(true);
//		ui->checkBox_udp->setEnabled(true);
//		ui->checkBox_arp->setEnabled(true);
//		ui->checkBox_icmp->setEnabled(true);
//		ui->lineEdit_filter->setEnabled(true);
//	}
//}

//void FilterWidget::on_checkBox_icmp_stateChanged()
//{
//	if(ui->checkBox_icmp->isChecked()){
//		ui->checkBox_tcp->setEnabled(false);
//		ui->checkBox_udp->setEnabled(false);
//		ui->checkBox_arp->setEnabled(false);
//		ui->checkBox_igmp->setEnabled(false);
//		ui->lineEdit_filter->setEnabled(false);
//	}
//	else{
//		ui->checkBox_tcp->setEnabled(true);
//		ui->checkBox_udp->setEnabled(true);
//		ui->checkBox_arp->setEnabled(true);
//		ui->checkBox_igmp->setEnabled(true);
//	}
//}
