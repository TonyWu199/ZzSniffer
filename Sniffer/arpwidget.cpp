#include "arpwidget.h"
#include "arpspoofing.h"
#include "ui_arpwidget.h"

extern QString NIC_name;

arpwidget::arpwidget(QWidget *parent) :
	QWidget(parent),
	ui(new Ui::arpwidget)
{
	ui->setupUi(this);
}

arpwidget::~arpwidget()
{
	delete ui;
}

void arpwidget::on_pushButton_clicked()
{
	Send_ARP(ui->host_mac->text(),
			 ui->host_ip->text(),
			 ui->router_mac->text(),
			 ui->router_ip->text(),
			 ui->target_mac->text(),
			 ui->target_ip->text(),
			 NIC_name);
}
