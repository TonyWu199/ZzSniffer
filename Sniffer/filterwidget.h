#ifndef FILTER_H
#define FILTER_H

#include <QWidget>
#include "string"

namespace Ui {
	class FilterWidget;
}

class FilterWidget : public QWidget
{
	Q_OBJECT

public:
	explicit FilterWidget(QWidget *parent = nullptr);
	~FilterWidget();

signals:
	//过滤的数据包类型*5，源ip地址，源端口，目的ip地址，目的端口, 自定义过滤器
	void filter_set(std::string, std::string, std::string, std::string, std::string,
					std::string, std::string, std::string, std::string, std::string);

public slots:

private slots:
	void on_pushButton_clicked();
//	void on_checkBox_tcp_stateChanged();
//	void on_checkBox_udp_stateChanged();
//	void on_checkBox_arp_stateChanged();
//	void on_checkBox_igmp_stateChanged();
//	void on_checkBox_icmp_stateChanged();

private:
	Ui::FilterWidget *ui;
};

#endif // FILTER_H
