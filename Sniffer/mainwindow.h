#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QDebug>
#include "filterwidget.h"
#include "arpwidget.h"
#include "capture_thread.h"
#include "string"

namespace Ui {
	class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
	explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
	void on_actionStart_triggered();
	void on_comboBox_NIC_currentTextChanged();
	void on_actionFilter_jump_triggered();
	void on_actionStop_triggered();
	void on_actionClear_triggered();
	//时间、长度、类型、源mac,目的mac，源ip，目的ip， offset
	void receive_packet(char *, int, const u_char*);
	//过滤的数据包类型*5，源ip地址，源端口，目的ip地址，目的端口, 自定义过滤器
	void filter_receive(std::string, std::string, std::string, std::string, std::string,
						std::string, std::string, std::string, std::string, std::string);
	void on_tableWidget_itemClicked();
	void on_actionARP_triggered();
    void on_comboBox_NIC_currentTextChanged(const QString &arg1);

private:
	Ui::MainWindow *ui;
	CaptureThread * capturethread = new CaptureThread();
	FilterWidget * flt = new FilterWidget();    //新界面
	arpwidget * arp = new arpwidget();
	void Designer(); //界面中一些宽度和长度的设计
	void set_comboBox_NIC();   //填充comboBox_NIC中的值
	std::string string_filter;  //临时保存过滤器
};

#endif // MAINWINDOW_H
