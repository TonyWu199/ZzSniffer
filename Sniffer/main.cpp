#include "mainwindow.h"
#include <QApplication>
#include "iostream"
#include "capture_thread.h"


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
	w.setWindowTitle("Zz Sniffer");
    w.show();

    return a.exec();
}


