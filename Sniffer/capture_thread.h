#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H
#include <QThread>
#include "winsock2.h"
#include "dataType.h"

class CaptureThread:public QThread
{
	   Q_OBJECT
public:
	   CaptureThread();
	   ~CaptureThread();
	   void set_NIC(const char * NIC);
	   void set_filter(const char * filter);

protected:
	   void run();

private:
	   const char * char_NIC;
	   const char * char_filter;

signals:
	   //时间、长度、类型、源mac,目的mac，源ip，目的ip, offset
	   void send_packet(char *, int, const u_char*);

};

#endif // CAPTURETHREAD_H
