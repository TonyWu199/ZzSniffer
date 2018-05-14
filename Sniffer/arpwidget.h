#ifndef ARPWIDGET_H
#define ARPWIDGET_H

#include "QWidget"

namespace Ui {
	class arpwidget;
}

class arpwidget : public QWidget
{
	Q_OBJECT

public:
	explicit arpwidget(QWidget *parent = nullptr);
	~arpwidget();

private slots:
	void on_pushButton_clicked();

private:
	Ui::arpwidget *ui;
};

#endif // ARPWIDGET_H
