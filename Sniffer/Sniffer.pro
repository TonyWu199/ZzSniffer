#-------------------------------------------------
#
# Project created by QtCreator 2018-04-16T15:46:51
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Sniffer
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        mainwindow.cpp \
    capture_thread.cpp \
    filterwidget.cpp \
    arpwidget.cpp

HEADERS += \
        mainwindow.h \
    utils.h \
    capture_thread.h \
    filterwidget.h \
    dataType.h \
    arpwidget.h \
    arpspoofing.h

FORMS += \
        mainwindow.ui \
    filtewidget.ui \
    arpwidget.ui


#INCLUDEPATH += C:\Qt\Qt5.10.1\Tools\mingw530_32\include
#LIBS += C:\Qt\Qt5.10.1\Tools\mingw530_32\lib\wpcap.lib
#LIBS += C:\Qt\Qt5.10.1\Tools\mingw530_32\lib\Packet.lib
#LIBS += -lws2_32
LIBS += \
        C:\Lib\WpdPack_4_1_2\WpdPack\Lib\Packet.lib \
    C:\Lib\WpdPack_4_1_2\WpdPack\Lib\wpcap.lib -lws2_32  #-lws2_32为了能够使用u_char

DISTFILES +=
