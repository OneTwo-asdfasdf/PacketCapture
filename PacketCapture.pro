#-------------------------------------------------
#
# Project created by QtCreator 2016-07-08T17:38:40
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = PacketCapture
TEMPLATE = app

LIBS += -lpcap
SOURCES += main.cpp\
        mainwindow.cpp

HEADERS  += mainwindow.h

FORMS    += mainwindow.ui
