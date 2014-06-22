#ifndef THREADGET_H
#define THREADGET_H

#include <QThread>
#include <stdio.h>

class ThreadGet : public QThread
{
    Q_OBJECT
public:
    explicit ThreadGet(QObject *parent = 0);
    virtual ~ThreadGet();
    
    void setNetSniffer(int read_fd);

signals:
    void sigGetData(QString data);
    
public slots:
    void stopThread();
    void startThread();

protected:
    void run();

private://function
    void _getData();

private://data
    volatile bool _running;
    int _read_fd;
    
};

#endif // THREADGET_H
