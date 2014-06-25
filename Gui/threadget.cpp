#include "threadget.h"

ThreadGet::ThreadGet(QObject *parent) :
    QThread(parent),
    _running(false),
    _read_fd(-1)
{
}

ThreadGet::~ThreadGet()
{
}

void ThreadGet::startThread()
{
    _running = true;
    start();
}

void ThreadGet::stopThread()
{
    _running = false;
    exit();
    _read_fd = -1;
}

void ThreadGet::setNetSniffer(int read_fd)
{
    _read_fd = read_fd;
}

void ThreadGet::run()
{
    if(_read_fd == -1)
        return;
    _getData();
}

void ThreadGet::_getData()
{
    const int buf_size = 127;
    while(_running)
    {
        char buffer[buf_size+1] = {0};
        int bytes = read(_read_fd, buffer, buf_size);
        if(bytes > 0)
        {
            buffer[bytes] = 0;
            QString txt = QString(buffer);
            emit sigGetData(txt);
        }
    }
}


