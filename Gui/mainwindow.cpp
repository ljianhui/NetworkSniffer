#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string>
#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    _sniffer_id(-1),
    _running(false)
{
    ui->setupUi(this);

    _pipes[0] = -1;
    _pipes[1] = -1;

    _addItems();

    ui->btn_stop->setEnabled(false);
    ui->edt_view->setLineWrapMode(QTextEdit::NoWrap);

    connect(ui->btn_start, SIGNAL(clicked()),
            this, SLOT(startAnalysis()));
    connect(ui->btn_stop, SIGNAL(clicked()),
            this, SLOT(stopAnalysis()));
    connect(ui->cbb_interface, SIGNAL(currentIndexChanged(int)),
            this, SLOT(resetFilter(int)));
    connect(ui->cbb_filter, SIGNAL(currentIndexChanged(int)),
            this, SLOT(resetFilter(int)));
    connect(&_thread, SIGNAL(sigGetData(QString)),
            this, SLOT(viewResult(QString)));
    connect(ui->btn_clear, SIGNAL(clicked()),
            this, SLOT(clearView()));
}

MainWindow::~MainWindow()
{
    delete ui;

    if(_sniffer_id != -1)
    {
        int status = 0;
        kill(_sniffer_id, SIGTERM);
        waitpid(_sniffer_id, &status, 0);

    }

    if(_pipes[0] != -1)
        ::close(_pipes[0]);

    _thread.stopThread();
    _thread.wait();
}

void MainWindow::resetFilter(int index)
{
    if(_running)
    {
        stopAnalysis();
        startAnalysis();
    }
    ui->statusBar->showMessage("recent action: reset filter");
}

void MainWindow::startAnalysis()
{
    if(_running == true)
        return;

    if(_createPipe() == false)
        return;

    _thread.setNetSniffer(_pipes[0]);
    _thread.startThread();
    _running = true;

    ui->btn_start->setEnabled(false);
    ui->btn_stop->setEnabled(true);
    ui->statusBar->showMessage("recent action: start analysis");
}

void MainWindow::stopAnalysis()
{
    if(_running == false)
        return;

    kill(_sniffer_id, SIGTERM);
    int status = 0;
    waitpid(_sniffer_id, &status, 0);
    _sniffer_id = -1;

    _thread.stopThread();
    _thread.wait();

    _running = false;

    ui->btn_start->setEnabled(true);
    ui->btn_stop->setEnabled(false);
    ui->statusBar->showMessage("recent action: stop analysis");
}

void MainWindow::viewResult(QString txt)
{
    ui->edt_view->insertPlainText(txt);
    ui->edt_view->moveCursor(QTextCursor::End);
}

void MainWindow::clearView()
{
    ui->edt_view->clear();
    ui->statusBar->showMessage("recent action: clear view");
}

void MainWindow::_addItems()
{
    ui->cbb_interface->addItem("");
    ui->cbb_interface->addItem("eth0");
    ui->cbb_interface->addItem("lo");
    ui->cbb_filter->addItem("null");
    ui->cbb_filter->addItem("ethernet");
    ui->cbb_filter->addItem("arp");
    ui->cbb_filter->addItem("ip");
    ui->cbb_filter->addItem("icmp");
    ui->cbb_filter->addItem("tcp");
    ui->cbb_filter->addItem("udp");
}

bool MainWindow::_createPipe()
{
    if(_sniffer_id != -1)
    {
        int status = 0;
        kill(_sniffer_id, SIGTERM);
        waitpid(_sniffer_id, &status, 0);
    }

    const char *args[6] = {0};
    int i = 0;

    args[i++] = "./netsniffer";

    std::string select = ui->cbb_interface->currentText().toStdString();
    if(select != "")
    {
        args[i++] = "-i";
        args[i++] = select.c_str();
    }

    select = ui->cbb_filter->currentText().toStdString();
    if(select != "null")
    {
        args[i++] = "-p";
        args[i++] = select.c_str();
    }
    args[i++] = NULL;

    if(_pipes[0] != -1)
    {
        ::close(_pipes[0]);//close read pipe
        _pipes[0] = -1;
    }

    int ret = pipe(_pipes);
    if(ret != 0)
        return false;

    _sniffer_id = fork();
    if(_sniffer_id == 0)
    {
        //child - write data
        ::close(1);//close stdin
        dup(_pipes[1]);//stdin to pipes[1]
        ::close(_pipes[0]);
        ::close(_pipes[1]);
        execvp(args[0], (char*const*)args);
        return false;
    }
    else
    {
        //parent - read data and view
        ::close(_pipes[1]);
        _pipes[1] = -1;
    }
    return true;
}
