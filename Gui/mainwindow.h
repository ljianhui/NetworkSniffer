#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <unistd.h>
#include <stdio.h>
#include "threadget.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

public slots:
    void viewResult(QString txt);
    void resetFilter(int index);
    void startAnalysis();
    void stopAnalysis();
    void clearView();
    
private:
    void _addItems();
    bool _createPipe();

    Ui::MainWindow *ui;
    pid_t _sniffer_id;
    int _pipes[2];
    bool _running;
    ThreadGet _thread;
};

#endif // MAINWINDOW_H
