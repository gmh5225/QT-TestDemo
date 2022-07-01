#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <Windows.h>
#include <QMessageBox>

int gv = 0;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
      , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    size_t addr = (size_t) &gv;
    QString qstrgvaddr = QString("%1").arg(addr, sizeof(size_t) * 2, 16, QChar('0').toUpper());
    ui->textEdit->setPlainText(qstrgvaddr);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
    QMessageBox::information(nullptr, "123", "456");
}

void MainWindow::on_pushButton_2_clicked()
{
    QMessageBox::information(nullptr, "789", "ABC");
}

void MainWindow::on_pushButton_3_clicked()
{
    gv = 1;
}

void MainWindow::on_pushButton_4_clicked()
{
    gv = 2;
}

void MainWindow::on_pushButton_5_clicked()
{
    int a = gv;
    QString qstr = QString("%1").arg(a, sizeof(int) * 2, 16, QChar('0').toUpper());
    QMessageBox::information(nullptr, qstr, qstr);
}

void MainWindow::on_pushButton_6_clicked()
{
    float x = 1.1;
    float y = 1.2;
    float z = x + y;
    auto qstr = QString::number(z);
    QMessageBox::information(nullptr, qstr, qstr);
}

LONG NTAPI VehExceptionHandler(EXCEPTION_POINTERS *ExceptionInfo)
{
    //......
    return EXCEPTION_CONTINUE_SEARCH;
}

void MainWindow::on_pushButton_7_clicked()
{
    //install veh
    auto ptr = AddVectoredExceptionHandler(TRUE, VehExceptionHandler);
    if (ptr) {
        QMessageBox::information(nullptr, "veh ok", "veh ok");
    } else {
        QMessageBox::information(nullptr, "veh failed", "veh failed");
    }
}
