#include "mainwindow.h"
#include "ui_mainwindow.h"
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
