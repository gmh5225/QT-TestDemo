#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <Windows.h>
#include <QMessageBox>
#include <QTextCodec>

typedef __success(return >= 0) LONG NTSTATUS;

#ifndef NT_STATUS_OK
#define NT_STATUS_OK 0
#endif

#define STATUS_SUCCESS ((NTSTATUS) 0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS) 0xC0000001)
#define STATUS_PROCEDURE_NOT_FOUND ((NTSTATUS) 0xC000007A)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS) 0xC0000004)
#define STATUS_NOT_FOUND ((NTSTATUS) 0xC0000225)
#define STATUS_THREAD_IS_TERMINATING ((NTSTATUS) 0xc000004b)
#define STATUS_NOT_SUPPORTED ((NTSTATUS) 0xC00000BB)

enum LDR_DLL_NOTIFICATION_REASON {
    LDR_DLL_NOTIFICATION_REASON_LOADED = 1,
    LDR_DLL_NOTIFICATION_REASON_UNLOADED = 2,
};

typedef struct tag_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} __UNICODE_STRING, *PUNICODE_STRING, *PCUNICODE_STRING;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA
{
    ULONG Flags;                  //Reserved.
    PCUNICODE_STRING FullDllName; //The full path name of the DLL module.
    PCUNICODE_STRING BaseDllName; //The base file name of the DLL module.
    PVOID DllBase;                //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;            //The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA
{
    ULONG Flags;                  //Reserved.
    PCUNICODE_STRING FullDllName; //The full path name of the DLL module.
    PCUNICODE_STRING BaseDllName; //The base file name of the DLL module.
    PVOID DllBase;                //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;            //The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID(NTAPI *PLDR_DLL_NOTIFICATION_FUNCTION)(_In_ ULONG NotificationReason,
                                                    _In_ PLDR_DLL_NOTIFICATION_DATA NotificationData,
                                                    _In_opt_ PVOID Context);

typedef NTSTATUS(NTAPI *_LdrRegisterDllNotification)(_In_ ULONG Flags,
                                                     _In_ PLDR_DLL_NOTIFICATION_FUNCTION
                                                         NotificationFunction,
                                                     _In_opt_ PVOID Context,
                                                     _Out_ PVOID *Cookie);

typedef NTSTATUS(NTAPI *_LdrUnregisterDllNotification)(_In_ PVOID Cookie);

int gv = 0;
Ui::MainWindow *g_ui;

_LdrRegisterDllNotification LdrRegisterDllNotification = NULL;
_LdrUnregisterDllNotification LdrUnregisterDllNotifcation = NULL;
PVOID Cookie = NULL;

BOOL GetNtFunctions()
{
    HMODULE hNtDll;
    if (!(hNtDll = GetModuleHandleA("ntdll.dll"))) {
        return FALSE;
    }
    LdrRegisterDllNotification = (_LdrRegisterDllNotification)
        GetProcAddress(hNtDll, "LdrRegisterDllNotification");
    LdrUnregisterDllNotifcation = (_LdrUnregisterDllNotification)
        GetProcAddress(hNtDll, "LdrUnregisterDllNotification");
    if (!LdrRegisterDllNotification || !LdrUnregisterDllNotifcation)
        return FALSE;

    return TRUE;
}

void NTAPI MyDllNotification(ULONG Reason,
                             PLDR_DLL_NOTIFICATION_DATA NotificationData,
                             PVOID Context)
{
    //Check for the reason
    switch (Reason) {
        //LDR_DLL_NOTIFICATION_REASON_LOADED
    case LDR_DLL_NOTIFICATION_REASON_LOADED: {
        wchar_t message[500] = {0};
        swprintf(message, L"DLL was loaded event for %wZ\n", (NotificationData->Loaded.FullDllName));
        std::wstring wstrmsg(message);
        std::string strmsg(wstrmsg.begin(), wstrmsg.end());
        g_ui->textEdit_2->append(strmsg.c_str());
        break;
    }
        //LDR_DLL_NOTIFICATION_REASON_UNLOADED
    case LDR_DLL_NOTIFICATION_REASON_UNLOADED: {
        wchar_t message[500] = {0};
        swprintf(message,
                 L"DLL was unloaded event for %wZ\n",
                 (NotificationData->Unloaded.FullDllName));
        std::wstring wstrmsg(message);
        std::string strmsg(wstrmsg.begin(), wstrmsg.end());
        g_ui->textEdit_2->append(strmsg.c_str());
        break;
    }
    default:
        return;
    }
}

void MainWindow::my_pushButton_qt5_clicked()
{
    QMessageBox::information(nullptr, "qt5", "qt5");
}

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    g_ui = ui;
    ui->setupUi(this);

    size_t addr = (size_t) &gv;
    QString qstrgvaddr = QString("%1").arg(addr, sizeof(size_t) * 2, 16, QChar('0').toUpper());
    ui->textEdit->setPlainText(qstrgvaddr);

    GetNtFunctions();
    LdrRegisterDllNotification(0, &MyDllNotification, NULL, &Cookie);

    connect(ui->pushButton_qt5, &QPushButton::clicked, this, &MainWindow::my_pushButton_qt5_clicked);
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

void MainWindow::on_pushButton_8_clicked()
{
    MessageBoxA(0, "123", "456", 0);
}

void MainWindow::on_pushButton_9_clicked()
{
    MessageBoxW(0, L"AAA", L"BBB", 0);
}

void MainWindow::on_pushButton_10_clicked()
{
    QTextCodec *codec = QTextCodec::codecForName("UTF-8");
    QString str = codec->toUnicode("很好"); //2

    wchar_t wstr[300] = {0};
    str.toWCharArray(wstr);
    std::wstring wwstr(wstr);
    QString qqqstr = QString::fromStdWString(wwstr);

    MessageBoxA(0, qqqstr.toStdString().c_str(), qqqstr.toStdString().c_str(), 0);

    //    MessageBoxA(0,
    //                QString::fromUtf8("很好").toStdString().c_str(),
    //                QString::fromUtf8("很好").toStdString().c_str(),
    //                0);
}

void MainWindow::on_pushButton_11_clicked()
{
    QTextCodec *codec = QTextCodec::codecForName("UTF-8");
    QString str = codec->toUnicode("你好"); //2

    MessageBoxW(0, str.toStdWString().c_str(), str.toStdWString().c_str(), 0);

    //    MessageBoxW(0,
    //                QString::fromUtf8("你好").toStdWString().c_str(),
    //                QString::fromUtf8("你好").toStdWString().c_str(),
    //                0);
}
