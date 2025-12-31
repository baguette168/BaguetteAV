#include "pch.h"
#include "framework.h"
#include "BaguetteAV.h"
#include "BaguetteAVDlg.h"
#include "afxdialogex.h"
#include <ShlObj.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define WM_LOG_MESSAGE (WM_USER + 100)
#define WM_SCAN_COMPLETE (WM_USER + 101)
#define WM_UPDATE_PROGRESS (WM_USER + 102)

CBaguetteAVDlg::CBaguetteAVDlg(CWnd* pParent)
    : CDialogEx(IDD_BAGUETTEAV_DIALOG, pParent)
{
    m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CBaguetteAVDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_LIST_LOG, m_LogList);
    DDX_Control(pDX, IDC_BTN_FULLSCAN, m_btnFullScan);
    DDX_Control(pDX, IDC_BTN_CUSTOMSCAN, m_btnCustomScan);
    DDX_Control(pDX, IDC_BTN_STOP, m_btnStop);
    DDX_Control(pDX, IDC_BTN_ROOTKIT, m_btnRootkit);
    DDX_Control(pDX, IDC_PROGRESS, m_Progress);
    DDX_Control(pDX, IDC_TXT_ENGINESTATUS, m_txtEngineStatus);
    DDX_Control(pDX, IDC_TXT_RUNTIMESTATUS, m_txtRuntimeStatus);
}

BEGIN_MESSAGE_MAP(CBaguetteAVDlg, CDialogEx)
    ON_WM_PAINT()
    ON_WM_QUERYDRAGICON()
    ON_WM_DESTROY()
    ON_WM_CLOSE()
    ON_BN_CLICKED(IDC_BTN_FULLSCAN, &CBaguetteAVDlg::OnBnClickedBtnFullscan)
    ON_BN_CLICKED(IDC_BTN_CUSTOMSCAN, &CBaguetteAVDlg::OnBnClickedBtnCustomscan)
    ON_BN_CLICKED(IDC_BTN_STOP, &CBaguetteAVDlg::OnBnClickedBtnStop)
    ON_BN_CLICKED(IDC_BTN_ROOTKIT, &CBaguetteAVDlg::OnBnClickedBtnRootkit)
    ON_MESSAGE(WM_LOG_MESSAGE, &CBaguetteAVDlg::OnLogMessage)
    ON_MESSAGE(WM_SCAN_COMPLETE, &CBaguetteAVDlg::OnScanComplete)
    ON_MESSAGE(WM_UPDATE_PROGRESS, &CBaguetteAVDlg::OnUpdateProgress)
END_MESSAGE_MAP()

std::string CBaguetteAVDlg::GetExeDirectory()
{
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string fullPath(path);
    size_t pos = fullPath.find_last_of("\\/");
    return fullPath.substr(0, pos);
}

void CBaguetteAVDlg::Log(const CString& msg)
{
    m_LogList.AddString(msg);
    m_LogList.SetCurSel(m_LogList.GetCount() - 1);
}

LRESULT CBaguetteAVDlg::OnLogMessage(WPARAM wParam, LPARAM lParam)
{
    CString* pMsg = (CString*)wParam;
    if (pMsg) {
        m_LogList.AddString(*pMsg);
        m_LogList.SetCurSel(m_LogList.GetCount() - 1);
        delete pMsg;
    }
    return 0;
}

LRESULT CBaguetteAVDlg::OnScanComplete(WPARAM wParam, LPARAM lParam)
{
    EnableScanButtons(true);
    m_txtRuntimeStatus.SetWindowText(_T("就绪"));
    m_Progress.SetPos(100);
    return 0;
}

LRESULT CBaguetteAVDlg::OnUpdateProgress(WPARAM wParam, LPARAM lParam)
{
    int percent = (int)wParam;
    m_Progress.SetPos(percent);
    return 0;
}

void CBaguetteAVDlg::EnableScanButtons(bool enable)
{
    m_btnFullScan.EnableWindow(enable);
    m_btnCustomScan.EnableWindow(enable);
    m_btnRootkit.EnableWindow(enable);
    m_btnStop.EnableWindow(!enable);
}

void CBaguetteAVDlg::InitializeClamAV()
{
    m_txtEngineStatus.SetWindowText(_T("正在初始化... "));

    std::string dbPath = GetExeDirectory() + "\\database";

    m_clamav = std::make_unique<ClamAVWrapper>(dbPath, &m_LogList);

    if (m_clamav->Initialize())
    {
        m_txtEngineStatus.SetWindowText(_T("保护已开启"));
        m_scanManager = std::make_unique<ScanManager>(m_clamav.get(), &m_LogList);
        m_rootkitDetector = std::make_unique<RootkitDetector>(&m_LogList);
        Log(_T("[状态] BaguetteAV 已就绪"));
    }
    else
    {
        m_txtEngineStatus.SetWindowText(_T("引擎加载失败"));
        EnableScanButtons(false);
        m_btnStop.EnableWindow(FALSE);
    }
}

BOOL CBaguetteAVDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();

    SetIcon(m_hIcon, TRUE);
    SetIcon(m_hIcon, FALSE);

    SetWindowText(_T("BaguetteAV 安全中心"));

    m_btnStop.EnableWindow(FALSE);
    m_Progress.SetRange(0, 100);
    m_Progress.SetPos(0);
    m_txtRuntimeStatus.SetWindowText(_T("就绪"));

    // 居中显示
    CenterWindow();

    InitializeClamAV();

    return TRUE;
}

void CBaguetteAVDlg::OnClose()
{
    OnDestroy();
    EndModalLoop(IDCANCEL);
}

void CBaguetteAVDlg::OnCancel()
{
    OnClose();
}

void CBaguetteAVDlg::OnDestroy()
{
    if (m_scanManager) {
        m_scanManager->StopScan();
        Sleep(300);
    }
    m_scanManager.reset();
    m_rootkitDetector.reset();
    m_clamav.reset();
    CDialogEx::OnDestroy();
}

void CBaguetteAVDlg::OnPaint()
{
    if (IsIconic())
    {
        CPaintDC dc(this);
        SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);
        int cxIcon = GetSystemMetrics(SM_CXICON);
        int cyIcon = GetSystemMetrics(SM_CYICON);
        CRect rect;
        GetClientRect(&rect);
        int x = (rect.Width() - cxIcon + 1) / 2;
        int y = (rect.Height() - cyIcon + 1) / 2;
        dc.DrawIcon(x, y, m_hIcon);
    }
    else
    {
        CDialogEx::OnPaint();
    }
}

HCURSOR CBaguetteAVDlg::OnQueryDragIcon()
{
    return static_cast<HCURSOR>(m_hIcon);
}

void CBaguetteAVDlg::OnBnClickedBtnFullscan()
{
    if (!m_scanManager) return;

    Log(_T(""));
    Log(_T("[扫描] 开始全盘扫描..."));
    m_txtRuntimeStatus.SetWindowText(_T("正在扫描..."));
    m_Progress.SetPos(0);

    EnableScanButtons(false);
    m_scanManager->StartFullScan();
}

void CBaguetteAVDlg::OnBnClickedBtnCustomscan()
{
    if (!m_scanManager) return;

    CFolderPickerDialog dlg(NULL, OFN_FILEMUSTEXIST, this);

    if (dlg.DoModal() == IDOK)
    {
        CString folderPath = dlg.GetPathName();

        Log(_T(""));
        Log(_T("[扫描] 目标:  ") + folderPath);
        m_txtRuntimeStatus.SetWindowText(_T("正在扫描..."));
        m_Progress.SetPos(0);

        EnableScanButtons(false);

        CT2A ascii(folderPath);
        m_scanManager->StartScanDirectory(std::string(ascii));
    }
}

void CBaguetteAVDlg::OnBnClickedBtnStop()
{
    if (m_scanManager) {
        Log(_T("[扫描] 正在停止... "));
        m_scanManager->StopScan();
        m_txtRuntimeStatus.SetWindowText(_T("已停止"));
    }
}

void CBaguetteAVDlg::OnBnClickedBtnRootkit()
{
    if (!m_rootkitDetector) {
        m_rootkitDetector = std::make_unique<RootkitDetector>(&m_LogList);
    }

    m_txtRuntimeStatus.SetWindowText(_T("Rootkit 检测中..."));
    m_Progress.SetPos(0);

    Log(_T(""));
    m_rootkitDetector->StartDetection();

    m_Progress.SetPos(100);
    m_txtRuntimeStatus.SetWindowText(_T("就绪"));
}