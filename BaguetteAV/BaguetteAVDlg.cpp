#include "pch.h"
#include "framework.h"
#include "BaguetteAV.h"
#include "BaguetteAVDlg.h"
#include "afxdialogex.h"
#include <shlobj.h>
#include <shlwapi.h>
#include <afxwin.h>
#include <afxcmn.h>

// 这里包含完整 ClamAVWrapper 和 LogHelper
#include "ClamAVWrapper.h"
#include "LogHelper.h"

#pragma comment(lib, "Shlwapi.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CBaguetteAVDlg::CBaguetteAVDlg(CWnd* pParent)
    : CDialogEx(IDD_BAGUETTEAV_DIALOG, pParent),
    m_bScanning(FALSE),
    m_nScanProgress(0),
    m_avEngine(nullptr),
    m_logger(nullptr)
{
    m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CBaguetteAVDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_TXT_ENGINESTATUS, m_txtEngineStatus);
    DDX_Control(pDX, IDC_TXT_RUNTIMESTATUS, m_txtRuntimeStatus);
    DDX_Control(pDX, IDC_PROGRESS, m_progress);
    DDX_Control(pDX, IDC_LIST_LOG, m_LogList);
}

BEGIN_MESSAGE_MAP(CBaguetteAVDlg, CDialogEx)
    ON_BN_CLICKED(IDC_BTN_FULLSCAN, &CBaguetteAVDlg::OnBnClickedBtnFullscan)
    ON_BN_CLICKED(IDC_BTN_CUSTOMSCAN, &CBaguetteAVDlg::OnBnClickedBtnCustomscan)
    ON_BN_CLICKED(IDC_BTN_STOP, &CBaguetteAVDlg::OnBnClickedBtnStop)
    ON_BN_CLICKED(IDC_BTN_ROOTKIT, &CBaguetteAVDlg::OnBnClickedBtnRootkit)
    ON_WM_TIMER()
END_MESSAGE_MAP()

static BOOL FileExistsA(const std::string& path)
{
    DWORD attr = GetFileAttributesA(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

static BOOL DirExistsA(const std::string& path)
{
    DWORD attr = GetFileAttributesA(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
}

static std::string GetExeDirA()
{
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    PathRemoveFileSpecA(path);
    return std::string(path);
}

static bool CheckDbFolderA(const std::string& folder)
{
    return FileExistsA(folder + "\\main.cvd");
}

BOOL CBaguetteAVDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();

    SetIcon(m_hIcon, TRUE);
    SetIcon(m_hIcon, FALSE);

    m_txtEngineStatus.SetWindowTextW(L"初始化中...");
    m_txtRuntimeStatus.SetWindowTextW(L"空闲");
    m_progress.SetRange(0, 100);
    m_progress.SetPos(0);

    m_logger = new LogHelper();

    std::string dbPath;
    std::string exeDir = GetExeDirA();
    std::string tryPath = exeDir + "\\virusdb";

    if (DirExistsA(tryPath) && CheckDbFolderA(tryPath))
        dbPath = tryPath;

    m_avEngine = new ClamAVWrapper(dbPath, &m_LogList);

    if (m_avEngine->Initialize())
    {
        m_txtEngineStatus.SetWindowTextW(L"已加载 ClamAV");
        AddLog(L"ClamAV 引擎加载成功");
    }
    else
    {
        m_txtEngineStatus.SetWindowTextW(L"ClamAV 初始化失败");
        AddLog(L"初始化失败：病毒库未正确加载");
    }

    return TRUE;
}

void CBaguetteAVDlg::AddLog(const CString& text)
{
    m_LogList.AddString(text);
    m_LogList.SetCurSel(m_LogList.GetCount() - 1);

    if (m_logger)
    {
        CT2A converted(text);
        m_logger->AddLog(std::string(converted));
    }
}

// 其他按钮和 OnTimer 内容保持不变，可复用之前的实现
