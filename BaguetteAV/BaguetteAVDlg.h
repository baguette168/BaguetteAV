#pragma once

#include <afxwin.h>
#include <afxcmn.h>
#include <vector>
#include <string>

// 前向声明，避免在头文件里包含 ClamAVWrapper / LogHelper 导致编译错误
class ClamAVWrapper;
class LogHelper;

class CBaguetteAVDlg : public CDialogEx
{
public:
    CBaguetteAVDlg(CWnd* pParent = nullptr);

#ifdef AFX_DESIGN_TIME
    enum { IDD = IDD_BAGUETTEAV_DIALOG };
#endif

protected:
    virtual void DoDataExchange(CDataExchange* pDX);
    virtual BOOL OnInitDialog();

    afx_msg void OnBnClickedBtnFullscan();
    afx_msg void OnBnClickedBtnCustomscan();
    afx_msg void OnBnClickedBtnStop();
    afx_msg void OnBnClickedBtnRootkit();
    afx_msg void OnTimer(UINT_PTR nIDEvent);

    DECLARE_MESSAGE_MAP()

private:
    HICON m_hIcon;

    CStatic m_txtEngineStatus;
    CStatic m_txtRuntimeStatus;
    CProgressCtrl m_progress;
    CListBox m_LogList;

    BOOL m_bScanning;
    int m_nScanProgress;

    std::vector<std::string> m_filesToScan;

    ClamAVWrapper* m_avEngine;
    LogHelper* m_logger;

    void AddLog(const CString& text);
};
