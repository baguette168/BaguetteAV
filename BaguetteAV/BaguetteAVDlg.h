#pragma once
#include <memory>
#include "ClamAVWrapper.h"
#include "ScanManager.h"
#include "RootkitDetector.h"

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
    virtual void OnCancel();
    afx_msg void OnPaint();
    afx_msg HCURSOR OnQueryDragIcon();
    afx_msg void OnBnClickedBtnFullscan();
    afx_msg void OnBnClickedBtnCustomscan();
    afx_msg void OnBnClickedBtnStop();
    afx_msg void OnBnClickedBtnRootkit();
    afx_msg LRESULT OnLogMessage(WPARAM wParam, LPARAM lParam);
    afx_msg LRESULT OnScanComplete(WPARAM wParam, LPARAM lParam);
    afx_msg LRESULT OnUpdateProgress(WPARAM wParam, LPARAM lParam);
    afx_msg void OnDestroy();
    afx_msg void OnClose();
    DECLARE_MESSAGE_MAP()

protected:
    HICON m_hIcon;
    CListBox m_LogList;
    CButton m_btnFullScan;
    CButton m_btnCustomScan;
    CButton m_btnStop;
    CButton m_btnRootkit;
    CProgressCtrl m_Progress;
    CStatic m_txtEngineStatus;
    CStatic m_txtRuntimeStatus;

private:
    std::unique_ptr<ClamAVWrapper> m_clamav;
    std::unique_ptr<ScanManager> m_scanManager;
    std::unique_ptr<RootkitDetector> m_rootkitDetector;

    void Log(const CString& msg);
    void InitializeClamAV();
    std::string GetExeDirectory();
    void EnableScanButtons(bool enable);
};