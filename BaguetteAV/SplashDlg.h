#pragma once
#include "afxdialogex.h"
#include "Resource.h"

class CSplashDlg : public CDialogEx
{
public:
    CSplashDlg(CWnd* pParent = nullptr);

#ifdef AFX_DESIGN_TIME
    enum { IDD = IDD_SPLASH_DIALOG };
#endif

protected:
    virtual void DoDataExchange(CDataExchange* pDX);
    virtual BOOL OnInitDialog();
    afx_msg void OnTimer(UINT_PTR nIDEvent);
    afx_msg void OnPaint();
    afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
    afx_msg BOOL OnEraseBkgnd(CDC* pDC);
    DECLARE_MESSAGE_MAP()

private:
    CStatic m_staticBuddha;
    CStatic m_staticTitle;
    CStatic m_staticLoading;
    CFont m_fontBuddha;
    CFont m_fontTitle;
    CFont m_fontLoading;
    CBrush m_bgBrush;
    int m_nAlpha;
    int m_nLoadingDots;
};