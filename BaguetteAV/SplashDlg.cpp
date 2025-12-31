#include "pch.h"
#include "framework.h"
#include "SplashDlg.h"

CSplashDlg::CSplashDlg(CWnd* pParent)
    : CDialogEx(IDD_SPLASH_DIALOG, pParent)
    , m_nAlpha(0)
    , m_nLoadingDots(0)
{
}

void CSplashDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_STATIC_BUDDHA, m_staticBuddha);
    DDX_Control(pDX, IDC_STATIC_TITLE, m_staticTitle);
    DDX_Control(pDX, IDC_STATIC_LOADING, m_staticLoading);
}

BEGIN_MESSAGE_MAP(CSplashDlg, CDialogEx)
    ON_WM_TIMER()
    ON_WM_PAINT()
    ON_WM_CTLCOLOR()
    ON_WM_ERASEBKGND()
END_MESSAGE_MAP()

BOOL CSplashDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();

    m_bgBrush.CreateSolidBrush(GetSysColor(COLOR_3DFACE));

    CString buddha =
        _T("                   _ooOoo_\n")
        _T("                  o8888888o\n")
        _T("                  88\" .  \"88\n")
        _T("                  (| -_- |)\n")
        _T("                  O\\  =  /O\n")
        _T("               ____/`---'\\____\n")
        _T("             .'  \\\\|     |//  `.\n")
        _T("            /  \\\\|||  :  |||//  \\\n")
        _T("           /  _||||| -: - |||||_  \\\n")
        _T("           |   | \\\\\\  -  /// |   |\n")
        _T("           | \\_|  ''\\---/''  |_/ |\n")
        _T("           \\  .-\\__  `-`  __/-.   /\n")
        _T("         ___`. .'  /--. --\\  `. .'___\n")
        _T("      . \"\" '<  `.___\\_<|>_/___.'  >' \"\".\n")
        _T("     | | :   `- \\`.;`\\ _ /`;.`/ -` :  | |\n")
        _T("     \\  \\ `-.    \\_ __\\ /__ _/   .-` /  /\n")
        _T("=====`-. ____`-.___\\_____/___.-`____.-'=====\n")
        _T("                  `=---='\n");

    m_fontBuddha.CreateFont(
        22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, _T("Consolas"));

    m_fontTitle.CreateFont(
        36, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, _T("Segoe UI"));

    m_fontLoading.CreateFont(
        18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, _T("Microsoft YaHei UI"));

    m_staticBuddha.SetFont(&m_fontBuddha);
    m_staticBuddha.SetWindowText(buddha);

    m_staticTitle.SetFont(&m_fontTitle);
    m_staticTitle.SetWindowText(_T("BaguetteAV"));

    m_staticLoading.SetFont(&m_fontLoading);
    m_staticLoading.SetWindowText(_T("正在初始化..."));

    CRect clientRect;
    GetClientRect(&clientRect);
    int dialogWidth = clientRect.Width();
    int dialogHeight = clientRect.Height();

    CDC* pDC = GetDC();
    CFont* pOldFont = pDC->SelectObject(&m_fontBuddha);
    CRect buddhaRect(0, 0, 0, 0);
    pDC->DrawText(buddha, &buddhaRect, DT_CALCRECT);
    pDC->SelectObject(pOldFont);

    pOldFont = pDC->SelectObject(&m_fontTitle);
    CRect titleRect(0, 0, 0, 0);
    pDC->DrawText(_T("BaguetteAV"), &titleRect, DT_CALCRECT);
    pDC->SelectObject(pOldFont);
    ReleaseDC(pDC);

    int buddhaWidth = buddhaRect.Width();
    int buddhaHeight = buddhaRect.Height();
    int titleWidth = titleRect.Width();
    int titleHeight = titleRect.Height();

    int totalHeight = buddhaHeight + 10 + titleHeight;
    int startY = (dialogHeight - totalHeight - 50) / 2;

    int buddhaX = (dialogWidth - buddhaWidth) / 2;
    int buddhaY = startY;
    m_staticBuddha.MoveWindow(buddhaX, buddhaY, buddhaWidth, buddhaHeight);

    int titleX = (dialogWidth - titleWidth) / 2;
    int titleY = buddhaY + buddhaHeight + 10;
    m_staticTitle.MoveWindow(titleX, titleY, titleWidth, titleHeight);
    m_staticTitle.ShowWindow(SW_SHOW);

    m_staticLoading.MoveWindow(0, dialogHeight - 40, dialogWidth, 25);

    CenterWindow();
    SetTimer(2, 400, NULL);

    return TRUE;
}

BOOL CSplashDlg::OnEraseBkgnd(CDC* pDC)
{
    CRect rect;
    GetClientRect(&rect);
    pDC->FillSolidRect(rect, GetSysColor(COLOR_3DFACE));
    return TRUE;
}

HBRUSH CSplashDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
    HBRUSH hbr = CDialogEx::OnCtlColor(pDC, pWnd, nCtlColor);

    if (nCtlColor == CTLCOLOR_STATIC || nCtlColor == CTLCOLOR_DLG)
    {
        pDC->SetBkColor(GetSysColor(COLOR_3DFACE));

        if (pWnd->GetDlgCtrlID() == IDC_STATIC_BUDDHA)
        {
            pDC->SetTextColor(RGB(0, 120, 215));
        }
        else if (pWnd->GetDlgCtrlID() == IDC_STATIC_TITLE)
        {
            pDC->SetTextColor(RGB(0, 100, 180));
        }
        else if (pWnd->GetDlgCtrlID() == IDC_STATIC_LOADING)
        {
            pDC->SetTextColor(RGB(100, 100, 100));
        }

        return m_bgBrush;
    }

    return hbr;
}

void CSplashDlg::OnPaint()
{
    CPaintDC dc(this);
    CRect rect;
    GetClientRect(&rect);
    dc.FillSolidRect(rect, GetSysColor(COLOR_3DFACE));
}

void CSplashDlg::OnTimer(UINT_PTR nIDEvent)
{
    if (nIDEvent == 2)
    {
        m_nLoadingDots = (m_nLoadingDots + 1) % 4;
        CString loading = _T("正在初始化");
        for (int i = 0; i < m_nLoadingDots; i++)
        {
            loading += _T(".");
        }
        m_staticLoading.SetWindowText(loading);
    }

    CDialogEx::OnTimer(nIDEvent);
}