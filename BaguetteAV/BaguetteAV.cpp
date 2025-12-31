#include "pch.h"
#include "framework.h"
#include "BaguetteAV.h"
#include "BaguetteAVDlg.h"
#include "SplashDlg.h"  // 只包含头文件，不是. cpp

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

BEGIN_MESSAGE_MAP(CBaguetteAVApp, CWinApp)
    ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()

CBaguetteAVApp::CBaguetteAVApp()
{
    m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;
}

CBaguetteAVApp theApp;

BOOL CBaguetteAVApp::InitInstance()
{
    INITCOMMONCONTROLSEX InitCtrls;
    InitCtrls.dwSize = sizeof(InitCtrls);
    InitCtrls.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&InitCtrls);

    CWinApp::InitInstance();
    AfxEnableControlContainer();

    SetRegistryKey(_T("BaguetteAV"));

    // 立即创建并显示启动画面
    CSplashDlg* pSplashDlg = new CSplashDlg();
    pSplashDlg->Create(IDD_SPLASH_DIALOG, NULL);
    pSplashDlg->ShowWindow(SW_SHOW);
    pSplashDlg->UpdateWindow();

    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    CShellManager* pShellManager = new CShellManager;
    CMFCVisualManager::SetDefaultManager(RUNTIME_CLASS(CMFCVisualManagerWindows));

    // 创建主对话框
    CBaguetteAVDlg* pMainDlg = new CBaguetteAVDlg();
    m_pMainWnd = pMainDlg;
    pMainDlg->Create(IDD_BAGUETTEAV_DIALOG, NULL);

    DWORD startTime = GetTickCount();
    while (GetTickCount() - startTime < 1500)
    {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(5);
    }

    // 丝滑过渡
    pSplashDlg->ModifyStyleEx(0, WS_EX_LAYERED);
    pMainDlg->ModifyStyleEx(0, WS_EX_LAYERED);
    pMainDlg->SetLayeredWindowAttributes(0, 0, LWA_ALPHA);
    pMainDlg->ShowWindow(SW_SHOW);

    for (int i = 0; i <= 255; i += 5)
    {
        pSplashDlg->SetLayeredWindowAttributes(0, 255 - i, LWA_ALPHA);
        pMainDlg->SetLayeredWindowAttributes(0, i, LWA_ALPHA);
        pMainDlg->UpdateWindow();
        Sleep(8);

        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    pSplashDlg->DestroyWindow();
    delete pSplashDlg;

    pMainDlg->ModifyStyleEx(WS_EX_LAYERED, 0);
    pMainDlg->UpdateWindow();

    if (pShellManager != nullptr)
    {
        delete pShellManager;
    }

#if ! defined(_AFXDLL) && !defined(_AFX_NO_MFC_CONTROLS_IN_DIALOGS)
    ControlBarCleanUp();
#endif

    pMainDlg->RunModalLoop();

    delete pMainDlg;
    m_pMainWnd = nullptr;

    return FALSE;
}