// ========================== BaguetteAV.cpp ==========================
#include "pch.h"
#include "framework.h"
#include "BaguetteAV.h"
#include "BaguetteAVDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CBaguetteAVApp theApp;

BOOL CBaguetteAVApp::InitInstance()
{
    CWinApp::InitInstance();
    AfxEnableControlContainer();

    CBaguetteAVDlg dlg;
    m_pMainWnd = &dlg;
    dlg.DoModal();

    return FALSE;
}
