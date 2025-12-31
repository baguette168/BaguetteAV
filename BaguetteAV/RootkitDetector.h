#pragma once
#include <string>
#include <vector>
#include <afxwin.h>

#define WM_LOG_MESSAGE (WM_USER + 100)

struct SuspiciousItem {
    std::string type;
    std::string name;
    std::string description;
    int riskLevel; // 1-3, 3最高
};

class RootkitDetector
{
public:
    RootkitDetector(CListBox* logList);
    ~RootkitDetector();

    void StartDetection();
    std::vector<SuspiciousItem> GetResults() const { return m_results; }

private:
    void PostLog(const std::string& msg);

    // 检测方法
    void CheckHiddenProcesses();
    void CheckSuspiciousServices();
    void CheckStartupPrograms();
    void CheckHostsFile();
    void CheckSuspiciousDrivers();

    CListBox* m_logList;
    HWND m_parentHwnd;
    std::vector<SuspiciousItem> m_results;
};