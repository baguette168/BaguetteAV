#pragma once
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <afxwin.h>

class ClamAVWrapper;

#define WM_LOG_MESSAGE (WM_USER + 100)
#define WM_SCAN_COMPLETE (WM_USER + 101)
#define WM_UPDATE_PROGRESS (WM_USER + 102)

class ScanManager
{
public:
    ScanManager(ClamAVWrapper* clamav, CListBox* logList);
    ~ScanManager();

    void StartScanFile(const std::string& filePath);
    void StartScanDirectory(const std::string& dirPath);
    void StartFullScan();
    void StopScan();
    bool IsScanning() const { return m_isScanning; }

private:
    void ScanFileInternal(const std::string& filePath);
    void ScanDirectoryInternal(const std::string& dirPath);
    void CollectFiles(const std::string& dirPath, std::vector<std::string>& files);
    void PostLog(const std::string& msg);
    void PostComplete();
    void PostProgress(int percent);

    ClamAVWrapper* m_clamav;
    CListBox* m_logList;
    HWND m_parentHwnd;
    std::thread m_scanThread;
    std::atomic<bool> m_isScanning;
    std::atomic<bool> m_stopRequested;
    int m_scannedCount;
    int m_threatCount;
};