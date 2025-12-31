#include "pch.h"
#include "ScanManager.h"
#include "ClamAVWrapper.h"
#include <windows.h>

ScanManager::ScanManager(ClamAVWrapper* clamav, CListBox* logList)
    : m_clamav(clamav)
    , m_logList(logList)
    , m_parentHwnd(NULL)
    , m_isScanning(false)
    , m_stopRequested(false)
    , m_scannedCount(0)
    , m_threatCount(0)
{
    if (m_logList && m_logList->GetParent()) {
        m_parentHwnd = m_logList->GetParent()->GetSafeHwnd();
    }
}

ScanManager::~ScanManager()
{
    m_stopRequested = true;
    if (m_scanThread.joinable()) {
        m_scanThread.join();
    }
}

void ScanManager::PostLog(const std::string& msg)
{
    if (m_parentHwnd && IsWindow(m_parentHwnd)) {
        CString* pMsg = new CString(msg.c_str());
        ::PostMessage(m_parentHwnd, WM_LOG_MESSAGE, (WPARAM)pMsg, 0);
    }
}

void ScanManager::PostComplete()
{
    if (m_parentHwnd && IsWindow(m_parentHwnd)) {
        ::PostMessage(m_parentHwnd, WM_SCAN_COMPLETE, 0, 0);
    }
}

void ScanManager::PostProgress(int percent)
{
    if (m_parentHwnd && IsWindow(m_parentHwnd)) {
        ::PostMessage(m_parentHwnd, WM_UPDATE_PROGRESS, (WPARAM)percent, 0);
    }
}

void ScanManager::StartScanFile(const std::string& filePath)
{
    if (m_isScanning) return;

    if (m_scanThread.joinable()) {
        m_scanThread.join();
    }

    m_isScanning = true;
    m_stopRequested = false;
    m_scannedCount = 0;
    m_threatCount = 0;

    std::string pathCopy = filePath;
    m_scanThread = std::thread([this, pathCopy]() {
        ScanFileInternal(pathCopy);
        });
}

void ScanManager::StartScanDirectory(const std::string& dirPath)
{
    if (m_isScanning) return;

    if (m_scanThread.joinable()) {
        m_scanThread.join();
    }

    m_isScanning = true;
    m_stopRequested = false;
    m_scannedCount = 0;
    m_threatCount = 0;

    std::string pathCopy = dirPath;
    m_scanThread = std::thread([this, pathCopy]() {
        ScanDirectoryInternal(pathCopy);
        });
}

void ScanManager::StartFullScan()
{
    StartScanDirectory("C:\\Users");
}

void ScanManager::StopScan()
{
    m_stopRequested = true;
}

void ScanManager::ScanFileInternal(const std::string& filePath)
{
    PostLog("开始扫描文件:  " + filePath);
    PostProgress(0);

    std::string result;
    bool success = m_clamav->ScanFile(filePath, result);

    m_scannedCount = 1;
    if (success && result.find("发现病毒") != std::string::npos) {
        m_threatCount = 1;
        PostLog("[! ] " + result);
    }
    else if (success) {
        PostLog("[OK] 文件安全");
    }
    else {
        PostLog("[X] " + result);
    }

    PostProgress(100);
    PostLog("扫描完成，共扫描 1 个文件，发现 " + std::to_string(m_threatCount) + " 个威胁");

    m_isScanning = false;
    PostComplete();
}

void ScanManager::CollectFiles(const std::string& dirPath, std::vector<std::string>& files)
{
    if (m_stopRequested) return;

    WIN32_FIND_DATAA findData;
    std::string searchPath = dirPath + "\\*";

    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (m_stopRequested) break;

        std::string fileName = findData.cFileName;
        if (fileName == "." || fileName == "..") continue;

        std::string fullPath = dirPath + "\\" + fileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)) {
                CollectFiles(fullPath, files);
            }
        }
        else {
            files.push_back(fullPath);
        }
    } while (FindNextFileA(hFind, &findData) != 0);

    FindClose(hFind);
}

void ScanManager::ScanDirectoryInternal(const std::string& dirPath)
{
    PostLog("开始扫描目录: " + dirPath);
    PostLog("正在收集文件列表.. .");
    PostProgress(0);

    std::vector<std::string> files;
    CollectFiles(dirPath, files);

    if (m_stopRequested) {
        PostLog("扫描已取消");
        m_isScanning = false;
        PostComplete();
        return;
    }

    PostLog("共找到 " + std::to_string(files.size()) + " 个文件");

    if (files.empty()) {
        PostLog("未找到任何文件");
        PostProgress(100);
        m_isScanning = false;
        PostComplete();
        return;
    }

    PostLog("开始扫描.. .");

    int total = (int)files.size();

    for (int i = 0; i < total && !m_stopRequested; i++)
    {
        const std::string& filePath = files[i];

        std::string result;
        bool success = m_clamav->ScanFile(filePath, result);

        m_scannedCount++;

        if (success && result.find("发现病毒") != std::string::npos) {
            m_threatCount++;
            PostLog("[! ] " + result + " - " + filePath);
        }

        // 更新进度条
        int percent = m_scannedCount * 100 / total;
        PostProgress(percent);

        if (m_scannedCount % 50 == 0 || m_scannedCount == total) {
            PostLog("进度:  " + std::to_string(m_scannedCount) + "/" + std::to_string(total) +
                " (" + std::to_string(percent) + "%)");
        }
    }

    PostLog("========================================");
    if (m_stopRequested) {
        PostLog("扫描已取消");
    }
    else {
        PostLog("扫描完成!");
    }
    PostLog("扫描文件数: " + std::to_string(m_scannedCount));
    PostLog("发现威胁数: " + std::to_string(m_threatCount));
    PostLog("========================================");

    PostProgress(100);
    m_isScanning = false;
    PostComplete();
}