#include "pch.h"
#include "RootkitDetector.h"
#include <windows.h>
#include <winsvc.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <fstream>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

RootkitDetector::RootkitDetector(CListBox* logList)
    : m_logList(logList)
    , m_parentHwnd(NULL)
{
    if (m_logList && m_logList->GetParent()) {
        m_parentHwnd = m_logList->GetParent()->GetSafeHwnd();
    }
}

RootkitDetector::~RootkitDetector()
{
}

void RootkitDetector::PostLog(const std::string& msg)
{
    if (m_logList && m_logList->GetSafeHwnd()) {
        CString cs(msg.c_str());
        m_logList->AddString(cs);
        m_logList->SetCurSel(m_logList->GetCount() - 1);
    }
}

void RootkitDetector::StartDetection()
{
    m_results.clear();

    PostLog("========================================");
    PostLog("开始 Rootkit 检测.. .");
    PostLog("========================================");

    PostLog("");
    PostLog("[1/5] 检查隐藏进程...");
    CheckHiddenProcesses();

    PostLog("");
    PostLog("[2/5] 检查可疑服务.. .");
    CheckSuspiciousServices();

    PostLog("");
    PostLog("[3/5] 检查启动项...");
    CheckStartupPrograms();

    PostLog("");
    PostLog("[4/5] 检查 Hosts 文件...");
    CheckHostsFile();

    PostLog("");
    PostLog("[5/5] 检查可疑驱动.. .");
    CheckSuspiciousDrivers();

    PostLog("");
    PostLog("========================================");
    PostLog("Rootkit 检测完成!");
    PostLog("发现 " + std::to_string(m_results.size()) + " 个可疑项目");
    PostLog("========================================");
}

void RootkitDetector::CheckHiddenProcesses()
{
    std::vector<DWORD> toolhelpPids;
    std::vector<DWORD> enumPids;

    // 方法1: CreateToolhelp32Snapshot
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe)) {
            do {
                toolhelpPids.push_back(pe.th32ProcessID);
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    // 方法2: EnumProcesses
    DWORD pids[2048];
    DWORD bytesReturned;
    if (EnumProcesses(pids, sizeof(pids), &bytesReturned)) {
        int count = bytesReturned / sizeof(DWORD);
        for (int i = 0; i < count; i++) {
            if (pids[i] != 0) {
                enumPids.push_back(pids[i]);
            }
        }
    }

    PostLog("  Toolhelp32 发现 " + std::to_string(toolhelpPids.size()) + " 个进程");
    PostLog("  EnumProcesses 发现 " + std::to_string(enumPids.size()) + " 个进程");

    // 比较两个列表
    int hiddenCount = 0;
    for (DWORD pid : enumPids) {
        if (std::find(toolhelpPids.begin(), toolhelpPids.end(), pid) == toolhelpPids.end()) {
            hiddenCount++;
            SuspiciousItem item;
            item.type = "隐藏进程";
            item.name = "PID:  " + std::to_string(pid);
            item.description = "进程在 EnumProcesses 中存在但在 Toolhelp32 中不存在";
            item.riskLevel = 3;
            m_results.push_back(item);
            PostLog("  [! ] 发现可能的隐藏进程 PID: " + std::to_string(pid));
        }
    }

    if (hiddenCount == 0) {
        PostLog("  [OK] 未发现隐藏进程");
    }
}

void RootkitDetector::CheckSuspiciousServices()
{
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        PostLog("  [X] 无法打开服务管理器 (错误: " + std::to_string(GetLastError()) + ")");
        return;
    }

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    // 首先获取需要的缓冲区大小
    EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);

    if (bytesNeeded == 0) {
        PostLog("  [X] 无法获取服务列表");
        CloseServiceHandle(hSCManager);
        return;
    }

    std::vector<BYTE> buffer(bytesNeeded);
    LPENUM_SERVICE_STATUS_PROCESSA services = (LPENUM_SERVICE_STATUS_PROCESSA)buffer.data();

    resumeHandle = 0;
    if (EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, buffer.data(), bytesNeeded, &bytesNeeded,
        &servicesReturned, &resumeHandle, NULL))
    {
        int suspiciousCount = 0;

        for (DWORD i = 0; i < servicesReturned; i++) {
            SC_HANDLE hService = OpenServiceA(hSCManager, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (hService) {
                DWORD configSize = 0;
                QueryServiceConfigA(hService, NULL, 0, &configSize);

                if (configSize > 0) {
                    std::vector<BYTE> configBuffer(configSize);
                    LPQUERY_SERVICE_CONFIGA config = (LPQUERY_SERVICE_CONFIGA)configBuffer.data();

                    if (QueryServiceConfigA(hService, config, configSize, &configSize)) {
                        std::string path = config->lpBinaryPathName ? config->lpBinaryPathName : "";
                        std::string serviceName = services[i].lpServiceName ? services[i].lpServiceName : "";

                        // 转换为小写进行检查
                        std::string pathLower = path;
                        std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);

                        // 检查路径中是否有可疑位置
                        if (pathLower.find("\\temp\\") != std::string::npos ||
                            pathLower.find("\\appdata\\local\\temp") != std::string::npos) {

                            suspiciousCount++;
                            SuspiciousItem item;
                            item.type = "可疑服务";
                            item.name = serviceName;
                            item.description = "服务路径位于可疑位置:  " + path;
                            item.riskLevel = 2;
                            m_results.push_back(item);
                            PostLog("  [!] 可疑服务:  " + serviceName);
                        }
                    }
                }
                CloseServiceHandle(hService);
            }
        }

        PostLog("  检查了 " + std::to_string(servicesReturned) + " 个服务");
        if (suspiciousCount == 0) {
            PostLog("  [OK] 未发现可疑服务");
        }
    }

    CloseServiceHandle(hSCManager);
}

void RootkitDetector::CheckStartupPrograms()
{
    std::vector<std::pair<HKEY, std::string>> startupKeys = {
        {HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
        {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}
    };

    int totalItems = 0;
    int suspiciousCount = 0;

    for (const auto& keyPair : startupKeys) {
        HKEY hKey;
        if (RegOpenKeyExA(keyPair.first, keyPair.second.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

            char valueName[256];
            char valueData[1024];
            DWORD valueNameSize, valueDataSize, valueType;
            DWORD index = 0;

            while (true) {
                valueNameSize = sizeof(valueName);
                valueDataSize = sizeof(valueData);

                if (RegEnumValueA(hKey, index, valueName, &valueNameSize, NULL,
                    &valueType, (LPBYTE)valueData, &valueDataSize) != ERROR_SUCCESS) {
                    break;
                }

                totalItems++;
                std::string path = valueData;
                std::string pathLower = path;
                std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);

                // 检查可疑路径
                if (pathLower.find("\\temp\\") != std::string::npos ||
                    pathLower.find("\\appdata\\local\\temp") != std::string::npos ||
                    pathLower.find(". tmp") != std::string::npos) {

                    suspiciousCount++;
                    SuspiciousItem item;
                    item.type = "可疑启动项";
                    item.name = valueName;
                    item.description = path;
                    item.riskLevel = 2;
                    m_results.push_back(item);
                    PostLog("  [! ] 可疑启动项: " + std::string(valueName));
                }

                index++;
            }

            RegCloseKey(hKey);
        }
    }

    PostLog("  检查了 " + std::to_string(totalItems) + " 个启动项");
    if (suspiciousCount == 0) {
        PostLog("  [OK] 未发现可疑启动项");
    }
}

void RootkitDetector::CheckHostsFile()
{
    char systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, MAX_PATH);
    std::string hostsPath = std::string(systemPath) + "\\drivers\\etc\\hosts";

    std::ifstream file(hostsPath);
    if (!file.is_open()) {
        PostLog("  [X] 无法打开 Hosts 文件");
        return;
    }

    std::string line;
    int lineCount = 0;
    int suspiciousCount = 0;

    std::vector<std::string> commonDomains = {
        "google.com", "facebook.com", "microsoft.com",
        "windowsupdate.com", "kaspersky.com", "avast.com",
        "norton.com", "mcafee.com", "malwarebytes.com"
    };

    while (std::getline(file, line)) {
        lineCount++;

        if (line.empty() || line[0] == '#') continue;

        std::string lineLower = line;
        std::transform(lineLower.begin(), lineLower.end(), lineLower.begin(), ::tolower);

        for (const auto& domain : commonDomains) {
            if (lineLower.find(domain) != std::string::npos) {
                if (lineLower.find("127.0.0.1") == std::string::npos &&
                    lineLower.find(":: 1") == std::string::npos &&
                    lineLower.find("0.0.0.0") == std::string::npos) {

                    suspiciousCount++;
                    SuspiciousItem item;
                    item.type = "Hosts 劫持";
                    item.name = domain;
                    item.description = line;
                    item.riskLevel = 3;
                    m_results.push_back(item);
                    PostLog("  [! ] 可疑 Hosts 条目: " + domain);
                }
            }
        }
    }

    file.close();

    PostLog("  检查了 " + std::to_string(lineCount) + " 行");
    if (suspiciousCount == 0) {
        PostLog("  [OK] Hosts 文件正常");
    }
}

void RootkitDetector::CheckSuspiciousDrivers()
{
    LPVOID drivers[1024];
    DWORD cbNeeded;

    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        PostLog("  [X] 无法枚举驱动");
        return;
    }

    int driverCount = cbNeeded / sizeof(LPVOID);
    int suspiciousCount = 0;

    for (int i = 0; i < driverCount; i++) {
        char driverName[MAX_PATH];
        if (GetDeviceDriverBaseNameA(drivers[i], driverName, sizeof(driverName))) {
            std::string name = driverName;
            std::string nameLower = name;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

            if (nameLower.find("hide") != std::string::npos ||
                nameLower.find("hook") != std::string::npos ||
                nameLower.find("stealth") != std::string::npos ||
                nameLower.find("rootkit") != std::string::npos) {

                suspiciousCount++;
                SuspiciousItem item;
                item.type = "可疑驱动";
                item.name = driverName;
                item.description = "驱动名称包含可疑关键词";
                item.riskLevel = 3;
                m_results.push_back(item);
                PostLog("  [!] 可疑驱动:  " + std::string(driverName));
            }
        }
    }

    PostLog("  检查了 " + std::to_string(driverCount) + " 个驱动");
    if (suspiciousCount == 0) {
        PostLog("  [OK] 未发现可疑驱动");
    }
}