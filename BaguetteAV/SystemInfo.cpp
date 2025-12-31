#include "pch.h"
#include "SystemInfo.h"
#include <windows.h>
#include <sstream>

std::string SystemInfo::GetOSName()
{
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
#pragma warning(push)
#pragma warning(disable : 4996)
    if (!GetVersionEx((OSVERSIONINFO*)&osvi))
        return "Unknown OS";
#pragma warning(pop)

    std::ostringstream oss;
    oss << "Windows " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
    return oss.str();
}

std::string SystemInfo::GetCPUInfo()
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    std::ostringstream oss;
    oss << "CPU架构: " << si.wProcessorArchitecture
        << ", 核心数: " << si.dwNumberOfProcessors;
    return oss.str();
}

std::string SystemInfo::GetMemoryInfo()
{
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    if (!GlobalMemoryStatusEx(&statex))
        return "Unknown Memory";

    std::ostringstream oss;
    oss << "总内存: " << statex.ullTotalPhys / (1024 * 1024) << " MB, "
        << "可用内存: " << statex.ullAvailPhys / (1024 * 1024) << " MB";
    return oss.str();
}
