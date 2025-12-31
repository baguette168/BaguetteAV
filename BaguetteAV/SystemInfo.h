#pragma once
#include <string>

class SystemInfo
{
public:
    SystemInfo() = default;
    ~SystemInfo() = default;

    // 获取操作系统信息
    std::string GetOSName();

    // 获取CPU信息
    std::string GetCPUInfo();

    // 获取内存信息（单位MB）
    std::string GetMemoryInfo();
};
