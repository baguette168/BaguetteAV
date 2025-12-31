#pragma once
#include <string>
#include <vector>
#include "ClamAVWrapper.h"
#include "LogHelper.h"

class ScanManager
{
public:
    ScanManager(ClamAVWrapper* engine, LogHelper* logger);
    ~ScanManager() = default;

    // 扫描单个文件
    bool ScanFile(const std::string& filePath);

    // 扫描多个文件
    bool ScanFiles(const std::vector<std::string>& files);

private:
    ClamAVWrapper* m_engine;
    LogHelper* m_logger;
};
