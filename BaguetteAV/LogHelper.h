#pragma once
#include <string>
#include <fstream>
#include <mutex>

class LogHelper
{
public:
    LogHelper();
    ~LogHelper();

    void AddLog(const std::string& text);

private:
    std::ofstream m_logFile;
    std::mutex m_mutex;
};
