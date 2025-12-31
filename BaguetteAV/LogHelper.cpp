#include "pch.h"
#include "LogHelper.h"

LogHelper::LogHelper()
{
    m_logFile.open("Logs\\BaguetteAV.log", std::ios::app);
}

LogHelper::~LogHelper()
{
    if (m_logFile.is_open())
        m_logFile.close();
}

void LogHelper::AddLog(const std::string& text)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_logFile.is_open())
    {
        m_logFile << text << std::endl;
    }
}
