#include "pch.h"
#include "ScanManager.h"

ScanManager::ScanManager(ClamAVWrapper* engine, LogHelper* logger)
    : m_engine(engine), m_logger(logger)
{
}

bool ScanManager::ScanFile(const std::string& filePath)
{
    if (!m_engine) return false;

    std::string result;
    bool ok = m_engine->ScanFile(filePath, result);
    if (m_logger)
    {
        m_logger->AddLog("É¨ÃèÎÄ¼þ: " + filePath + " -> " + result);
    }
    return ok;
}

bool ScanManager::ScanFiles(const std::vector<std::string>& files)
{
    if (!m_engine) return false;

    for (const auto& f : files)
    {
        if (!ScanFile(f))
            return false;
    }
    return true;
}
