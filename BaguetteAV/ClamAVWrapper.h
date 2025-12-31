#pragma once
#include <string>
#include <afxwin.h>

struct cl_engine;

class ClamAVWrapper
{
public:
    ClamAVWrapper(const std::string& dbPath, CListBox* logList);
    ~ClamAVWrapper();

    bool Initialize();
    void Uninitialize();
    bool ScanFile(const std::string& filePath, std::string& result);

private:
    void Log(const std::string& msg);
    std::string GetExeDirectory();

    std::string m_dbPath;
    cl_engine* m_engine;
    CListBox* m_LogList;
};