#pragma once
#include <string>
#include <afxwin.h> // สนำร CListBox

class ClamAVWrapper
{
public:
    ClamAVWrapper(const std::string& dbPath, CListBox* logList);
    ~ClamAVWrapper();

    bool Initialize();
    bool ScanFile(const std::string& path, std::string& result);

private:
    std::string m_dbPath;
    CListBox* m_LogList;
    void Log(const CString& text);
};
