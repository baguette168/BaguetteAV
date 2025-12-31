#include "pch.h"
#include "ClamAVWrapper.h"
#include <clamav.h>
#include <string>

ClamAVWrapper::ClamAVWrapper(const std::string& dbPath, CListBox* logList)
    : m_dbPath(dbPath), m_engine(nullptr), m_LogList(logList)
{
}

ClamAVWrapper::~ClamAVWrapper()
{
    Uninitialize();
}

void ClamAVWrapper::Log(const std::string& msg)
{
    if (m_LogList)
    {
        CString cs(msg.c_str());
        m_LogList->AddString(cs);
        m_LogList->SetCurSel(m_LogList->GetCount() - 1);
    }
}

bool ClamAVWrapper::Initialize()
{
    int ret;

    m_engine = cl_engine_new();
    if (!m_engine)
    {
        Log("ClamAV 创建引擎失败");
        return false;
    }

    unsigned int sigs = 0;
    ret = cl_load(m_dbPath.c_str(), m_engine, &sigs, 0); // 0 表示默认选项
    if (ret != CL_SUCCESS)
    {
        Log(std::string("加载病毒库失败：") + cl_strerror((cl_error_t)ret));
        cl_engine_free(m_engine);
        m_engine = nullptr;
        return false;
    }

    ret = cl_engine_compile(m_engine);
    if (ret != CL_SUCCESS)
    {
        Log(std::string("引擎编译失败：") + cl_strerror((cl_error_t)ret));
        cl_engine_free(m_engine);
        m_engine = nullptr;
        return false;
    }

    Log("ClamAV 初始化完成");
    return true;
}

void ClamAVWrapper::Uninitialize()
{
    if (m_engine)
    {
        cl_engine_free(m_engine);
        m_engine = nullptr;
    }
}

bool ClamAVWrapper::ScanFile(const std::string& filePath, std::string& result)
{
    if (!m_engine)
    {
        result = "引擎未初始化";
        return false;
    }

    const char* virname = nullptr;
    int ret = cl_scanfile(filePath.c_str(), &virname, nullptr, m_engine, 0); // 0 表示默认选项

    if (ret == CL_VIRUS)
    {
        result = std::string("发现病毒: ") + (virname ? virname : "未知病毒");
        Log(result);
        return true;
    }
    else if (ret == CL_CLEAN)
    {
        result = "文件干净: " + filePath;
        Log(result);
        return true;
    }
    else
    {
        result = std::string("扫描失败: ") + cl_strerror((cl_error_t)ret);
        Log(result);
        return false;
    }
}
