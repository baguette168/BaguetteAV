#include "pch.h"
#include "ClamAVWrapper.h"
#include <clamav.h>
#include <string>
#include <windows.h>

// 全局变量用于日志回调
static CListBox* g_LogList = nullptr;

// ClamAV 消息回调 - 只显示错误
void clamav_msg_callback(enum cl_msg severity, const char* fullmsg, const char* msg, void* context)
{
    // 只在出错时显示
    if (g_LogList && msg && severity == CL_MSG_ERROR)
    {
        CString cs(("[ClamAV] " + std::string(msg)).c_str());
        g_LogList->AddString(cs);
        g_LogList->SetCurSel(g_LogList->GetCount() - 1);
    }
}

ClamAVWrapper::ClamAVWrapper(const std::string& dbPath, CListBox* logList)
    : m_dbPath(dbPath), m_engine(nullptr), m_LogList(logList)
{
    g_LogList = logList;
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

std::string ClamAVWrapper::GetExeDirectory()
{
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string fullPath(path);
    size_t pos = fullPath.find_last_of("\\/");
    return fullPath.substr(0, pos);
}

bool ClamAVWrapper::Initialize()
{
    cl_error_t ret;

    cl_set_clcb_msg(clamav_msg_callback);

    ret = cl_init(CL_INIT_DEFAULT);
    if (ret != CL_SUCCESS)
    {
        Log("[错误] ClamAV 引擎初始化失败");
        return false;
    }

    std::string exeDir = GetExeDirectory();
    std::string dbPath = exeDir + "\\database";
    std::string certsPath = exeDir + "\\certs";

    m_engine = cl_engine_new();
    if (!m_engine)
    {
        Log("[错误] 无法创建扫描引擎");
        return false;
    }

    // 设置证书目录
    ret = cl_engine_set_str(m_engine, CL_ENGINE_CVDCERTSDIR, certsPath.c_str());
    if (ret != CL_SUCCESS)
    {
        Log("[错误] 证书配置失败");
        cl_engine_free(m_engine);
        m_engine = nullptr;
        return false;
    }

    unsigned int sigs = 0;
    ret = cl_load(dbPath.c_str(), m_engine, &sigs, CL_DB_STDOPT);

    if (ret != CL_SUCCESS)
    {
        Log("[错误] 病毒库加载失败");
        cl_engine_free(m_engine);
        m_engine = nullptr;
        return false;
    }

    ret = cl_engine_compile(m_engine);
    if (ret != CL_SUCCESS)
    {
        Log("[错误] 引擎编译失败");
        cl_engine_free(m_engine);
        m_engine = nullptr;
        return false;
    }

    // 只输出一行简洁的成功信息
    Log("[引擎] ClamAV " + std::string(cl_retver()) + " | 病毒库:  " + std::to_string(sigs) + " 个签名");

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
    unsigned long int scanned = 0;

    struct cl_scan_options options;
    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse = ~0;
    options.general = CL_SCAN_GENERAL_ALLMATCHES | CL_SCAN_GENERAL_HEURISTICS;

    cl_error_t ret = cl_scanfile(
        filePath.c_str(),
        &virname,
        &scanned,
        m_engine,
        &options
    );

    if (ret == CL_VIRUS)
    {
        result = std::string("发现威胁: ") + (virname ? virname : "未知威胁");
        return true;
    }
    else if (ret == CL_CLEAN)
    {
        result = "安全";
        return true;
    }
    else
    {
        result = std::string("扫描错误: ") + cl_strerror(ret);
        return false;
    }
}