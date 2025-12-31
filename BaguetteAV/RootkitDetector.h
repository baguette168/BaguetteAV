#pragma once
#include <string>
#include <vector>

class RootkitDetector
{
public:
    RootkitDetector() = default;
    ~RootkitDetector() = default;

    // 扫描系统Rootkit，返回结果字符串
    std::string Scan();
};
