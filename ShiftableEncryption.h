#ifndef SHIFTABLE_ENCRYPTION_H
#define SHIFTABLE_ENCRYPTION_H

#include "PBC.h"
#include <iostream>
#include <map>
#include <string>

class ShiftableEncryption {
public:
    Pairing& e;
    G1 g;
    G1 c0;
    G1 g_zero;       // 用于表示零元素
    G1 g_one;        // 用于表示单位元素
    G1 g_minus_one;  // 用于表示负单位元素
    std::map<string, G1> ci;

public:
    // 构造函数，传入Pairing引用
    explicit ShiftableEncryption(Pairing& pairing);

    // DKGen: 通过字符串哈希生成私钥Zr
    Zr DKGen(const std::string& key);

    // EKGen: 公钥生成，g^dk
    G1 EKGen(const Zr& dk);

    // Expand: 计算ci[i] = c0^dk[i]
    void Expand(const std::map<string, Zr>& DK);

    // Shift: 根据DELTA和r更新c0和ci
    void Shift(const std::map<std::string, G1>& EK,
               const std::map<std::string, G1>& DELTA,
               const Zr& r);

    // Decrypt: 计算 ci[i] / (c0 ^ dk[i]) 得到明文
    std::map<std::string, G1> Decrypt(const std::map<std::string, Zr>& DK);

    // 输出密文，用于调试
    void Dump();
};

#endif // SHIFTABLE_ENCRYPTION_H
