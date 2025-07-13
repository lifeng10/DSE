#ifndef BF_IBE_H
#define BF_IBE_H

#include <iostream>
#include <string>
#include <sstream>
#include <random>
#include <cstring>
#include "pbcwrapper/PBC.h"
#include <gmp.h>

using namespace std;

class BF_IBE {
public:
    struct PublicKey {
        G2 P;
        G2 P2; // s*P
    };

    struct SecretKey {
        Zr s;
    };

    struct PrivateKey {
        G1 id;
        std::string IDstr;
    };

    // 构造函数，传入 Pairing 引用
    BF_IBE(Pairing& pairing);

    // 系统初始化：生成公钥和主密钥
    void setup(PublicKey& pk, SecretKey& sk);

    // 私钥提取：为用户 ID 生成私钥
    PrivateKey extract(const SecretKey& sk, const std::string& ID);

    // 加密函数
    void encrypt(const PublicKey& pk, const std::string& ID, const std::string& M,
                 G2& U, Zr& V, Zr& W, Zr& sig, GT& g_id_r);

    // 解密函数
    std::string decrypt(const PublicKey& pk, const PrivateKey& sk,
                        const G2& U, const Zr& V, const Zr& W);

private:
    Pairing& e;

    // 用于模拟 hash 函数
    Zr hashToZr(const Zr& x);
    Zr hashGTToZn(const GT& gt);

    // 编码和解码消息
    Zr encodeToZn(const std::string& message);
    std::string decodeFromZn(const Zr& x);
};

#endif // BF_IBE_H
