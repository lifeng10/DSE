#include "PBC.h"
#include "ShiftableEncryption.h"
#include "BF_IBE.h"
#include <iostream>
#include <map>
#include <string>

int main() {
    // 初始化 pairing
    FILE* paramFile = fopen("../pbcwrapper/pairing.param", "r");
    if (!paramFile) {
        std::cerr << "Cannot open pairing.param\n";
        return 1;
    }
    Pairing e(paramFile);
    fclose(paramFile);

    // 创建 ShiftableEncryption 实例
    ShiftableEncryption se(e);

    // 假设有两个用户 Alice 和 Bob
    std::map<std::string, Zr> DK;
    DK["Alice"] = se.DKGen("Alice");
    DK["Bob"] = se.DKGen("Bob");
    DK["Alice"].dump(stdout, "Alice's secret key: ", 16);
    DK["Bob"].dump(stdout, "Bob's secret key: ", 16);

    // 生成公钥
    std::map<std::string, G1> EK;
    for (const auto& kv : DK) {
        EK[kv.first] = se.EKGen(kv.second);
    }
    EK["Alice"].dump(stdout, "Alice's public key: ", 16);
    EK["Bob"].dump(stdout, "Bob's public key: ", 16);

    // 扩展密文
    se.Expand(DK);

    // 输出初始密文
    std::cout << "=== 初始密文 ===" << std::endl;
    se.Dump();

    auto result = se.Decrypt(DK);
    // std::cout << "=== 解密结果 ===" << std::endl;
    // for (const auto& kv : result) {
    //     kv.second.dump(stdout, ("m[" + kv.first + "]: ").c_str(), 16);
    // }

    // 构造 DELTA（这里用单位元模拟）
    std::map<std::string, G1> DELTA;
    for (const auto& kv : DK) {
        DELTA[kv.first] = se.g ^ Zr(e, (long int)1); // 单位元
    }

    // 随机 r
    Zr r(e, true);

    // Shift 操作
    se.Shift(EK, DELTA, r);

    std::cout << "=== Shift 后密文 ===" << std::endl;
    se.Dump();

    // 解密
    result = se.Decrypt(DK);
    std::cout << "=== 解密结果 ===" << std::endl;
    for (const auto& kv : result) {
        kv.second.dump(stdout, ("m[" + kv.first + "]: ").c_str(), 16);
    }

    cout << "=== Shiftable Encryption 完成 ===" << std::endl;

    // cout << "=== IBE 测试 ===" << endl;

    //     // 初始化 pairing
    // FILE* paramFile = fopen("../pbcwrapper/a1.param", "r");
    // if (!paramFile) {
    //     std::cerr << "Cannot open pairing.param\n";
    //     return 1;
    // }
    // Pairing pairing(paramFile);
    // cout<<"Is symmetric? "<< pairing.isSymmetric()<< endl;
    // cout<<"Is pairing present? "<< pairing.isPairingPresent()<< endl;
    // fclose(paramFile);

    // BF_IBE ibe(pairing);
    // BF_IBE::PublicKey pk;
    // BF_IBE::SecretKey sk;
    // ibe.setup(pk, sk);
    // string ID = "user@example.com";
    // auto sk_id = ibe.extract(sk, ID);
    // string message = "Hello World!"; // Example message

    // G2 U;
    // Zr V(pairing), W(pairing), sig(pairing);
    // GT g_id_r(pairing);
    // ibe.encrypt(pk, ID, message, U, V, W, sig, g_id_r);

    // string decrypted = ibe.decrypt(pk, sk_id, U, V, W);
    // cout << "Decrypted message: " << decrypted << endl;
    // cout << "Original message: " << message << endl;

    return 0;
}