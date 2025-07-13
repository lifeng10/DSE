#include "ShiftableEncryption.h"

// 构造函数实现
ShiftableEncryption::ShiftableEncryption(Pairing& pairing) : e(pairing) {
    g = G1(e, false);       // random G1 element
    Zr r(e, true);          // random Zr element
    c0 = g ^ r;
    g_zero = G1(e, true);   // identity element (zero)
    g_one = g;              // g itself is the generator (unit)
    g_minus_one = g.inverse(); // negative unit element
}

// DKGen: derive secret key by hashing string into Zr
Zr ShiftableEncryption::DKGen(const std::string& key) {
    return Zr(e, key.c_str(), key.length());
}

// EKGen: public key = g^dk
G1 ShiftableEncryption::EKGen(const Zr& dk) {
    return g ^ dk;
}

// Expand: compute ci[i] = c0^dk[i]
void ShiftableEncryption::Expand(const std::map<std::string, Zr>& DK) {
    for (const auto& kv : DK) {
        ci[kv.first] = c0 ^ kv.second;
    }
}

// Shift: update c0 and ci with delta and re-randomization
void ShiftableEncryption::Shift(const std::map<std::string, G1>& EK,
                               const std::map<std::string, G1>& DELTA,
                               const Zr& r) {
    c0 = (g ^ r) * c0;
    for (const auto& kv : EK) {
        const std::string& id = kv.first;
        ci[id] = ci[id] * ((EK.at(id) ^ r) * DELTA.at(id));
    }
}

// Decrypt: compute ci[i] / (c0 ^ dk[i])
std::map<std::string, G1> ShiftableEncryption::Decrypt(const std::map<std::string, Zr>& DK) {
    std::map<std::string, G1> result;
    for (const auto& kv : DK) {
        const std::string& id = kv.first;
        G1 m = ci.at(id) / (c0 ^ kv.second);
        result[id] = m;
    }
    return result;
}

// Dump: output ciphertext (for debugging)
void ShiftableEncryption::Dump() {
    c0.dump(stdout, "c0: ", 16);
    for (const auto& kv : ci) {
        kv.second.dump(stdout, ("ci[" + kv.first + "]: ").c_str(), 16);
    }
}
