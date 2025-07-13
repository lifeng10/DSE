#include "BF_IBE.h"          // ✅ 包含头文件

using namespace std;

// ✅ 构造函数定义
BF_IBE::BF_IBE(Pairing& pairing) : e(pairing) {}

// ✅ setup 实现
void BF_IBE::setup(PublicKey& pk, SecretKey& sk) {
    sk.s = Zr(e, true);
    pk.P = G2(e, false);
    pk.P2 = pk.P ^ sk.s;
}

// ✅ extract 实现
BF_IBE::PrivateKey BF_IBE::extract(const SecretKey& sk, const string& ID) {
    G1 Qid = G1(e, ID.c_str(), ID.size());
    PrivateKey sk_id;
    sk_id.id = Qid ^ sk.s;
    sk_id.IDstr = ID;
    return sk_id;
}

// ✅ encrypt 实现
void BF_IBE::encrypt(const PublicKey& pk, const string& ID, const string& M,
                     G2& U, Zr& V, Zr& W, Zr& sig, GT& g_id_r) {
    G1 Qid = G1(e, ID.c_str(), ID.size());
    GT g_id = e(Qid, pk.P2);
    sig = Zr(e, true);

    stringstream ss;
    ss << sig.toString() << M;
    Zr r(e, ss.str().c_str(), ss.str().size());

    U = pk.P ^ r;
    g_id_r = g_id ^ r;

    V = sig + hashGTToZn(g_id_r);
    const unsigned char* data = reinterpret_cast<const unsigned char*>(M.c_str());
    Zr encode_M(e, data, M.size());
    W = encode_M + hashToZr(sig);
}

// ✅ decrypt 实现
string BF_IBE::decrypt(const PublicKey& pk, const PrivateKey& sk, const G2& U,
                       const Zr& V, const Zr& W) {
    GT pairing_result = e(sk.id, U);
    Zr sig = V - hashGTToZn(pairing_result);
    Zr dec_M = W - hashToZr(sig);
    string M = dec_M.toString();

    Zr r(e, (sig.toString() + M).c_str(), (sig.toString() + M).size());
    if (U == (pk.P ^ r)) {
         return M;
    } else {
        return "[Decryption Failed]";
    }
}

// ✅ 私有函数定义
Zr BF_IBE::hashToZr(const Zr& x) {
    return x;
}

Zr BF_IBE::hashGTToZn(const GT& gt) {
    return Zr(e, gt.toString().c_str(), gt.toString().size());
}

Zr BF_IBE::encodeToZn(const string& message) {
    return Zr(e, message.c_str(), message.size());
}

string BF_IBE::decodeFromZn(const Zr& x) {
    return x.toString(); // 可替换为真正的反序列化操作
}
