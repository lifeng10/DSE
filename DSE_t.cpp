#include "ShiftableEncryption.h"
#include "BF_IBE.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <iomanip>
#include <set>

// PRF: HMAC-SHA256，输出就是一个32字节的 std::string，可直接作为新密钥
std::string SimplePRF(const std::string& key, const std::string& message) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len = 0;

    HMAC(
        EVP_sha256(),
        key.data(), key.size(),
        reinterpret_cast<const unsigned char*>(message.data()), message.size(),
        result, &result_len
    );

    return std::string(reinterpret_cast<char*>(result), result_len); // 返回二进制 string（32 字节）
}

// 辅助函数：将字节串打印为 hex
void printHex(const std::string& data) {
    for (unsigned char c : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)c;
    }
    std::cout << std::dec << std::endl;
}

struct IBE_Ciphertext{
    G2 U;
    Zr V;
    Zr W;
};

void Delegate(
    BF_IBE& ibe,
    ShiftableEncryption& mse,
    const std::string& msk,
    std::map<std::string, std::string>& W_cloud,
    std::map<std::string, uint32_t>& CNT_query,
    std::map<std::string, BF_IBE::PublicKey>& PK_IBE,
    std::map<std::string, BF_IBE::SecretKey>& SK_IBE,
    std::map<std::string, G1>& PK_SME,
    std::map<std::string, Zr>& SK_SME,
    std::map<std::string, std::string>& SK_EDB,
    const std::set<std::string>& Wcal_edit,
    const std::set<std::string>& Wcal_query   
) {
    for (const auto& kw : Wcal_edit)
    {
        uint32_t flag = 0;
        if (W_cloud.count(kw) == 0) {   // If keyword not in cloud
            W_cloud[kw] = kw; // Assign new index
            CNT_query[W_cloud[kw]] = 0; // Initialize query count
            flag = 1; // New keyword added
        }
        string kw_idx = W_cloud[kw];

        //? Generate IBE key pair for new keyword
        BF_IBE::PublicKey pk;
        BF_IBE::SecretKey sk;
        ibe.setup(pk, sk); // Generate public key for new keyword
        PK_IBE[kw_idx] = pk; // Store public key
        SK_IBE[kw_idx] = sk;

        //? Generate SME key pair for new keyword
        SK_SME[kw_idx] = mse.DKGen(msk + kw + "SME");
        PK_SME[kw_idx] = mse.EKGen(SK_SME[kw_idx]);

        //? Generate EDB key for new keyword
        SK_EDB[kw_idx] = SimplePRF(msk, "dict" + kw + "0");

        if (flag == 1)
        {
            map<string, Zr> DK_temp = {{kw_idx, SK_SME[kw_idx]}};
            mse.Expand(DK_temp);
        }
        
    }
}

void UpdateToken(
    BF_IBE& ibe,
    ShiftableEncryption& mse,
    const std::map<std::string, std::string>& ID_W_edit,
    map<string, string>& W_cloud,
    std::map<std::string, IBE_Ciphertext>& update_dict,
    std::map<std::string, Zr>& SK_SME,
    Pairing& pairing_symmetric,
    Pairing& pairing_asymmetric,
    std::map<std::string, G1>& PK_SME,
    std::map<std::string, uint32_t>& CNT_query,
    std::map<std::string, std::string>& SK_EDB,
    std::map<std::string, BF_IBE::PublicKey>& PK_IBE
) {
    map<string, Zr> SK_SME_current_edit;
    string IK_EDB;
    for (const auto& kv : ID_W_edit) {
        SK_SME_current_edit[kv.first] = SK_SME[kv.first];
    }

    // Decrypt update keyword count
    map<string, G1> CNT_update;
    CNT_update = mse.Decrypt(SK_SME_current_edit);

    map<std::string, G1> DELTA;
    for (const auto& kv : W_cloud) {
        string kw_idx = kv.second;
        if (ID_W_edit.count(kw_idx) > 0) {
            DELTA[kw_idx] = mse.g_one;
        } else {
            DELTA[kw_idx] = mse.g_zero; // 这里用单位元模拟
        }
    }

    Zr r(pairing_symmetric, true); // 随机 r
    mse.Shift(PK_SME, DELTA, r);

    map<string, IBE_Ciphertext> update_dict;
    for (const auto& kv : ID_W_edit) {
        string kw_idx = kv.first;
        IK_EDB = SimplePRF(SK_EDB[kw_idx], to_string(CNT_query[kw_idx]));
        G1 increasement(CNT_update[kw_idx] * mse.g_one); // 增量
        string addr = SimplePRF(IK_EDB, increasement.toString(false));
        IBE_Ciphertext cipher;
        Zr sig(pairing_asymmetric);
        GT g_id_r(pairing_asymmetric);
        ibe.encrypt(PK_IBE[kw_idx], to_string(CNT_query[kw_idx]), kv.second,
            cipher.U, cipher.V, cipher.W, sig, g_id_r);
        update_dict[addr] = cipher; // 存储更新后的密文
    }
}

void Update(
    std::map<std::string, IBE_Ciphertext>& EDB,
    const std::map<std::string, IBE_Ciphertext>& update_dict
) {
    for (const auto& kv : update_dict) {
        EDB[kv.first] = kv.second; // 更新 EDB
    }
}

void SearchToken(
    BF_IBE& ibe,
    ShiftableEncryption& mse,
    const std::vector<std::string>& ID_W_search,
    const std::map<std::string, Zr>& SK_SME_current_search,
    const std::map<std::string, G1>& PK_SME,
    const std::map<std::string, BF_IBE::PublicKey>& PK_IBE,
    const Pairing& pairing_asymmetric
) {
    // 这里可以实现搜索令牌的逻辑
    // 例如，使用 SK_SME_current_search 和 PK_SME 来生成搜索令牌
}

void Search(
    const std::map<std::string, IBE_Ciphertext>& EDB,
    const std::vector<std::string>& ID_W_search,
    const std::map<std::string, Zr>& SK_SME_current_search,
    const std::map<std::string, G1>& PK_SME,
    const Pairing& pairing_asymmetric
) {
    // 这里可以实现搜索的逻辑
    // 例如，使用 EDB 和搜索令牌来查找匹配的密文
}


int main(){
    // Initialize sysmetric pairing for SME
    FILE* paramF = fopen("../pbcwrapper/pairing.param", "r");
    if (!paramF) {
        std::cerr << "Cannot open pairing.param\n";
        return 1;
    }
    Pairing pairing_symmetric(paramF);
    // cout<<"Is symmetric? "<< pairing_symmetric.isSymmetric()<< endl;
    // cout<<"Is pairing present? "<< pairing_symmetric.isPairingPresent()<< endl;
    fclose(paramF);

    // Initialize asymmetric pairing for BF-IBE
    paramF = fopen("../pbcwrapper/a1.param", "r");
    if (!paramF) {
        std::cerr << "Cannot open a1.param\n";
        return 1;
    }
    Pairing pairing_asymmetric(paramF);
    // cout<<"Is symmetric? "<< pairing_asymmetric.isSymmetric()<< endl;
    // cout<<"Is pairing present? "<< pairing_asymmetric.isPairingPresent()<< endl;
    fclose(paramF);

    //! Setup
    BF_IBE ibe(pairing_asymmetric);
    ShiftableEncryption mse(pairing_symmetric);
    string msk = "master secret key";
    map<string, string> W_cloud;
    map<string, uint32_t> CNT_query;
    map<string, BF_IBE::PublicKey> PK_IBE;
    map<string, BF_IBE::SecretKey> SK_IBE;
    map<string, G1> PK_SME;
    map<string, Zr> SK_SME;
    map<string, string> SK_EDB;
    set<string> Wcal_query;
    set<string> Wcal_edit;
    map<string, IBE_Ciphertext> EDB;

    //! Delegate
    for (const auto& kw : Wcal_edit)
    {
        uint32_t flag = 0;
        if (W_cloud.count(kw) == 0) {   // If keyword not in cloud
            W_cloud[kw] = kw; // Assign new index
            CNT_query[W_cloud[kw]] = 0; // Initialize query count
            flag = 1; // New keyword added
        }
        string kw_idx = W_cloud[kw];

        //? Generate IBE key pair for new keyword
        BF_IBE::PublicKey pk;
        BF_IBE::SecretKey sk;
        ibe.setup(pk, sk); // Generate public key for new keyword
        PK_IBE[kw_idx] = pk; // Store public key
        SK_IBE[kw_idx] = sk;

        //? Generate SME key pair for new keyword
        SK_SME[kw_idx] = mse.DKGen(msk + kw + "SME");
        PK_SME[kw_idx] = mse.EKGen(SK_SME[kw_idx]);

        //? Generate EDB key for new keyword
        SK_EDB[kw_idx] = SimplePRF(msk, "dict" + kw + "0");

        if (flag == 1)
        {
            map<string, Zr> DK_temp = {{kw_idx, SK_SME[kw_idx]}};
            mse.Expand(DK_temp);
        }
        
    }
    
    //! Update Token
    map<string, string> ID_W_edit;      // <ciphertext keyword, new_id>
    map<string, Zr> SK_SME_current_edit;
    string IK_EDB;
    for (const auto& kv : ID_W_edit){
        SK_SME_current_edit[kv.first] = SK_SME[kv.first];
    }

    // Decrypt update keyword count
    map<string, G1> CNT_update;
    CNT_update = mse.Decrypt(SK_SME_current_edit);

    map<std::string, G1> DELTA;
    for (const auto& kv : W_cloud) {
        string kw_idx = kv.second;
        if (ID_W_edit.count(kw_idx) > 0) {
            DELTA[kw_idx] = mse.g_one;
        } else {
            DELTA[kw_idx] = mse.g_zero; // 这里用单位元模拟
        }
    }

    Zr r(pairing_symmetric, true); // 随机 r
    mse.Shift(PK_SME, DELTA, r);

    map<string, IBE_Ciphertext> update_dict;
    for (const auto& kv : ID_W_edit) {
        string kw_idx = kv.first;
        IK_EDB = SimplePRF(SK_EDB[kw_idx], to_string(CNT_query[kw_idx]));
        G1 increasement(CNT_update[kw_idx] * mse.g_one); // 增量
        string addr = SimplePRF(IK_EDB, increasement.toString(false));
        IBE_Ciphertext cipher;
        Zr sig(pairing_asymmetric);
        GT g_id_r(pairing_asymmetric);
        ibe.encrypt(PK_IBE[kw_idx], to_string(CNT_query[kw_idx]), kv.second,
            cipher.U, cipher.V, cipher.W, sig, g_id_r);
        update_dict[addr] = cipher; // 存储更新后的密文
    }

    //! Update
    for (const auto& kv : update_dict) {
        EDB[kv.first] = kv.second; // 更新 EDB
    }

    //! Search Token
    vector<string> W_query;      // <ciphertext keyword, new_id>
    map<string, Zr> SK_SME_current_search;
    map<string, BF_IBE::PrivateKey> srchToken_DK;
    map<string, string> srchToken_IK;
    for (const auto& kv : W_query){
        SK_SME_current_search[kv] = SK_SME[kv];
    }

    map<string, G1> CNT_update_search;
    CNT_update_search = mse.Decrypt(SK_SME_current_search);

    for (const auto& kv : W_query)
    {
        BF_IBE::PrivateKey DK_IBE = ibe.extract(SK_IBE[kv], to_string(CNT_query[kv]));
        IK_EDB = SimplePRF(SK_EDB[kv], to_string(CNT_query[kv]));
        srchToken_DK[kv] = DK_IBE;
        srchToken_IK[kv] = IK_EDB;
    }

    //! Search
    set<string> result;
    for (const auto& kw : W_query) {
        
    }
}