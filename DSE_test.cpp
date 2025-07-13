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

class DSE_Owner {
public:
    ShiftableEncryption MSE;
    BF_IBE IBE;
    string msk;
    map<string, string> W_cloud;
    map<string, BF_IBE::PublicKey> PK_IBE;
    map<string, G1> PK_SME;
    map<string, uint32_t> CNT_query;
public:
    DSE_Owner(ShiftableEncryption& mse_, BF_IBE& ibe_)
        : MSE(mse_), IBE(ibe_) {
        msk = "master secret key";
    }

    void KeyGen(set<string> Wcal_query, set<string> Wcal_edit, map<string, BF_IBE::SecretKey>& client_query_IBE, map<string, string>& client_edit_dict, map<string, Zr>& client_edit_SME) {
        map<string, BF_IBE::SecretKey> SK_IBE;
        map<string, string> SK_dict;
        map<string, Zr> SK_SME;
        for (const auto& kw : Wcal_edit)
        {
            uint32_t flag = 0;
            if (W_cloud.count(kw) == 0) {   // If keyword not in cloud
                W_cloud[kw] = kw; // Assign new index
                CNT_query[W_cloud[kw]] = 0; // Initialize query count
                flag = 1; // New keyword added
            }
            string kw_idx = W_cloud[kw];

            BF_IBE::PublicKey pk;
            BF_IBE::SecretKey sk;
            IBE.setup(pk, sk); // Generate public key for new keyword
            PK_IBE[kw_idx] = pk; // Store public key

            if (Wcal_query.count(kw) > 0) {
                SK_IBE[kw_idx] = sk;
            }

            SK_dict[kw_idx] = SimplePRF(msk, "dict" + kw + "0");
            SK_SME[kw_idx] = MSE.DKGen(msk + kw + "SME");
            PK_SME[kw_idx] = MSE.EKGen(SK_SME[kw_idx]);

            if (flag == 1)
            {
                map<string, Zr> DK_temp = {{kw_idx, SK_SME[kw_idx]}};
                MSE.Expand(DK_temp);
            }
            
            client_query_IBE = SK_IBE;
            client_edit_dict = SK_dict;
            client_edit_SME = SK_SME;
        }
            
    }
};

class DSE_Client{
public:
    map<string, BF_IBE::SecretKey> client_query_IBE;
    map<string, string> client_edit_dict;
    map<string, Zr> client_edit_SME;
    ShiftableEncryption MSE;
    BF_IBE IBE;
    DSE_Owner dse_owner;
public:
    DSE_Client(ShiftableEncryption& mse_, BF_IBE& ibe_, map<string, BF_IBE::SecretKey> query_IBE, map<string, string> edit_dict, map<string, Zr> edit_SME, DSE_Owner &dse_owner_)
        : MSE(mse_), IBE(ibe_), client_query_IBE(query_IBE), client_edit_dict(edit_dict), client_edit_SME(edit_SME), dse_owner(dse_owner_) {}

    map<string, IBE_Ciphertext> UpdtTkn(map<string, string> ID_W_edit, map<string, string> W_cloud){
        map<string, Zr> SK_SME_edit;
        for (const auto& kv : ID_W_edit) {
            SK_SME_edit[kv.first] = client_edit_SME[kv.first];
        }
        
        map<string, G1> CNT_edit;
        CNT_edit = MSE.Decrypt(SK_SME_edit);

        map<std::string, G1> DELTA;
        string kw_idx;
        for (const auto& kv : W_cloud) {
            kw_idx = kv.second;
            if(ID_W_edit.count(kw_idx) > 0 && ())
        }

        Zr r(MSE.e, true); // 随机 r
        MSE.Shift(dse_owner.PK_SME, DELTA, r);

        map<string, IBE_Ciphertext> updt_dict;
        for (const auto& kv : ID_W_edit) {
            
        }

        return updt_dict;
    }

    void SrchTkn(set<string> W_query){

    }
};

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
    BF_IBE ibe(pairing_asymmetric);
    ShiftableEncryption mse(pairing_symmetric);
    //========================= Test Content =================================================
    //========================= Test Content =================================================
    //========================= Test Content =================================================
    //========================= Test Content =================================================
    //========================= Test Content =================================================

    // Initialize DSE_Owner with symmetric pairing and BF-IBE
    DSE_Owner dse_owner(mse, ibe);
    set<string> Wcal_query;
    set<string> Wcal_edit;
    map<string, BF_IBE::SecretKey> client_query_IBE;
    map<string, string> client_edit_dict;
    map<string, Zr> client_edit_SME;
    dse_owner.KeyGen(Wcal_query, Wcal_edit, client_query_IBE, client_edit_dict, client_edit_SME);

    // Initialize DSE_Client with symmetric pairing, BF-IBE, and DSE_Owner
    DSE_Client dse_client(mse, ibe, client_query_IBE, client_edit_dict, client_edit_SME, dse_owner);

    //==================================== Test Content =================================================

    std::string key = "secretkey";
    std::string input = "message to hash";

    printHex(SimplePRF(key, input)); // 打印 PRF 输出
    return 0;
}