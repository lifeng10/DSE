#include "ShiftableEncryption.h"
#include "BF_IBE.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <iomanip>
#include <set>
#include <chrono>

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
    map<string, uint32_t>& Srch_Counter,
    std::map<std::string, BF_IBE::PublicKey>& PK_IBE,
    std::map<std::string, BF_IBE::SecretKey>& SK_IBE,
    std::map<std::string, G1>& PK_SME,
    std::map<std::string, Zr>& SK_SME,
    set<string>& W_search,
    set<string>& W_update,
    map<string, string>& W_universal,
    std::map<std::string, std::string>& SK_EDB
) {
    for (const auto& kw : W_update)
    {
        W_universal[kw] = kw; // 给每个关键字一个别名
        Srch_Counter[kw] = 0; // 初始化查询计数

        string kw_idx = W_universal[kw];
        //todo 给每个关键字生成IBE的公私钥
        BF_IBE::PublicKey pk;
        BF_IBE::SecretKey sk;
        ibe.setup(pk, sk);
        PK_IBE[kw_idx] = pk;
        SK_IBE[kw_idx] = sk;

        //todo 给每个关键字生成SME的公私钥
        SK_SME[kw_idx] = mse.DKGen(msk + kw + "SME");
        PK_SME[kw_idx] = mse.EKGen(SK_SME[kw_idx]);

        //todo 给每个关键字生成EDB的密钥
        SK_EDB[kw_idx] = SimplePRF(msk, "dict" + kw + "0");

        //todo 扩展SME的ci，给每个关键字生成一个密文的更新次数
        map<string, Zr> DK_temp = {{kw_idx, SK_SME[kw_idx]}};
        mse.Expand(DK_temp);
    }
}

void UpdateToken(
    BF_IBE& ibe,
    ShiftableEncryption& mse,
    map<string, uint32_t>& Srch_Counter,
    std::map<std::string, BF_IBE::PublicKey>& PK_IBE,
    std::map<std::string, BF_IBE::SecretKey>& SK_IBE,
    std::map<std::string, G1>& PK_SME,
    std::map<std::string, Zr>& SK_SME,
    std::map<std::string, std::string>& SK_EDB,
    map<string, string>& W_universal,
    string update_keyword,
    string update_doc_id,
    Pairing& pairing_asymmetric,
    map<std::string, G1>& DELTA,
    string& addr,
    IBE_Ciphertext& val
) {
    //todo 获得解密对应该关键字的SME密钥
    map<string, Zr> SK_SME_update;
    string kw_idx = W_universal[update_keyword];
    SK_SME_update[kw_idx] = SK_SME[kw_idx];

    //todo 解密对应该关键字的更新次数（g的幂次）
    map<string, G1> Updt_Counter;
    Updt_Counter = mse.Decrypt(SK_SME_update);

    //todo 构造Delta，获得每次关键字的更新次数的密文
    for (const auto& kv : W_universal) {
        string kw_idx = kv.second;
        if (kw_idx == update_keyword) {
            DELTA[kw_idx] = mse.g_one; // 更新次数增加1
        } else {
            DELTA[kw_idx] = mse.g_zero; // 其他关键字不变
        }
    }

    //todo 生成更新的地址和密文
    string IK_EDB = SimplePRF(SK_EDB[kw_idx], to_string(Srch_Counter[kw_idx]));
    G1 increasement(Updt_Counter[kw_idx] * mse.g_one); // 增量
    addr = SimplePRF(IK_EDB, increasement.toString(false));
    Zr sig(pairing_asymmetric);
    GT g_id_r(pairing_asymmetric);
    ibe.encrypt(PK_IBE[kw_idx], to_string(Srch_Counter[kw_idx]), update_doc_id, val.U, val.V, val.W, sig, g_id_r);
}

void Update(
    ShiftableEncryption& mse,
    Pairing& pairing_symmetric,
    std::map<std::string, G1>& PK_SME,
    map<string, IBE_Ciphertext> EDB,
    map<std::string, G1>& DELTA,
    string& addr,
    IBE_Ciphertext& val
) {
    //todo 更新EDB中的密文
    EDB[addr] = val;

    //todo 更新ShiftableEncryption的ci
    Zr r(pairing_symmetric, true); // 随机 r
    mse.Shift(PK_SME, DELTA, r);
}

void SearchToken(
    BF_IBE& ibe,
    ShiftableEncryption& mse,
    map<string, uint32_t>& Srch_Counter,
    std::map<std::string, BF_IBE::PublicKey>& PK_IBE,
    std::map<std::string, BF_IBE::SecretKey>& SK_IBE,
    std::map<std::string, G1>& PK_SME,
    std::map<std::string, Zr>& SK_SME,
    std::map<std::string, std::string>& SK_EDB,
    map<string, string>& W_universal,
    string search_keyword,
    map<string, G1>& Updt_Counter_srch,
    map<string, BF_IBE::PrivateKey>& srchToken_DK,
    map<string, string>& srchToken_IK
){
    //todo 获得解密对应该关键字的SME密钥
    map<string, Zr> SK_SME_search;
    string kw_idx = W_universal[search_keyword];
    SK_SME_search[kw_idx] = SK_SME[kw_idx];

    //todo 解密对应该关键字的更新次数（g的幂次）
    Updt_Counter_srch = mse.Decrypt(SK_SME_search);
    // //! delete
    // G1 g_counter = Updt_Counter_srch[kw_idx];
    // uint32_t cc = 0;
    // while (true)
    // {
    //     if (g_counter == mse.g_zero) {
    //         cout << "SearchToken cc: " << cc << endl;
    //         break;
    //     }
    //     cc++;
    //     g_counter = g_counter * mse.g_minus_one;
    // }
    

    //todo 生成IBE的密钥
    srchToken_DK[kw_idx] = ibe.extract(SK_IBE[kw_idx], to_string(Srch_Counter[kw_idx]));
    srchToken_IK[kw_idx] = SimplePRF(SK_EDB[kw_idx], to_string(Srch_Counter[kw_idx]));
}

void Search(
    BF_IBE& ibe,
    ShiftableEncryption& mse,
    map<string, uint32_t>& Srch_Counter,
    std::map<std::string, BF_IBE::PublicKey>& PK_IBE,
    std::map<std::string, BF_IBE::SecretKey>& SK_IBE,
    std::map<std::string, G1>& PK_SME,
    std::map<std::string, Zr>& SK_SME,
    std::map<std::string, std::string>& SK_EDB,
    map<string, IBE_Ciphertext> EDB,
    map<string, string>& W_universal,
    string search_keyword,
    map<string, G1>& Updt_Counter_srch,
    map<string, BF_IBE::PrivateKey>& srchToken_DK,
    map<string, string>& srchToken_IK,
    set<string>& results
) {
    //todo search keyword idx
    string kw_idx = W_universal[search_keyword];

    //todo 
    uint32_t srch_counter = 0;
    G1 g_counter = Updt_Counter_srch[kw_idx];
    string addr;
    IBE_Ciphertext val;
    string result_id;
    while (true)
    {
        if (g_counter == mse.g_zero) {
           break;
        }
        
        srch_counter++;
        addr = SimplePRF(srchToken_IK[kw_idx], g_counter.toString(false));
        val = EDB[addr];
        result_id = ibe.decrypt(PK_IBE[kw_idx], srchToken_DK[kw_idx], val.U, val.V, val.W);
        results.insert(result_id); // 将结果添加到集合中
        g_counter = g_counter * mse.g_minus_one; // 更新计数器
    }
}

void Setup(
    BF_IBE& ibe,
    ShiftableEncryption& mse,
    map<string, uint32_t>& Srch_Counter,
    map<string, BF_IBE::PublicKey>& PK_IBE,
    map<string, BF_IBE::SecretKey>& SK_IBE,
    map<string, G1>& PK_SME,
    map<string, Zr>& SK_SME,
    std::map<std::string, std::string>& SK_EDB,
    map<string, string>& W_universal,
    map<string, vector<string>>& update_keyword_id_list,
    Pairing& pairing_asymmetric,
    Pairing& pairing_symmetric,
    map<string, IBE_Ciphertext>& EDB
) {
    map<string, G1> Updt_Counter;
    Updt_Counter = mse.Decrypt(SK_SME); // 解密所有的更新计数器

    map<string, G1> DELTA;
    string addr;
    IBE_Ciphertext val;
    string IK_EDB;
    G1 counter;
    for (const auto& kw : update_keyword_id_list) {
        string kw_idx = W_universal[kw.first];
        vector<string> doc_ids = kw.second;
        counter = Updt_Counter[kw_idx];
        DELTA[kw_idx] = mse.g_zero; // 初始化DELTA为零
        for (const auto& doc_id : doc_ids) {
            counter = counter * mse.g_one; // 增加计数器
            IK_EDB = SimplePRF(SK_EDB[kw_idx], to_string(Srch_Counter[kw_idx]));
            addr = SimplePRF(IK_EDB, counter.toString(false));
            Zr sig(pairing_asymmetric);
            GT g_id_r(pairing_asymmetric);
            ibe.encrypt(PK_IBE[kw_idx], to_string(Srch_Counter[kw_idx]), doc_id, val.U, val.V, val.W, sig, g_id_r);
            EDB[addr] = val; // 存储密文
            DELTA[kw_idx] = DELTA[kw_idx] * mse.g_one; // 更新DELTA
        }
    }
    Zr r(pairing_symmetric, true); // 随机 r
    mse.Shift(PK_SME, DELTA, r); // 更新ShiftableEncryption
}

//! 自动生成 update_keyword_id_list
void generateUpdateKeywordIDList(
    int num_keywords,
    int num_docs_per_keyword,
    std::map<std::string, std::vector<std::string>>& update_keyword_id_list,
    set<string>& W_search_test,
    set<string>& W_update_test
) {
    srand(time(nullptr));  // 用当前时间作为随机种子

    for (int i = 1; i <= num_keywords; ++i) {
        std::string keyword = "kw" + std::to_string(i);
        std::vector<std::string> docs;
        W_search_test.insert(keyword);
        W_update_test.insert(keyword);

        for (int j = 0; j < num_docs_per_keyword; ++j) {
            int doc_id = 1 + j;  // 文档ID在 1~100 之间
            docs.push_back("doc" + std::to_string(doc_id));
        }

        update_keyword_id_list[keyword] = docs;
    }
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

    map<std::string, std::vector<std::string>> update_keyword_id_list;
    set<string> W_search_test;
    set<string> W_update_test;
    int num_keywords = 10; 
    int num_docs_per_keyword = 10; 
    auto start = std::chrono::high_resolution_clock::now();
    generateUpdateKeywordIDList(num_keywords, num_docs_per_keyword, update_keyword_id_list, W_search_test, W_update_test);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Generated " << num_keywords << " keywords with " << num_docs_per_keyword << " documents each in " 
              << duration.count() << " milliseconds." << std::endl;

    //! Setup
    BF_IBE ibe(pairing_asymmetric);
    ShiftableEncryption mse(pairing_symmetric);
    string msk = "master secret key";
    map<string, string> W_universal;
    map<string, uint32_t> Srch_Counter;
    map<string, BF_IBE::PublicKey> PK_IBE;
    map<string, BF_IBE::SecretKey> SK_IBE;
    map<string, G1> PK_SME;
    map<string, Zr> SK_SME;
    map<string, string> SK_EDB;
    map<string, IBE_Ciphertext> EDB;

    //! Delegate
    set<string> W_search;   //设置的跟W_universal一样
    set<string> W_update;   //设置的跟W_universal一样
    W_search = W_search_test;
    W_update = W_update_test;
    start = std::chrono::high_resolution_clock::now();
    Delegate(ibe, mse, msk, Srch_Counter, PK_IBE, SK_IBE, PK_SME, SK_SME, W_search, W_update, W_universal, SK_EDB);
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Delegated " << W_update.size() << " keywords in "
              << duration.count() << " milliseconds." << std::endl;

    //! Setup
    start = std::chrono::high_resolution_clock::now();
    Setup(ibe, mse, Srch_Counter, PK_IBE, SK_IBE, PK_SME, SK_SME, SK_EDB, W_universal, update_keyword_id_list, pairing_asymmetric, pairing_symmetric, EDB);
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Setup completed in " << duration.count() << " milliseconds." << std::endl;

    //! Update Token
    string update_keyword = "apple"; // 假设我们要更新的关键字是 "apple"
    string update_doc_id = "doc111";
    map<std::string, G1> DELTA;
    string addr;
    IBE_Ciphertext val;
    // UpdateToken(ibe, mse, Srch_Counter, PK_IBE, SK_IBE, PK_SME, SK_SME, SK_EDB, W_universal, update_keyword, update_doc_id, pairing_asymmetric, DELTA, addr, val);

    //! Update
    // Update(mse, pairing_symmetric, PK_SME, EDB, DELTA, addr, val);

    //! Search Token
    string search_keyword = "kw1"; // 假设我们要搜索的关键字是 "kw1"
    map<string, G1> Updt_Counter_srch;
    map<string, BF_IBE::PrivateKey> srchToken_DK;
    map<string, string> srchToken_IK;
    start = std::chrono::high_resolution_clock::now();
    SearchToken(ibe, mse, Srch_Counter, PK_IBE, SK_IBE, PK_SME, SK_SME, SK_EDB, W_universal, search_keyword, Updt_Counter_srch, srchToken_DK, srchToken_IK);
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Search token generated for keyword '" << search_keyword << "' in "
              << duration.count() << " milliseconds." << std::endl; 

    //! Search
    set<string> results;
    start = std::chrono::high_resolution_clock::now();
    Search(ibe, mse, Srch_Counter, PK_IBE, SK_IBE, PK_SME, SK_SME, SK_EDB, EDB, W_universal, search_keyword, Updt_Counter_srch, srchToken_DK, srchToken_IK, results);
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Search completed in " << duration.count() << " milliseconds." << std::endl;

    // 输出搜索结果
    // std::cout << "Search results for keyword '" << search_keyword << "':" << std::endl;
    // for (const auto& doc_id : results) {
    //     std::cout << doc_id << std::endl;   // 输出每个文档ID
    // }
    std::cout << "Total search results: " << results.size() << std::endl;

    return 0;
}