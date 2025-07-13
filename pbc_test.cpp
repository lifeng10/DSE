#include "PBC.h" //包含pbcwrapper的头文件PBC.h

int main(int argc, char **argv) {
    //初始化配对变量e
    const char *paramFileName = (argc > 1) ? argv[1] : "../pbcwrapper/pairing.param";
    FILE *sysParamFile = fopen(paramFileName, "r");
    if (sysParamFile == NULL) {
        cerr<<"Can't open the parameter file " << paramFileName << "\n";
        cerr<<"Usage: " << argv[0] << " [paramfile]\n";
        return 0;
    }
    Pairing e(sysParamFile);
    cout<<"Is symmetric? "<< e.isSymmetric()<< endl;
    cout<<"Is pairing present? "<< e.isPairingPresent()<< endl;  
    fclose(sysParamFile);

    G1 g(e, false);
    g.dump(stdout, "G1 element: ", 16);

    G1 g1(e, true);
    g1.dump(stdout, "G1 element: ", 16);

    Zr inverse(e, (long int)-1);
    inverse.dump(stdout, "Inverse Zr: ", 10);

    G1 g_inv = g.inverse();
    g_inv.dump(stdout, "G1 inverse: ", 16);

    G1 g_minus_one(g ^ (Zr(e, (long int)-1)));
    g_minus_one.dump(stdout, "G1 raised to -1: ", 16);

    Zr x(e, true);
    x.dump(stdout, "Zr element: ", 10);

    G1 h(g ^ x);
    h.dump(stdout, "G1 raised to Zr: ", 16);

    GT m(e, false);
    m.dump(stdout, "GT element m: ", 16);

    Zr r(e, true);
    r.dump(stdout, "Random Zr: ", 10);

    G1 c1(g ^ r);
    c1.dump(stdout, "G1 raised to random Zr: ", 16);

    GT c2 = m * (e(h, g)^r);
    c2.dump(stdout, "GT raised to random Zr: ", 16);

    GT decrypted = c2 / (e(c1, g)^x);
    decrypted.dump(stdout, "Decrypted GT: ", 16);

    if (decrypted == m) {
        std::cout << "Decryption successful!" << std::endl;
    } else {
        std::cout << "Decryption failed!" << std::endl;
    }
}