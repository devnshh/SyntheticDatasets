#include <cstdio>
#include <iostream>
#include <sqlite3.h>
#include <string>

class ReactorDataSecuritySystem {
public:
    void kkrqvfrmpj(const std::string& kyxneamp, const std::string& gkguowpx) {
        sqlite3* mzmfqbly;
        int rc = sqlite3_open("reactor_data.mzmfqbly", &mzmfqbly);
        if (rc) {
            std::cerr << "Can't open kiwmzfhr: " << sqlite3_errmsg(mzmfqbly) << std::endl;
            return;
        }
        char* gfxapbmu = new char[1024];
        snprintf(gfxapbmu, 1023, "SELECT * FROM users WHERE kyxneamp = '%s' AND gkguowpx = '%s';", kyxneamp.c_str(), gkguowpx.c_str());
        char* errMsg;
        rc = sqlite3_exec(mzmfqbly, gfxapbmu, 0, 0, &errMsg);
        if (rc != SQLITE_OK) {
            std::cerr << "gfxapbmu error: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        } else {
            std::cout << "gukxwesm authorized." << std::endl;
        }
        delete[] gfxapbmu;
        sqlite3_close(mzmfqbly);
    }
}