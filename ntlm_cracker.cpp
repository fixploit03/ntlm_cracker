#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <openssl/md4.h>
#include <unistd.h> // untuk getopt
#include <algorithm> // untuk std::remove

// Fungsi untuk mengonversi string ke UTF-16LE
std::vector<uint8_t> string_to_utf16le(const std::string& str) {
    std::vector<uint8_t> utf16;
    for (char c : str) {
        utf16.push_back(static_cast<uint8_t>(c)); // Byte rendah
        utf16.push_back(0);                       // Byte tinggi (0 untuk ASCII)
    }
    return utf16;
}

// Fungsi untuk menghitung hash MD4
std::string compute_md4(const std::vector<uint8_t>& data) {
    MD4_CTX ctx;
    MD4_Init(&ctx);
    MD4_Update(&ctx, data.data(), data.size());
    unsigned char hash[MD4_DIGEST_LENGTH];
    MD4_Final(hash, &ctx);
    std::stringstream ss;
    for (int i = 0; i < MD4_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int main(int argc, char* argv[]) {
    std::string hash_target;
    std::string wordlist_file;
    int opt;

    // Parsing argumen baris perintah
    while ((opt = getopt(argc, argv, "h:w:")) != -1) {
        switch (opt) {
            case 'h':
                hash_target = optarg;
                break;
            case 'w':
                wordlist_file = optarg;
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " -h <hash> -w <wordlist>\n";
                return 1;
        }
    }

    // Validasi input
    if (hash_target.empty() || wordlist_file.empty()) {
        std::cerr << "Error: Both -h <hash> and -w <wordlist> are required.\n";
        return 1;
    }

    // Buka file wordlist
    std::ifstream fp(wordlist_file);
    if (!fp.is_open()) {
        std::cerr << "Error: Could not open wordlist file: " << wordlist_file << "\n";
        return 1;
    }

    std::string line;
    while (std::getline(fp, line)) {
        // Hilangkan karakter newline atau carriage return
        line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
        line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());

        // Konversi kata sandi ke UTF-16LE
        std::vector<uint8_t> utf16 = string_to_utf16le(line);

        // Hitung hash MD4
        std::string hash = compute_md4(utf16);

        // Bandingkan dengan hash target (case-insensitive)
        if (strcasecmp(hash.c_str(), hash_target.c_str()) == 0) {
            std::cout << "Password found: " << line << "\n";
            fp.close();
            return 0;
        }
    }

    fp.close();
    std::cout << "Password not found in wordlist.\n";
    return 0;
}
