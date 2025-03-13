/*
 * NTLM Hash Cracker
 * Author: Rofi (Fixploit03)
 * Github: https://github.com/fixploit03/ntlm_cracker
 *
*/

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <map>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <openssl/evp.h>
#include <unistd.h>
#include <algorithm>
#include <atomic>

struct HashEntry {
    std::string username;
    std::string rid;
    std::string lm_hash;
    std::string ntlm_hash;
};

std::mutex mtx;
size_t total_words = 0;
std::atomic<size_t> processed_words(0);

void print_banner() {
    std::cout << "-------------------------------------------------\n";
    std::cout << "       ╔╗╔╔╦╗╦  ╔╦╗  ╔═╗╦═╗╔═╗╔═╗╦╔═╔═╗╦═╗      \n";
    std::cout << "       ║║║ ║ ║  ║║║  ║  ╠╦╝╠═╣║  ╠╩╗║╣ ╠╦╝\n";
    std::cout << "       ╝╚╝ ╩ ╩═╝╩ ╩  ╚═╝╩╚═╩ ╩╚═╝╩ ╩╚═╝╩╚═\n\n";
    std::cout << "                NTLM Hash Cracker\n";
    std::cout << "              By: Rofi (Fixploit03)\n";
    std::cout << "    https://github.com/fixploit03/ntlm_cracker\n";
    std::cout << "--------------------------------------------------\n\n";
}

void print_help(const char* program_name) {
    print_banner();
    std::cout << "Usage: " << program_name << " -f <hash_file> -w <wordlist> [-o <output_file>] [-h]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -f <hash_file>    Specify the file containing hashdump (format: user:rid:lm:ntlm:::)\n";
    std::cout << "  -w <wordlist>     Specify the wordlist file for dictionary attack\n";
    std::cout << "  -o <output_file>  Specify the output file to save cracked passwords (optional)\n";
    std::cout << "  -h                Show this help message and exit\n\n";
    std::cout << "Example:\n";
    std::cout << "  " << program_name << " -f hash.txt -w /usr/share/wordlists/rockyou -o result.txt\n";
}

std::vector<uint8_t> string_to_utf16le(const std::string& str) {
    std::vector<uint8_t> utf16;
    utf16.reserve(str.size() * 2);
    for (char c : str) {
        utf16.push_back(static_cast<uint8_t>(c));
        utf16.push_back(0);
    }
    return utf16;
}

std::string compute_md4(const std::vector<uint8_t>& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_md4();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << std::setw(2) << (int)hash[i];
    }
    return ss.str();
}

std::vector<HashEntry> read_hashdump_file(const std::string& filename) {
    std::vector<HashEntry> entries;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open hash file: " << filename << "\n";
        return entries;
    }

    std::string line;
    while (std::getline(file, line)) {
        line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
        line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
        if (line.empty()) continue;

        std::stringstream ss(line);
        std::string username, rid, lm_hash, ntlm_hash, temp;
        if (std::getline(ss, username, ':') &&
            std::getline(ss, rid, ':') &&
            std::getline(ss, lm_hash, ':') &&
            std::getline(ss, ntlm_hash, ':')) {
            if (std::getline(ss, temp) && temp == "::") {
                entries.push_back({username, rid, lm_hash, ntlm_hash});
            }
        }
    }
    file.close();
    return entries;
}

void crack_segment(const std::vector<std::string>& wordlist_segment,
                   const std::unordered_map<std::string, std::string>& hash_to_user,
                   std::map<std::string, std::string>& found_passwords) {
    for (const auto& line : wordlist_segment) {
        std::vector<uint8_t> utf16 = string_to_utf16le(line);
        std::string hash = compute_md4(utf16);

        std::lock_guard<std::mutex> lock(mtx);
        processed_words++;
        double progress = (static_cast<double>(processed_words) / total_words) * 100.0;
        std::cout << "\rProgress: " << std::fixed << std::setprecision(2) << progress << "%" << std::flush;

        auto it = hash_to_user.find(hash);
        if (it != hash_to_user.end()) {
            std::cout << "\nPassword found for user " << it->second 
                      << " (hash: " << hash << "): " << line << "\n";
            found_passwords[hash] = line;
        }
    }
}

int main(int argc, char* argv[]) {
    std::string hash_file;
    std::string wordlist_file;
    std::string output_file;
    int opt;

    while ((opt = getopt(argc, argv, "f:w:o:h")) != -1) {
        switch (opt) {
            case 'f': hash_file = optarg; break;
            case 'w': wordlist_file = optarg; break;
            case 'o': output_file = optarg; break;
            case 'h':
                print_help(argv[0]);
                return 0;
            default:
                std::cerr << "Usage: " << argv[0] << " -f <hash_file> -w <wordlist> [-o <output_file>] [-h]\n";
                return 1;
        }
    }

    print_banner();

    if (hash_file.empty() || wordlist_file.empty()) {
        std::cerr << "Error: Both -f <hash_file> and -w <wordlist> are required.\n";
        std::cerr << "Use -h for help.\n";
        return 1;
    }

    std::vector<HashEntry> hash_entries = read_hashdump_file(hash_file);
    if (hash_entries.empty()) {
        std::cerr << "Error: No valid hashdump entries found in file: " << hash_file << "\n";
        return 1;
    }

    std::unordered_map<std::string, std::string> hash_to_user;
    for (const auto& entry : hash_entries) {
        hash_to_user[entry.ntlm_hash] = entry.username;
    }

    std::ifstream fp(wordlist_file);
    if (!fp.is_open()) {
        std::cerr << "Error: Could not open wordlist file: " << wordlist_file << "\n";
        return 1;
    }

    std::vector<std::string> wordlist;
    std::string line;
    while (std::getline(fp, line)) {
        line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
        line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
        if (!line.empty()) wordlist.push_back(line);
    }
    fp.close();

    total_words = wordlist.size();
    if (total_words == 0) {
        std::cerr << "Error: Wordlist is empty.\n";
        return 1;
    }

    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;
    std::vector<std::thread> threads;
    std::map<std::string, std::string> found_passwords;

    std::cout << "Progress: 0.00%" << std::flush;

    size_t segment_size = wordlist.size() / num_threads;
    for (unsigned int i = 0; i < num_threads; ++i) {
        size_t start = i * segment_size;
        size_t end = (i == num_threads - 1) ? wordlist.size() : (i + 1) * segment_size;
        std::vector<std::string> segment(wordlist.begin() + start, wordlist.begin() + end);
        threads.emplace_back(crack_segment, segment, std::ref(hash_to_user), 
                             std::ref(found_passwords));
    }

    for (auto& t : threads) {
        t.join();
    }

    std::cout << "\rProgress: 100.00%\n";

    if (!found_passwords.empty()) {
        std::cout << "\n======= Summary of Found Passwords =======\n\n";
        for (const auto& [hash, password] : found_passwords) {
            std::cout << "[+] " << hash_to_user[hash] << ":" << hash << ":" << password << "\n";
        }
    } else {
        std::cout << "\nNo passwords found for any hash in the file.\n";
    }

    if (!output_file.empty()) {
        std::ofstream out_file(output_file);
        if (!out_file.is_open()) {
            std::cerr << "Error: Could not open output file: " << output_file << "\n";
            return 1;
        }

        if (!found_passwords.empty()) {
            out_file << "======= Summary of Found Passwords =======\n\n";
            for (const auto& [hash, password] : found_passwords) {
                out_file << "[+] " << hash_to_user[hash] << ":" << hash << ":" << password << "\n";
            }
        } else {
            out_file << "No passwords found for any hash in the file.\n";
        }
        out_file.close();
        std::cout << "\n[+] Results saved to: " << output_file << "\n";
    }

    return 0;
}
