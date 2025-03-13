/*
 * NTLM Hash Cracker
 * Author: Rofi (Fixploit03)
 * GitHub: https://github.com/fixploit03/ntlm_cracker
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <openssl/evp.h>
#include <unistd.h>
#include <algorithm>
#include <atomic>
#include <sys/mman.h>
#include <fcntl.h>
#include <cmath>
#include <stdexcept>
#include <ctime>

class BloomFilter {
    std::vector<bool> bits;
    size_t size;
    size_t num_hashes;

    size_t hash1(const std::string& str) const {
        size_t h = 0;
        for (char c : str) h = h * 31 + c;
        return h % size;
    }

    size_t hash2(const std::string& str) const {
        size_t h = 0;
        for (char c : str) h = h * 17 + c;
        return h % size;
    }

public:
    BloomFilter(size_t n, double false_positive_rate = 0.01) {
        try {
            double calc_size = -n * std::log(false_positive_rate) / (std::log(2) * std::log(2));
            size = static_cast<size_t>(calc_size);
            if (size < n) size = n * 10;
            if (size > 1000000000) size = 1000000000;
            num_hashes = static_cast<size_t>(size * std::log(2) / n);
            if (num_hashes < 2) num_hashes = 2;
            bits.resize(size, false);
        } catch (const std::exception& e) {
            throw std::runtime_error("Failed to initialize Bloom Filter: " + std::string(e.what()));
        }
    }

    void add(const std::string& str) {
        bits[hash1(str)] = true;
        bits[hash2(str)] = true;
    }

    bool might_contain(const std::string& str) const {
        return bits[hash1(str)] && bits[hash2(str)];
    }
};

struct HashEntry {
    std::string username;
    std::string ntlm_hash;
};

std::mutex mtx;
std::atomic<size_t> processed_words(0);
std::atomic<bool> password_found(false);
size_t total_words = 0;

std::string get_timestamp() {
    std::time_t now = std::time(nullptr);
    std::tm* local_time = std::localtime(&now);
    if (!local_time) {
        std::cerr << "[-] Warning: Failed to retrieve local time\n";
        return "00:00:00 /0000-00-00/";
    }
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << local_time->tm_hour << ":"
       << std::setfill('0') << std::setw(2) << local_time->tm_min << ":"
       << std::setfill('0') << std::setw(2) << local_time->tm_sec << " /"
       << (local_time->tm_year + 1900) << "-"
       << std::setfill('0') << std::setw(2) << (local_time->tm_mon + 1) << "-"
       << std::setfill('0') << std::setw(2) << local_time->tm_mday << "/";
    return ss.str();
}

std::vector<uint8_t> string_to_utf16le(const std::string& str) {
    std::vector<uint8_t> utf16;
    try {
        utf16.reserve(str.size() * 2);
        for (char c : str) {
            utf16.push_back(static_cast<uint8_t>(c));
            utf16.push_back(0);
        }
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to convert string to UTF-16LE: " + std::string(e.what()));
    }
    return utf16;
}

std::string compute_md4(const std::vector<uint8_t>& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_MD_CTX");

    const EVP_MD* md = EVP_md4();
    if (!md) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("MD4 not supported by OpenSSL");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to compute MD4 hash");
    }

    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::vector<HashEntry> read_hashdump_file(const std::string& filename) {
    std::vector<HashEntry> entries;
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open hash file: " + filename);
    }

    std::string line;
    size_t line_num = 0;
    while (std::getline(file, line)) {
        line_num++;
        line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
        line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
        if (line.empty()) continue;

        std::stringstream ss(line);
        std::string username, rid, lm_hash, ntlm_hash, temp;
        if (!std::getline(ss, username, ':') ||
            !std::getline(ss, rid, ':') ||
            !std::getline(ss, lm_hash, ':') ||
            !std::getline(ss, ntlm_hash, ':')) {
            std::cerr << "[-] Warning: Invalid format on line " << line_num << " in " << filename << "\n";
            continue;
        }
        if (std::getline(ss, temp) && temp != "::") {
            std::cerr << "[-] Warning: Invalid suffix on line " << line_num << " in " << filename << "\n";
            continue;
        }
        if (ntlm_hash.size() != 32) {
            std::cerr << "[-] Warning: Invalid NTLM hash length on line " << line_num << " in " << filename << "\n";
            continue;
        }
        entries.push_back({username, ntlm_hash});
    }
    file.close();
    if (entries.empty()) {
        throw std::runtime_error("No valid hash entries found in " + filename);
    }
    return entries;
}

void crack_segment(const char* wordlist_data, off_t start, off_t end,
                   const std::unordered_map<std::string, std::string>& hash_to_user,
                   const BloomFilter& bloom) {
    std::string line;
    try {
        for (off_t i = start; i < end; ++i) {
            if (wordlist_data[i] == '\n' || wordlist_data[i] == '\r') {
                if (!line.empty()) {
                    std::vector<uint8_t> utf16 = string_to_utf16le(line);
                    std::string hash = compute_md4(utf16);
                    if (bloom.might_contain(hash)) {
                        auto it = hash_to_user.find(hash);
                        if (it != hash_to_user.end()) {
                            std::lock_guard<std::mutex> lock(mtx);
                            std::cout << "[+] Password found for user " << it->second
                                      << " (hash: " << hash << "): " << line << "\n";
                            password_found = true; // Set flag jika kata sandi ditemukan
                        }
                    }
                    line.clear();
                }
                processed_words++;
            } else {
                line += wordlist_data[i];
            }
        }
        if (!line.empty()) {
            std::vector<uint8_t> utf16 = string_to_utf16le(line);
            std::string hash = compute_md4(utf16);
            if (bloom.might_contain(hash)) {
                auto it = hash_to_user.find(hash);
                if (it != hash_to_user.end()) {
                    std::lock_guard<std::mutex> lock(mtx);
                    std::cout << "[+] Password found for user " << it->second
                              << " (hash: " << hash << "): " << line << "\n";
                    password_found = true; // Set flag jika kata sandi ditemukan
                }
            }
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(mtx);
        std::cerr << "[-] Error in cracking segment: " << e.what() << "\n";
    }
}

int main(int argc, char* argv[]) {
    std::string hash_file, wordlist_file;
    int opt;

    while ((opt = getopt(argc, argv, "f:w:")) != -1) {
        switch (opt) {
            case 'f': hash_file = optarg; break;
            case 'w': wordlist_file = optarg; break;
            default:
                std::cout << "Usage: " << argv[0] << " -f <hash_file> -w <wordlist>\n";
                return 1;
        }
    }

    if (optind < argc || hash_file.empty() || wordlist_file.empty()) {
        std::cout << "Usage: " << argv[0] << " -f <hash_file> -w <wordlist>\n";
        return 1;
    }

    try {
        std::cout << "\n[*] Starting at " << get_timestamp() << "\n\n";

        std::cout << "[*] Counting hashes to be cracked...\n";
        std::vector<HashEntry> hash_entries = read_hashdump_file(hash_file);
        std::cout << "[+] Number of hashes to be cracked: " << hash_entries.size() << "\n";

        BloomFilter bloom(hash_entries.size());
        std::unordered_map<std::string, std::string> hash_to_user;
        for (const auto& entry : hash_entries) {
            hash_to_user[entry.ntlm_hash] = entry.username;
            bloom.add(entry.ntlm_hash);
        }

        int fd = open(wordlist_file.c_str(), O_RDONLY);
        if (fd == -1) {
            throw std::runtime_error("Failed to open wordlist file: " + wordlist_file);
        }

        off_t file_size = lseek(fd, 0, SEEK_END);
        if (file_size == -1) {
            close(fd);
            throw std::runtime_error("Failed to determine wordlist file size");
        }

        char* wordlist_data = static_cast<char*>(mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0));
        if (wordlist_data == MAP_FAILED) {
            close(fd);
            throw std::runtime_error("Failed to map wordlist file into memory");
        }

        std::cout << "[*] Counting passwords to be attempted...\n";
        total_words = std::count(wordlist_data, wordlist_data + file_size, '\n');
        if (total_words == 0) {
            munmap(wordlist_data, file_size);
            close(fd);
            throw std::runtime_error("Wordlist file is empty: " + wordlist_file);
        }
        std::cout << "[+] Number of passwords to be attempted: " << total_words << "\n";

        std::cout << "[*] Cracking hashes...\n";
        unsigned int num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 4;
        std::vector<std::thread> threads;

        off_t segment_size = file_size / num_threads;
        for (unsigned int i = 0; i < num_threads; ++i) {
            off_t start = i * segment_size;
            off_t end = (i == num_threads - 1) ? file_size : (i + 1) * segment_size;
            threads.emplace_back(crack_segment, wordlist_data, start, end, std::ref(hash_to_user), std::ref(bloom));
        }

        for (auto& t : threads) {
            t.join();
        }

        if (!password_found) {
            std::cout << "[*] No passwords were found in the wordlist.\n";
        }

        std::cout << "[*] Finished\n";
        std::cout << "\n[*] Ending at " << get_timestamp() << "\n";

        if (munmap(wordlist_data, file_size) == -1) {
            std::cerr << "[-] Warning: Failed to unmap wordlist memory.\n";
        }
        close(fd);

    } catch (const std::exception& e) {
        std::cerr << "[-] Fatal error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
