/*
 * NTLM Hash Cracker
 * Author: Rofi (Fixploit03)
 * GitHub: https://github.com/fixploit03/ntlm_cracker
 *
 *  MIT License
 *
 *  Copyright (c) 2025 fixploit03
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
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
#include <cstring>

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
            if (n == 0) {
                throw std::invalid_argument("Bloom Filter size cannot be zero");
            }
            if (false_positive_rate <= 0 || false_positive_rate >= 1) {
                throw std::invalid_argument("False positive rate must be between 0 and 1");
            }
            double calc_size = -n * log(false_positive_rate) / (log(2) * log(2));
            size = static_cast<size_t>(calc_size);
            if (size < n) size = n * 10;
            if (size > 1000000000) {
                std::cerr << "[-] Warning: Bloom Filter size capped at 1 billion\n";
                size = 1000000000;
            }
            num_hashes = static_cast<size_t>(size * log(2) / n);
            if (num_hashes < 2) num_hashes = 2;
            bits.resize(size, false);
        } catch (const std::bad_alloc& e) {
            throw std::runtime_error("Memory allocation failed for Bloom Filter: " + std::string(e.what()));
        } catch (const std::invalid_argument& e) {
            throw std::runtime_error("Invalid argument for Bloom Filter: " + std::string(e.what()));
        } catch (const std::exception& e) {
            throw std::runtime_error("Unexpected error initializing Bloom Filter: " + std::string(e.what()));
        }
    }

    void add(const std::string& str) {
        try {
            bits.at(hash1(str)) = true;
            bits.at(hash2(str)) = true;
        } catch (const std::out_of_range& e) {
            std::cerr << "[-] Error: Bloom Filter index out of range: " << e.what() << "\n";
            throw;
        }
    }

    bool might_contain(const std::string& str) const {
        try {
            return bits.at(hash1(str)) && bits.at(hash2(str));
        } catch (const std::out_of_range& e) {
            std::cerr << "[-] Error: Bloom Filter index out of range: " << e.what() << "\n";
            return false;
        }
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
    time_t now = time(nullptr);
    tm* local_time = localtime(&now);
    if (!local_time) {
        std::cerr << "[-] Warning: Failed to retrieve local time\n";
        return "00:00:00 /0000-00-00/";
    }
    std::stringstream ss;
    try {
        ss << std::setfill('0') << std::setw(2) << local_time->tm_hour << ":"
           << std::setfill('0') << std::setw(2) << local_time->tm_min << ":"
           << std::setfill('0') << std::setw(2) << local_time->tm_sec << " /"
           << (local_time->tm_year + 1900) << "-"
           << std::setfill('0') << std::setw(2) << (local_time->tm_mon + 1) << "-"
           << std::setfill('0') << std::setw(2) << local_time->tm_mday << "/";
    } catch (const std::exception& e) {
        std::cerr << "[-] Error: Failed to format timestamp: " << e.what() << "\n";
        return "00:00:00 /0000-00-00/";
    }
    return ss.str();
}

std::vector<uint8_t> string_to_utf16le(const std::string& str) {
    std::vector<uint8_t> utf16;
    try {
        if (str.empty()) {
            std::cerr << "[-] Warning: Empty string passed to UTF-16LE conversion\n";
            return utf16;
        }
        size_t required_size = str.size() * 2;
        if (required_size / 2 != str.size()) {
            throw std::overflow_error("Input string too large for UTF-16LE conversion");
        }
        utf16.reserve(required_size);
        for (char c : str) {
            utf16.push_back(static_cast<uint8_t>(c));
            utf16.push_back(0);
        }
    } catch (const std::overflow_error& e) {
        throw std::runtime_error("Overflow in UTF-16LE conversion: " + std::string(e.what()));
    } catch (const std::bad_alloc& e) {
        throw std::runtime_error("Memory allocation failed in UTF-16LE conversion: " + std::string(e.what()));
    } catch (const std::exception& e) {
        throw std::runtime_error("Unexpected error in UTF-16LE conversion: " + std::string(e.what()));
    }
    return utf16;
}

std::string compute_md4(const std::vector<uint8_t>& data) {
    EVP_MD_CTX* ctx = nullptr;
    try {
        if (data.empty()) {
            throw std::invalid_argument("Empty data passed to MD4 computation");
        }
        ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create EVP_MD_CTX");

        const EVP_MD* md = EVP_md4();
        if (!md) throw std::runtime_error("MD4 not supported by OpenSSL");

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;

        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
            throw std::runtime_error("Failed to initialize MD4 digest");
        }
        if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
            throw std::runtime_error("Failed to update MD4 digest");
        }
        if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
            throw std::runtime_error("Failed to finalize MD4 digest");
        }

        EVP_MD_CTX_free(ctx);
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < hash_len; ++i) {
            ss << std::setw(2) << static_cast<int>(hash[i]);
        }
        return ss.str();
    } catch (const std::exception& e) {
        if (ctx) EVP_MD_CTX_free(ctx);
        throw std::runtime_error("MD4 computation failed: " + std::string(e.what()));
    }
}

std::vector<HashEntry> read_hashdump_file(const std::string& filename) {
    std::vector<HashEntry> entries;
    std::ifstream file(filename);
    std::unordered_map<std::string, std::string> seen_hashes;
    try {
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open hash file: " + filename + " (" + strerror(errno) + ")");
        }

        std::string line;
        size_t line_num = 0;
        while (getline(file, line)) {
            line_num++;
            line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
            line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
            if (line.empty()) continue;

            std::stringstream ss(line);
            std::string username, rid, lm_hash, ntlm_hash, temp;
            if (!getline(ss, username, ':') || username.empty() ||
                !getline(ss, rid, ':') || rid.empty() ||
                !getline(ss, lm_hash, ':') || lm_hash.empty() ||
                !getline(ss, ntlm_hash, ':') || ntlm_hash.size() != 32 ||
                (getline(ss, temp) && temp != "::")) {
                std::cerr << "[-] Warning: Invalid format on line " << line_num << " in " << filename << "\n";
                continue;
            }
            if (!std::all_of(ntlm_hash.begin(), ntlm_hash.end(), ::isxdigit)) {
                std::cerr << "[-] Warning: NTLM hash contains non-hex characters on line " << line_num << "\n";
                continue;
            }
            if (seen_hashes.find(ntlm_hash) != seen_hashes.end()) {
                std::cerr << "[-] Warning: Duplicate NTLM hash found for '" << username << "' at line " << line_num << "\n";
                continue;
            }
            seen_hashes[ntlm_hash] = username;
            entries.push_back({username, ntlm_hash});
        }
        if (file.bad()) {
            throw std::runtime_error("I/O error while reading " + filename);
        }
        file.close();
        if (entries.empty()) {
            throw std::runtime_error("No valid hash entries found in " + filename);
        }
    } catch (const std::exception& e) {
        if (file.is_open()) file.close();
        throw std::runtime_error("Error reading hash file: " + std::string(e.what()));
    }
    return entries;
}

void crack_segment(const char* wordlist_data, off_t start, off_t end,
                   const std::unordered_map<std::string, std::string>& hash_to_user,
                   const BloomFilter& bloom) {
    std::string line;
    try {
        if (!wordlist_data) {
            throw std::invalid_argument("Null wordlist data pointer");
        }
        if (start < 0 || end < start) {
            throw std::out_of_range("Invalid segment range: " + std::to_string(start) + " to " + std::to_string(end));
        }
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
                            password_found = true;
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
                    password_found = true;
                }
            }
        }
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(mtx);
        std::cerr << "[-] Error in cracking segment " << start << "-" << end << ": " << e.what() << "\n";
    }
}

int main(int argc, char* argv[]) {
    std::string hash_file, wordlist_file;
    int opt;
    int fd = -1;
    char* wordlist_data = nullptr;
    off_t file_size = 0;

    opterr = 0;

    while ((opt = getopt(argc, argv, "f:w:")) != -1) {
        switch (opt) {
            case 'f':
                hash_file = optarg;
                break;
            case 'w':
                wordlist_file = optarg;
                break;
            case '?': 
                std::cout << "Usage: " << argv[0] << " -f <hash_file> -w <wordlist>\n";
                return 1;
            default:
                std::cout << "Usage: " << argv[0] << " -f <hash_file> -w <wordlist>\n";
                return 1;
        }
    }

    if (hash_file.empty() || wordlist_file.empty() || optind < argc) {
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

        fd = open(wordlist_file.c_str(), O_RDONLY);
        if (fd == -1) {
            throw std::runtime_error("Failed to open wordlist file: " + wordlist_file + " (" + strerror(errno) + ")");
        }

        file_size = lseek(fd, 0, SEEK_END);
        if (file_size == -1) {
            throw std::runtime_error("Failed to determine wordlist file size: " + std::string(strerror(errno)));
        }
        if (file_size == 0) {
            throw std::runtime_error("Wordlist file is empty: " + wordlist_file);
        }

        wordlist_data = static_cast<char*>(mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0));
        if (wordlist_data == MAP_FAILED) {
            throw std::runtime_error("Failed to map wordlist file into memory: " + std::string(strerror(errno)));
        }

        std::cout << "[*] Counting passwords to be attempted...\n";
        total_words = std::count(wordlist_data, wordlist_data + file_size, '\n');
        if (total_words == 0) {
            throw std::runtime_error("Wordlist file contains no valid entries");
        }
        std::cout << "[+] Number of passwords to be attempted: " << total_words << "\n";

        std::cout << "[*] Cracking hashes...\n";
        unsigned int num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) {
            std::cerr << "[-] Warning: Could not detect hardware concurrency, defaulting to 4 threads\n";
            num_threads = 4;
        }
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
            std::cout << "[-] No passwords were found in the wordlist.\n";
        }

        std::cout << "[*] Finished\n";
        std::cout << "\n[*] Ending at " << get_timestamp() << "\n";

        if (munmap(wordlist_data, file_size) == -1) {
            std::cerr << "[-] Warning: Failed to unmap wordlist memory: " << strerror(errno) << "\n";
        }
        close(fd);

    } catch (const std::exception& e) {
        std::cerr << "[-] Fatal error: " << e.what() << "\n";
        if (wordlist_data && munmap(wordlist_data, file_size) == -1) {
            std::cerr << "[-] Warning: Failed to unmap wordlist memory: " << strerror(errno) << "\n";
        }
        if (fd != -1) close(fd);
        return 1;
    }

    return 0;
}
