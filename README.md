## Install

```
sudo apt install g++ libssl-dev
```

## Compile

```
g++ -o ntlm_cracker ntlm_cracker.cpp -lssl -lcrypto -pthread -std=c++17 -O2
```

# Usage

```
ntlm_cracker -f <hash_file> -w <wordlist> [-o <output_file>] [-h]
```
