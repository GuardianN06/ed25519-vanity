#include <windows.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <random>
#include <thread>
#include <atomic>
#include <chrono>
#include <vector>
#include <fstream>

typedef int (*sodium_init_func)();
typedef void (*randombytes_buf_func)(void*, size_t);
typedef void (*crypto_sign_seed_keypair_func)(unsigned char*, unsigned char*, const unsigned char*);

std::string to_hex(const unsigned char* data, size_t length) {
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return oss.str();
}

void brute_force_task(const std::string& desired_prefix, std::atomic<bool>& found, std::atomic<int>& attempts,
    sodium_init_func sodium_init, randombytes_buf_func randombytes_buf,
    crypto_sign_seed_keypair_func crypto_sign_seed_keypair, unsigned char* result_public_key,
    unsigned char* result_secret_key) {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium in thread!" << std::endl;
        return;
    }

    unsigned char seed[32];
    unsigned char public_key[32];
    unsigned char secret_key[64];
    const size_t prefix_length = desired_prefix.size() / 2;

    unsigned char prefix_bytes[16] = {};
    for (size_t i = 0; i < prefix_length; ++i) {
        prefix_bytes[i] = std::stoi(desired_prefix.substr(i * 2, 2), nullptr, 16);
    }

    while (!found.load()) {
        randombytes_buf(seed, sizeof(seed));
        crypto_sign_seed_keypair(public_key, secret_key, seed);
        attempts.fetch_add(1);
        if (std::memcmp(public_key, prefix_bytes, prefix_length) == 0) {
            found.store(true);
            std::memcpy(result_public_key, public_key, 32);
            std::memcpy(result_secret_key, secret_key, 64);
            return;
        }
    }
}


int main() {
    HMODULE hLib = LoadLibraryA("libsodium.dll");
    if (!hLib) {
        std::cerr << "Failed to load libsodium.dll!" << std::endl;
        return 1;
    }

    // Get function pointers
    sodium_init_func sodium_init = (sodium_init_func)GetProcAddress(hLib, "sodium_init");
    randombytes_buf_func randombytes_buf = (randombytes_buf_func)GetProcAddress(hLib, "randombytes_buf");
    crypto_sign_seed_keypair_func crypto_sign_seed_keypair =
        (crypto_sign_seed_keypair_func)GetProcAddress(hLib, "crypto_sign_seed_keypair");

    if (!sodium_init || !randombytes_buf || !crypto_sign_seed_keypair) {
        std::cerr << "Failed to get required functions from libsodium.dll!" << std::endl;
        FreeLibrary(hLib);
        return 1;
    }

    std::string desired_prefix;
    std::cout << "Enter prefix:" << std::endl;
    std::cin >> desired_prefix;
    unsigned char result_public_key[32];
    unsigned char result_secret_key[64];
    std::atomic<bool> found(false);
    std::atomic<int> attempts(0);

    int thread_count = std::thread::hardware_concurrency();
    std::cout << "Using " << thread_count << " threads to search for Ed25519 key pair:" << desired_prefix << std::endl;

    auto start_time = std::chrono::high_resolution_clock::now();

    // use threads for parallelization
    std::vector<std::thread> threads;
    for (int i = 0; i < thread_count; ++i) {
        threads.emplace_back(brute_force_task, std::ref(desired_prefix), std::ref(found), std::ref(attempts),
            sodium_init, randombytes_buf, crypto_sign_seed_keypair, result_public_key,
            result_secret_key);
    }

    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_seconds = end_time - start_time;

    if (found) {
        std::string public_key_hex = to_hex(result_public_key, 32);
        std::string secret_key_hex = to_hex(result_secret_key, 64);

        std::cout << "Found a matching key pair after " << attempts.load() << " attempts!" << std::endl;
        std::cout << "Public Key: " << public_key_hex << std::endl;
        std::cout << "Secret Key: " << secret_key_hex << std::endl;
        std::cout << "Time taken: " << elapsed_seconds.count() << " seconds." << std::endl;

        std::ofstream outfile("key_pair.txt");
        if (outfile.is_open()) {
            outfile << "Public Key: " << public_key_hex << "\n";
            outfile << "Secret Key: " << secret_key_hex << "\n";
            outfile << "Attempts: " << attempts.load() << "\n";
            outfile << "Time Taken: " << elapsed_seconds.count() << " seconds\n";
            outfile.close();
            std::cout << "Key pair saved to key_pair.txt" << std::endl;
        }
        else {
            std::cerr << "Failed to open file for writing!" << std::endl;
        }
    }
    else {
        std::cout << "No matching key pair found." << std::endl;
    }

    FreeLibrary(hLib);
    return 0;
}
