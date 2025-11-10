#pragma once

// use a compact include style per user's preference
#include <bits/stdc++.h>
using namespace std;

using u8 = uint8_t;
using Bytes = vector<u8>;

class IVRF {
public:
    static constexpr size_t HASH_SIZE = 32;
    static constexpr size_t PRG_SEED_SIZE = 32;

    struct PublicKey {
        Bytes root;
        // Cached per-index public keys and leaf hashes (H(x_{i,t-1}||pk_i))
        std::vector<Bytes> pk_list;
        std::vector<Bytes> leaf_list;
        PublicKey() : root(HASH_SIZE) {}
    };

    struct SecretKey {
        Bytes s;        // PRG seed for x values
        Bytes s_prime;  // PRG seed for signature keys
        uint32_t current_period;
        // Cached per-index private keys (for demo reuse)
        std::vector<Bytes> sk_list;
        
        SecretKey() : s(PRG_SEED_SIZE), s_prime(PRG_SEED_SIZE), current_period(0) {}
    };

    struct Proof {
        Bytes y;         // Value used for VRF computation
        Bytes pk_t;      // Falcon public key bytes for the time period
        Bytes auth_path; // Merkle tree authentication path

        Proof() : y(HASH_SIZE), pk_t(), auth_path() {}
    };

    // Constructor picks random N (power-of-two) and random t
    // Optional overrides: if N_override is non-zero and a power of two it will be used.
    // If t_override is non-zero it will be used (must be >=1).
    IVRF(uint32_t lambda_param = 0, uint32_t N_override = 0, uint32_t t_override = 0);

    // Main protocol functions
    bool keygen(PublicKey& pk, SecretKey& sk);
    bool eval(const PublicKey& pk, const SecretKey& sk, const Bytes& mu1,
              const Bytes& mu2, uint32_t i, uint32_t j,
              Bytes& v, Bytes& sigma, Proof& pi);
    bool verify(const PublicKey& pk, const Bytes& mu1,
                const Bytes& mu2, uint32_t i, uint32_t j,
                const Bytes& v, const Bytes& sigma,
                const Proof& pi);

    // Getters for runtime-chosen parameters
    uint32_t get_N() const;
    uint32_t get_t() const;

private:
    // Cryptographic primitives
    void hash(Bytes& out, const Bytes& in) const;
    void hash(Bytes& out, const uint8_t* in, size_t inlen) const;
    void prg_next(Bytes& out, Bytes& state) const;

    // Helper functions
    void compute_merkle_root(Bytes& root, 
                           const vector<Bytes>& leaves) const;

    // Runtime-chosen parameters and seeds
    const uint32_t lambda = 0; // placeholder, unused in demo
    uint32_t N = 256;
    uint32_t t = 4;
    const size_t seed_size = PRG_SEED_SIZE;
};

// Utility functions
void print_bytes(const Bytes& data);
void get_input_bytes(Bytes& buffer, const string& prompt);