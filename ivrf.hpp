#pragma once

// use a compact include style per user's preference
#include <bits/stdc++.h>
using namespace std;

using u8 = uint8_t;
using Bytes = vector<u8>;

class IVRF {
public:
    static constexpr size_t HASH_SIZE = 32;
    static constexpr size_t PRG_SEED_SIZE = 48;

    struct PublicKey {
        Bytes root;
        std::vector<Bytes> pk_list;
        std::vector<Bytes> leaf_list;
        PublicKey() : root(HASH_SIZE) {}
    };

    struct SecretKey {
        Bytes s;
        Bytes s_prime;
        std::vector<Bytes> sk_list;
        
        SecretKey() : s(PRG_SEED_SIZE), s_prime(PRG_SEED_SIZE) {}
    };

    struct Proof {
        Bytes y;
        Bytes pk_t;
        Bytes auth_path;

        Proof() : y(HASH_SIZE), pk_t(), auth_path() {}
    };

    IVRF(uint32_t N_override = 0, uint32_t t_override = 0);

    bool keygen(PublicKey& pk, SecretKey& sk);
    bool eval(const PublicKey& pk, const SecretKey& sk, const Bytes& mu1,
              const Bytes& mu2, uint32_t i, uint32_t j,
              Bytes& v, Bytes& sigma, Proof& pi);
    bool verify(const PublicKey& pk, const Bytes& mu1,
                const Bytes& mu2, uint32_t i, uint32_t j,
                const Bytes& v, const Bytes& sigma,
                const Proof& pi);

    uint32_t get_N() const;
    uint32_t get_t() const;

private:
    void hash(Bytes& out, const Bytes& in) const;
    void hash(Bytes& out, const uint8_t* in, size_t inlen) const;

    void compute_merkle_root(Bytes& root, const vector<Bytes>& leaves) const;

    uint32_t N = 256;
    uint32_t t = 4;
};

void print_bytes(const Bytes& data);

// Utility function to concatenate two byte arrays
inline Bytes concat_bytes(const Bytes& a, const Bytes& b) {
    Bytes result;
    result.reserve(a.size() + b.size());
    result.insert(result.end(), a.begin(), a.end());
    result.insert(result.end(), b.begin(), b.end());
    return result;
}