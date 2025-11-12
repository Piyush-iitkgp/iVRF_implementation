#include "ivrf.hpp"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <falcon.h>
extern "C" {
#include "drbg_rng.h"
}

using namespace std;

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// RAII wrapper for 64-byte aligned memory required by Falcon operations
struct AlignedBuf {
    void *ptr = nullptr;
    size_t size = 0;
    AlignedBuf(size_t s = 0, size_t align = 64) { if (s) alloc(s, align); }
    void alloc(size_t s, size_t align = 64) {
        free(ptr); ptr = nullptr; size = 0;
        if (posix_memalign(&ptr, align, s) != 0) throw bad_alloc();
        size = s;
    }
    uint8_t* data() { return reinterpret_cast<uint8_t*>(ptr); }
    ~AlignedBuf() { if (ptr) free(ptr); }
};

IVRF::IVRF(uint32_t N_override, uint32_t t_override) {
    if (N_override != 0 && (N_override & (N_override - 1)) == 0) {
        N = N_override;
    } else {
        unsigned char buf[4];
        if (RAND_bytes(buf, sizeof(buf)) <= 0) {
            throw runtime_error("Failed to generate random bytes");
        }
        uint32_t rand_val = (static_cast<uint32_t>(buf[0]) << 24) |
                            (static_cast<uint32_t>(buf[1]) << 16) |
                            (static_cast<uint32_t>(buf[2]) << 8) |
                            static_cast<uint32_t>(buf[3]);
            int exp = 8 + (rand_val % 3); // 8..10 (256..1024)
        N = 1u << exp;
    }

    if (t_override != 0) {
        t = t_override;
    } else {
        unsigned char buf2[4];
        if (RAND_bytes(buf2, sizeof(buf2)) <= 0) {
            throw runtime_error("Failed to generate random bytes");
        }
        uint32_t rand_val2 = (static_cast<uint32_t>(buf2[0]) << 24) |
                             (static_cast<uint32_t>(buf2[1]) << 16) |
                             (static_cast<uint32_t>(buf2[2]) << 8) |
                             static_cast<uint32_t>(buf2[3]);
        t = 2 + (rand_val2 % 7); // 2..8
    }
}

void IVRF::hash(Bytes& out, const Bytes& in) const {
    hash(out, in.data(), in.size());
}

// Hash function H: {0,1}* → {0,1}^256 using SHA-256
void IVRF::hash(Bytes& out, const uint8_t* in, size_t inlen) const {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, inlen);
    SHA256_Final(out.data(), &ctx);
}


// Computes Merkle tree root from N leaves using binary tree construction
// Used in both keygen and verification phases
void IVRF::compute_merkle_root(Bytes& root, const vector<Bytes>& leaves) const {
    if (leaves.empty()) {
        return;
    }

    vector<Bytes> current_level = leaves;
    while (current_level.size() > 1) {
    vector<Bytes> next_level;
        for (size_t i = 0; i < current_level.size(); i += 2) {
            Bytes combined;
            if (i + 1 < current_level.size()) {
                combined = concat_bytes(current_level[i], current_level[i + 1]);
            } else {
                combined = concat_bytes(current_level[i], current_level[i]);
            }
            Bytes parent(IVRF::HASH_SIZE);
            hash(parent, combined);
            next_level.push_back(parent);
        }
        current_level = next_level;
    }
    
    root = current_level[0];
}

// iAV.Keygen: Authenticated MT-iVRF key generation (Section 3.2)
// Generates:
//   - PRG seed s for x values
//   - PRG seed s' for Falcon signature keys
//   - N Falcon-512 key pairs (pk_i, sk_i)
//   - Merkle tree over leaves x_{i,t} = H(x_{i,t-1} || pk_i)
bool IVRF::keygen(PublicKey& pk, SecretKey& sk) {
    cout << "\n=== iAV.Keygen(pp) ===" << endl;
    
    // Step 1: Generate PRG seeds s and s'
    uint8_t random_seed[IVRF::PRG_SEED_SIZE];
    RAND_bytes(random_seed, IVRF::PRG_SEED_SIZE);
    sk.s = Bytes(random_seed, random_seed + IVRF::PRG_SEED_SIZE);

    RAND_bytes(random_seed, IVRF::PRG_SEED_SIZE);
    sk.s_prime = Bytes(random_seed, random_seed + IVRF::PRG_SEED_SIZE);

    vector<Bytes> leaves;

    AES256_CTR_DRBG_struct s_ctx, sprime_ctx;
    drbg_randombytes_init(&s_ctx, reinterpret_cast<unsigned char*>(sk.s.data()), NULL, 128);
    drbg_randombytes_init(&sprime_ctx, reinterpret_cast<unsigned char*>(sk.s_prime.data()), NULL, 128);

    // Falcon-512 (NIST Level 1 post-quantum security)
    constexpr unsigned FLOGN = 9;
    size_t pk_size = FALCON_PUBKEY_SIZE(FLOGN);
    size_t sk_size = FALCON_PRIVKEY_SIZE(FLOGN);
    size_t tmp_size = max(FALCON_TMPSIZE_KEYGEN(FLOGN), FALCON_TMPSIZE_SIGNDYN(FLOGN));
    AlignedBuf tmp_buf(tmp_size);
    uint8_t *tmp = tmp_buf.data();

    pk.pk_list.clear(); pk.pk_list.resize(N, Bytes());
    pk.leaf_list.clear(); pk.leaf_list.resize(N, Bytes());
    sk.sk_list.clear(); sk.sk_list.resize(N, Bytes());

    // Step 2-3: Generate x values and Falcon keys for each time period
    for (uint32_t idx = 0; idx < N; idx++) {
        // Derive x_{i,0} from seed s using PRG
        Bytes x_0(IVRF::HASH_SIZE);
        drbg_randombytes(&s_ctx, reinterpret_cast<unsigned char*>(x_0.data()), IVRF::HASH_SIZE);

        // Compute x_{i,t-1} = H^{t-1}(x_{i,0})
        Bytes x_final = x_0;
        for (uint32_t j = 1; j < t; j++) {
            hash(x_final, x_final);
        }

        // Step 4-5: Derive r_i from s' and generate Falcon key pair
        Bytes r_i(IVRF::PRG_SEED_SIZE);
        drbg_randombytes(&sprime_ctx, reinterpret_cast<unsigned char*>(r_i.data()), IVRF::PRG_SEED_SIZE);

        Bytes pk_i(pk_size);
        Bytes sk_i(sk_size);
        shake256_context sc;
        shake256_init_prng_from_seed(&sc, r_i.data(), r_i.size());
        int fk = falcon_keygen_make(&sc, FLOGN, sk_i.data(), sk_i.size(), pk_i.data(), pk_i.size(), tmp, tmp_size);
        if (fk != 0) {
            cerr << "Falcon keygen failed: " << fk << "\n";
            return false;
        }

        pk.pk_list[idx] = pk_i;
        sk.sk_list[idx] = sk_i;

        // Step 6: Compute Merkle tree leaf x_{i,t} = H(x_{i,t-1} || pk_i)
        Bytes combined = concat_bytes(x_final, pk_i);
        Bytes leaf(IVRF::HASH_SIZE);
        hash(leaf, combined);
        pk.leaf_list[idx] = leaf;
        leaves.push_back(leaf);
    }

    // Step 7: Compute Merkle root (public key pk_av)
    compute_merkle_root(pk.root, leaves);
    
    cout << "Generated N = " << N << " key pairs (pk₀, sk₀), ..., (pk_{N-1}, sk_{N-1})" << endl;
    cout << "Merkle root (pk_av = root): ";
    print_bytes(pk.root);
    
    return true;
}

// iAV.Eval: VRF evaluation with authentication (Section 3.2)
// Computes:
//   - VRF output v = H(y, μ₁) where y = H^{t-1-j}(x_{i,0})
//   - Falcon signature σ on μ₂
//   - Proof π = (y, AP_i, pk_i)
bool IVRF::eval(const PublicKey& pk, const SecretKey& sk, const Bytes& mu1,
                const Bytes& mu2, uint32_t i, uint32_t j,
                Bytes& v, Bytes& sigma, Proof& pi) {
    cout << "\n=== iAV.Eval(μ₁, μ₂, (i=" << i << ", j=" << j << ")) ===" << endl;
    
    if (i >= N || j >= t) {
        cerr << "Invalid parameters: i=" << i << " (max " << N-1 << "), j=" << j << " (max " << t-1 << ")" << endl;
        return false;
    }

    // Step 1: Derive x_{i,0} from seed s
    unsigned char seed_local[IVRF::PRG_SEED_SIZE];
    memcpy(seed_local, sk.s.data(), IVRF::PRG_SEED_SIZE);
    AES256_CTR_DRBG_struct s_in;
    drbg_randombytes_init(&s_in, seed_local, NULL, 128);
    Bytes x(IVRF::HASH_SIZE);
    for (uint32_t idx = 0; idx <= i; ++idx) {
        drbg_randombytes(&s_in, reinterpret_cast<unsigned char*>(x.data()), IVRF::HASH_SIZE);
    }

    // Step 2: Compute y = H^{t-1-j}(x_{i,0})
    Bytes y = x;
    uint32_t pow_needed = (t > 0 && j < t) ? (t - 1 - j) : 0;
    for (uint32_t iter = 0; iter < pow_needed; ++iter) hash(y, y);
    pi.y = y;

    // Step 3: Compute VRF output v = H(y, μ₁)
    Bytes input = concat_bytes(y, mu1);
    v.resize(IVRF::HASH_SIZE);
    hash(v, input.data(), input.size());
    
    cout << "VRF output v = H(y, μ₁): ";
    print_bytes(v);

    constexpr unsigned FLOGN = 9;
    size_t tmp_size = FALCON_TMPSIZE_SIGNDYN(FLOGN);
    AlignedBuf tmp_eval_buf(tmp_size);

    if (i >= sk.sk_list.size() || sk.sk_list[i].empty()) {
        cerr << "No cached private key for index " << i << "; eval cannot proceed\n";
        return false;
    }

    // Generate Falcon signature σ on μ₂ using sk_i
    const Bytes &sk_i = sk.sk_list[i];
    shake256_context sc_sig;
    if (shake256_init_prng_from_system(&sc_sig) != 0) {
        cerr << "Falcon RNG initialization failed for signing\n";
        return false;
    }
    size_t sig_buf_size = FALCON_SIG_COMPRESSED_MAXSIZE(FLOGN);
    Bytes sig_buf(sig_buf_size);
    size_t sig_len = sig_buf_size;
    int sres = falcon_sign_dyn(&sc_sig, sig_buf.data(), &sig_len, FALCON_SIG_COMPRESSED, sk_i.data(), sk_i.size(), mu2.data(), mu2.size(), tmp_eval_buf.data(), tmp_eval_buf.size);
    if (sres != 0) {
        cerr << "Falcon sign failed: " << sres << "\n";
        return false;
    }
    sigma.assign(sig_buf.begin(), sig_buf.begin() + sig_len);
    cout << "Signature σ on μ₂: " << sig_len << " bytes" << endl;
    
    // Step 4: Compute Merkle authentication path AP_i using binary-heap tree
    size_t tree_height = 0; for (uint32_t m = N; m > 1; m >>= 1) tree_height++;
    pi.auth_path.resize(tree_height * IVRF::HASH_SIZE);

    vector<Bytes> tree(2 * N, Bytes(IVRF::HASH_SIZE));
    for (uint32_t li = 0; li < N; ++li) {
        tree[N + li] = pk.leaf_list[li];
    }
    for (int64_t k = (int64_t)N - 1; k >= 1; --k) {
        Bytes combined = concat_bytes(tree[2 * k], tree[2 * k + 1]);
        hash(tree[(size_t)k], combined);
    }

    uint32_t cur = N + i;
    for (size_t level = 0; level < tree_height; level++) {
        uint32_t sibling = cur ^ 1;
        copy(tree[sibling].begin(), tree[sibling].end(),
                 pi.auth_path.begin() + level * IVRF::HASH_SIZE);
        cur >>= 1;
    }

    if (i < pk.pk_list.size()) {
        pi.pk_t = pk.pk_list[i];
    } else {
        pi.pk_t = Bytes();
    }
    
    cout << "\n[Proof Components]" << endl;
    cout << "y (committed value): ";
    print_bytes(pi.y);
    cout << "pk_" << i << " (public key for period " << i << "): ";
    print_bytes(pi.pk_t);
    cout << "\nAuthentication Path AP_" << i << " (Merkle path):" << endl;
    for (size_t level = 0; level < tree_height; level++) {
        cout << "  Level " << level << ": ";
        Bytes node(pi.auth_path.begin() + level * IVRF::HASH_SIZE,
                   pi.auth_path.begin() + (level + 1) * IVRF::HASH_SIZE);
        print_bytes(node);
    }
    
    cout << "\nπ = (y, AP_" << i << ")" << endl;
    cout << "Evaluation complete" << endl;

    // Sanity-check: recompute root from leaf and auth_path
    {
        Bytes cur = pk.leaf_list[i];
        uint32_t idx = i;
        Bytes parent(IVRF::HASH_SIZE);
        for (size_t level = 0; level < tree_height; level++) {
            Bytes sibling(pi.auth_path.begin() + level * IVRF::HASH_SIZE,
                         pi.auth_path.begin() + (level + 1) * IVRF::HASH_SIZE);
            Bytes combined;
            if (idx & 1) {
                combined = concat_bytes(sibling, cur);
            } else {
                combined = concat_bytes(cur, sibling);
            }
            hash(parent, combined);
            cur = parent;
            idx >>= 1;
        }
        // Sanity check
        if (cur != pk.root) {
            cerr << "Warning: Eval-side path does not reconstruct root" << endl;
        }
    }
    return true;
}

// iAV.Verify: VRF verification (Section 3.2)
// Verifies:
//   1. VRF output: v = H(y, μ₁)
//   2. Falcon signature on μ₂
//   3. Merkle path: root' = pk_av
bool IVRF::verify(const PublicKey& pk, const Bytes& mu1,
                  const Bytes& mu2, uint32_t i, uint32_t j,
                  const Bytes& v, const Bytes& sigma,
                  const Proof& pi) {
    cout << "\n=== iAV.Verify(μ₁, μ₂, (i=" << i << ", j=" << j << "), v, π) ===" << endl;
    
    if (i >= N || j >= t) {
        cerr << "Invalid parameters" << endl;
        return false;
    }

    // Step 2: Verify v = H(y, μ₁)
    Bytes input = concat_bytes(pi.y, mu1);
    
    Bytes computed_v(IVRF::HASH_SIZE);
    hash(computed_v, input.data(), input.size());
    
    if (v != computed_v) {
        cerr << "VRF output mismatch: v ≠ H(y, μ₁)" << endl;
        return false;
    }
    cout << "✓ VRF output verified: v = H(y, μ₁)" << endl;
    
    // Step 3: Verify Falcon signature σ on μ₂ using pk_i
    constexpr unsigned FLOGN = 9;
    size_t tmp_size = FALCON_TMPSIZE_VERIFY(FLOGN);
    AlignedBuf tmp_ver_buf(tmp_size);
    
    int vres = falcon_verify(sigma.data(), sigma.size(), FALCON_SIG_COMPRESSED, 
                             pi.pk_t.data(), pi.pk_t.size(), mu2.data(), mu2.size(), 
                             tmp_ver_buf.data(), tmp_size);
    if (vres != 0) {
        cerr << "Signature verification failed" << endl;
        return false;
    }
    cout << "✓ Signature verified" << endl;
    
    // Step 4: Compute x_{i,t-1} = H^{j}(y) and then leaf = H(x_{i,t-1} || pk_i)
    Bytes current_node = pi.y;
    uint32_t hash_times = j;
    for (uint32_t ht = 0; ht < hash_times; ht++) {
        Bytes tmp(IVRF::HASH_SIZE);
        hash(tmp, current_node);
        current_node = tmp;
    }
    
    // Compute leaf value x_{i,t} = H(x_{i,t-1} || pk_i)
    Bytes leaf_combined = concat_bytes(current_node, pi.pk_t);
    Bytes leaf_hash(IVRF::HASH_SIZE);
    hash(leaf_hash, leaf_combined);
    current_node = leaf_hash;
    // Leaf verification is handled in the Merkle path verification
    
    // Compute Merkle root using authentication path
    Bytes computed_root(IVRF::HASH_SIZE);
    uint32_t node_index = i;
    
    size_t tree_height = 0; for (uint32_t m = N; m > 1; m >>= 1) tree_height++;
    for (size_t level = 0; level < tree_height; level++) {
        Bytes sibling(pi.auth_path.begin() + level * IVRF::HASH_SIZE,
                      pi.auth_path.begin() + (level + 1) * IVRF::HASH_SIZE);
        
        Bytes combined;
        if (node_index & 1) {
            combined = concat_bytes(sibling, current_node);
        } else {
            combined = concat_bytes(current_node, sibling);
        }
        
        hash(computed_root, combined);
        current_node = computed_root;
        node_index >>= 1;
    }
    
    if (computed_root == pk.root) {
        cout << "✓ Merkle path verified: root' = pk_av" << endl;
        cout << "\n*** All verifications passed: iAV.Verify returns 1 ***" << endl;
        return true;
    } else {
        cerr << "Merkle path verification failed: root' ≠ pk_av" << endl;
        return false;
    }
}

void print_bytes(const Bytes& data) {
    for (u8 byte : data) {
        cout << hex << setw(2) << setfill('0') 
                  << static_cast<int>(byte);
    }
    cout << dec << endl;
}

uint32_t IVRF::get_N() const {
    return N;
}

uint32_t IVRF::get_t() const {
    return t;
}