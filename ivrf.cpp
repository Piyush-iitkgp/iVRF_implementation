#include "ivrf.hpp"
// OpenSSL and system
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <falcon.h>

using namespace std; // user style: avoid std:: everywhere

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// Small RAII wrapper for aligned temporary buffers used by Falcon routines.
struct AlignedBuf {
    void *ptr = nullptr;
    size_t size = 0;
    AlignedBuf(size_t s = 0, size_t align = 64) { if (s) alloc(s, align); }
    void alloc(size_t s, size_t align = 64) {
        free(ptr); ptr = nullptr; size = 0;
        if (posix_memalign(&ptr, align, s) != 0) throw std::bad_alloc();
        size = s;
    }
    uint8_t* data() { return reinterpret_cast<uint8_t*>(ptr); }
    ~AlignedBuf() { if (ptr) free(ptr); }
};

// Constructor: choose random N (power of two) and random t
IVRF::IVRF(uint32_t /*lambda_param*/, uint32_t N_override, uint32_t t_override) {
    // If the user provided valid overrides, use them. Otherwise choose randomly.
    if (N_override != 0 && (N_override & (N_override - 1)) == 0) {
        N = N_override;
        std::cout << "Using overridden N = " << N << std::endl;
    } else {
        unsigned char buf[4];
        if (RAND_bytes(buf, sizeof(buf)) <= 0) {
            throw std::runtime_error("Failed to generate random bytes");
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
        std::cout << "Using overridden t = " << t << std::endl;
    } else {
        unsigned char buf2[4];
        if (RAND_bytes(buf2, sizeof(buf2)) <= 0) {
            throw std::runtime_error("Failed to generate random bytes");
        }
        uint32_t rand_val2 = (static_cast<uint32_t>(buf2[0]) << 24) |
                             (static_cast<uint32_t>(buf2[1]) << 16) |
                             (static_cast<uint32_t>(buf2[2]) << 8) |
                             static_cast<uint32_t>(buf2[3]);
        t = 2 + (rand_val2 % 7); // 2..8
    }

    std::cout << "Initialized with N=" << N << ", t=" << t << std::endl;
}

void IVRF::hash(Bytes& out, const Bytes& in) const {
    hash(out, in.data(), in.size());
}

void IVRF::hash(Bytes& out, const uint8_t* in, size_t inlen) const {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, inlen);
    SHA256_Final(out.data(), &ctx);
}

void IVRF::prg_next(Bytes& out, Bytes& state) const {
    hash(out, state);
    state = out;
}

void IVRF::compute_merkle_root(Bytes& root, const vector<Bytes>& leaves) const {
    if (leaves.empty()) {
        return;
    }

    vector<Bytes> current_level = leaves;
    while (current_level.size() > 1) {
    std::vector<Bytes> next_level;
        for (size_t i = 0; i < current_level.size(); i += 2) {
            Bytes combined;
            combined.insert(combined.end(), current_level[i].begin(), current_level[i].end());
            if (i + 1 < current_level.size()) {
                combined.insert(combined.end(), current_level[i + 1].begin(), current_level[i + 1].end());
            } else {
                // If odd number of nodes, duplicate the last one
                combined.insert(combined.end(), current_level[i].begin(), current_level[i].end());
            }
            Bytes parent(IVRF::HASH_SIZE);
            hash(parent, combined);
            next_level.push_back(parent);
        }
        current_level = next_level;
    }
    
    root = current_level[0];
}

bool IVRF::keygen(PublicKey& pk, SecretKey& sk) {
    std::cout << "\n=== Demonstrating iAV.Keygen ===\n";

    // Generate random seeds using OpenSSL's RAND_bytes
    uint8_t random_seed[32];
    RAND_bytes(random_seed, 32);
    sk.s = Bytes(random_seed, random_seed + 32);

    RAND_bytes(random_seed, 32);
    sk.s_prime = Bytes(random_seed, random_seed + 32);

    std::cout << "Generated PRG seed for x values: ";
    print_bytes(sk.s);
    std::cout << "Generated PRG seed for signatures: ";
    print_bytes(sk.s_prime);

    sk.current_period = 0;

    // Generate and store x_{i,t-1} values and per-index Falcon public/private keys
    vector<Bytes> leaves;
    Bytes prg_state = sk.s;
    Bytes prg_state_prime = sk.s_prime;

    std::cout << "\nGenerating initial x values and per-index Falcon keys...\n";

    constexpr unsigned FLOGN = 9; // Falcon-512
    size_t pk_size = FALCON_PUBKEY_SIZE(FLOGN);
    size_t sk_size = FALCON_PRIVKEY_SIZE(FLOGN);
    size_t tmp_size = std::max(FALCON_TMPSIZE_KEYGEN(FLOGN), FALCON_TMPSIZE_SIGNDYN(FLOGN));
    AlignedBuf tmp_buf(tmp_size);
    uint8_t *tmp = tmp_buf.data();

    // Reserve caches
    pk.pk_list.clear(); pk.pk_list.resize(N, Bytes());
    pk.leaf_list.clear(); pk.leaf_list.resize(N, Bytes());
    sk.sk_list.clear(); sk.sk_list.resize(N, Bytes());

    for (uint32_t idx = 0; idx < N; idx++) {
        // Generate x_{i,0}
    Bytes x_0(IVRF::HASH_SIZE);
        prg_next(x_0, prg_state);

        // Compute x_{i,t-1}
    Bytes x_final = x_0;
        for (uint32_t j = 1; j < t; j++) {
            hash(x_final, x_final);
        }

        // derive r_i from s_prime PRG
    Bytes r_i(IVRF::PRG_SEED_SIZE);
        prg_next(r_i, prg_state_prime);

        // generate Falcon keypair from r_i seed and cache keys
    Bytes pk_i(pk_size);
    Bytes sk_i(sk_size);
        shake256_context sc;
        shake256_init_prng_from_seed(&sc, r_i.data(), r_i.size());
        int fk = falcon_keygen_make(&sc, FLOGN, sk_i.data(), sk_i.size(), pk_i.data(), pk_i.size(), tmp, tmp_size);
        if (fk != 0) {
            std::cerr << "Falcon keygen failed during keygen: " << fk << "\n";
            return false;
        }

        // cache pk and sk bytes
        pk.pk_list[idx] = pk_i;
        sk.sk_list[idx] = sk_i;

        // final leaf = H(x_{i,t-1} || pk_i)
        Bytes combined;
        combined.insert(combined.end(), x_final.begin(), x_final.end());
        combined.insert(combined.end(), pk_i.begin(), pk_i.end());
        Bytes leaf(IVRF::HASH_SIZE);
        hash(leaf, combined);
        leaves.push_back(leaf);
    }

    // Compute Merkle root using all leaves
    compute_merkle_root(pk.root, leaves);
    std::cout << "\nComputed Merkle root (public key):\n";
    print_bytes(pk.root);

    // tmp_buf is RAII; no explicit free required

    return true;
}

bool IVRF::eval(const PublicKey& pk, const SecretKey& sk, const Bytes& mu1,
                const Bytes& mu2, uint32_t i, uint32_t j,
                Bytes& v, Bytes& sigma, Proof& pi) {
    std::cout << "\n=== Demonstrating iAV.Eval ===\n";
    std::cout << "Evaluating for time period " << i << ", iteration " << j << "\n";
    
    if (i >= N || j >= t) {
        std::cout << "Invalid time period or iteration\n";
        return false;
    }

    std::cout << "Input message mu1: ";
    print_bytes(mu1);
    std::cout << "Input message mu2: ";
    print_bytes(mu2);
    
    // Compute x_{i,0} by advancing PRG to index i
    Bytes prg_state = sk.s;
    Bytes x(IVRF::HASH_SIZE);
    for (uint32_t idx = 0; idx <= i; ++idx) prg_next(x, prg_state);

    // Compute y = H^j(x)
    Bytes y = x;
    for (uint32_t iter = 0; iter < j; ++iter) hash(y, y);
    pi.y = y;
    std::cout << "\nComputed y value: ";
    print_bytes(pi.y);
    

    // Compute VRF output v
    Bytes input;
    input.insert(input.end(), y.begin(), y.end());
    input.insert(input.end(), mu1.begin(), mu1.end());
    v.resize(IVRF::HASH_SIZE);
    hash(v, input.data(), input.size());
    
    std::cout << "Computed VRF output v: ";
    print_bytes(v);

    // Generate signature using cached per-index private key (sk.sk_list[i]) and sign mu2
    Bytes sig_hash_input;
    sig_hash_input.insert(sig_hash_input.end(), y.begin(), y.end());
    sig_hash_input.insert(sig_hash_input.end(), mu1.begin(), mu1.end());
    sig_hash_input.insert(sig_hash_input.end(), mu2.begin(), mu2.end());

    constexpr unsigned FLOGN = 9;
    size_t tmp_size = FALCON_TMPSIZE_SIGNDYN(FLOGN);
    AlignedBuf tmp_eval_buf(tmp_size);

    if (i >= sk.sk_list.size() || sk.sk_list[i].empty()) {
        std::cerr << "No cached private key for index " << i << "; eval cannot proceed\n";
        return false;
    }

    const Bytes &sk_i = sk.sk_list[i];
    // Use Falcon's RNG for signing
    shake256_context sc_sig;
    if (shake256_init_prng_from_system(&sc_sig) != 0) {
        std::cerr << "Falcon RNG initialization failed for signing\n";
        return false;
    }
    size_t sig_buf_size = FALCON_SIG_COMPRESSED_MAXSIZE(FLOGN);
    Bytes sig_buf(sig_buf_size);
    size_t sig_len = sig_buf_size;
    int sres = falcon_sign_dyn(&sc_sig, sig_buf.data(), &sig_len, FALCON_SIG_COMPRESSED, sk_i.data(), sk_i.size(), mu2.data(), mu2.size(), tmp_eval_buf.data(), tmp_eval_buf.size);
    if (sres != 0) {
        std::cerr << "Falcon sign failed: " << sres << "\n";
        return false;
    }
    sigma.assign(sig_buf.begin(), sig_buf.begin() + sig_len);
    std::cout << "Generated Falcon signature (sigma) len=" << sig_len << ": ";
    print_bytes(sigma);
    
    // Generate Merkle authentication path
    // Generate Merkle authentication path over leaves x_{idx,t-1}
    // (keygen computed the root over x_{i,t-1}, so we must produce the auth
    // path for that leaf. The proof will also include y = x_{i,j}, and the
    // verifier will hash y (t-1-j) times to reach the leaf before checking
    // the inclusion path.)
    size_t tree_height = static_cast<size_t>(std::log2(N));
    pi.auth_path.resize(tree_height * IVRF::HASH_SIZE);

    // Generate all leaves using cached pk_list and cached leaf_list
    vector<Bytes> leaves;
    leaves.reserve(N);
    for (uint32_t idx = 0; idx < N; idx++) {
        if (!pk.pk_list[idx].empty() && !pk.leaf_list[idx].empty()) {
            leaves.push_back(pk.leaf_list[idx]);
        } else {
            // Fallback: recompute from PRG (shouldn't happen if keygen cached correctly)
            Bytes prg_c = sk.s; for (uint32_t ii = 0; ii <= idx; ++ii) prg_next(prg_c, prg_c);
            Bytes x_leaf = prg_c; for (uint32_t iter = 1; iter < t; ++iter) hash(x_leaf, x_leaf);
            Bytes comb; comb.insert(comb.end(), x_leaf.begin(), x_leaf.end());
            if (!pk.pk_list[idx].empty()) comb.insert(comb.end(), pk.pk_list[idx].begin(), pk.pk_list[idx].end());
            Bytes leaf_hash(IVRF::HASH_SIZE); hash(leaf_hash, comb);
            leaves.push_back(leaf_hash);
        }
    }

    // Build tree levels bottom-up
    std::vector<std::vector<Bytes>> tree_levels;
    tree_levels.push_back(leaves);
    for (size_t level = 0; level < tree_height; level++) {
        const auto &prev = tree_levels.back();
        std::vector<Bytes> next;
        for (size_t k = 0; k < prev.size(); k += 2) {
            Bytes combined;
            combined.insert(combined.end(), prev[k].begin(), prev[k].end());
            if (k + 1 < prev.size()) combined.insert(combined.end(), prev[k+1].begin(), prev[k+1].end());
            else combined.insert(combined.end(), prev[k].begin(), prev[k].end());
            Bytes parent(IVRF::HASH_SIZE);
            hash(parent, combined);
            next.push_back(parent);
        }
        tree_levels.push_back(next);
    }

    // Extract authentication path for index i
    uint32_t node_index = i;
    for (size_t level = 0; level < tree_height; level++) {
        const auto &level_nodes = tree_levels[level];
        size_t sibling = node_index ^ 1;
        if (sibling < level_nodes.size()) {
            std::copy(level_nodes[sibling].begin(), level_nodes[sibling].end(),
                      pi.auth_path.begin() + level * IVRF::HASH_SIZE);
        } else {
            // If sibling missing (odd node), copy the node itself
            std::copy(level_nodes[node_index].begin(), level_nodes[node_index].end(),
                      pi.auth_path.begin() + level * IVRF::HASH_SIZE);
        }
        node_index >>= 1;
    }

    std::cout << "Generated Merkle authentication path:\n";
    for (size_t level = 0; level < tree_height; level++) {
        std::cout << "Level " << level << ": ";
        Bytes node(pi.auth_path.begin() + level * IVRF::HASH_SIZE,
                   pi.auth_path.begin() + (level + 1) * IVRF::HASH_SIZE);
        print_bytes(node);
    }
    
    // pk_t is the Falcon public key for this time period (pk_i)
    if (i < pk.pk_list.size()) pi.pk_t = pk.pk_list[i];
    else pi.pk_t = Bytes();
    std::cout << "Public key for time period (pk_t) computed: ";
    print_bytes(pi.pk_t);
    
    return true;
}

bool IVRF::verify(const PublicKey& pk, const Bytes& mu1,
                  const Bytes& mu2, uint32_t i, uint32_t j,
                  const Bytes& v, const Bytes& sigma,
                  const Proof& pi) {
    std::cout << "\n=== Demonstrating iAV.Verify ===\n";
    
    if (i >= N || j >= t) {
        std::cout << "Invalid time period or iteration\n";
        return false;
    }

    // Verify VRF output
        Bytes input;
    input.insert(input.end(), pi.y.begin(), pi.y.end());
    input.insert(input.end(), mu1.begin(), mu1.end());
    
    Bytes computed_v(IVRF::HASH_SIZE);
    hash(computed_v, input.data(), input.size());
    
    std::cout << "Expected VRF output: ";
    print_bytes(v);
    std::cout << "Computed VRF output: ";
    print_bytes(computed_v);
    
    if (v != computed_v) {
        std::cout << "VRF verification failed!\n";
        return false;
    }
    
    // Verify Falcon signature using the provided public key (pi.pk_t)
    constexpr unsigned FLOGN = 9;
    size_t tmp_size = FALCON_TMPSIZE_VERIFY(FLOGN);
    void *tmp_ptr_ver = nullptr;
    if (posix_memalign(&tmp_ptr_ver, 64, tmp_size) != 0) {
        std::cerr << "posix_memalign failed for verify tmp buffer" << std::endl;
        return false;
    }
    uint8_t *tmp_ver = reinterpret_cast<uint8_t*>(tmp_ptr_ver);
        int vres = falcon_verify(sigma.data(), sigma.size(), FALCON_SIG_COMPRESSED, pi.pk_t.data(), pi.pk_t.size(), mu2.data(), mu2.size(), tmp_ver, tmp_size);
    if (vres != 0) {
        std::cout << "Falcon signature verification failed: " << vres << "\n";
        free(tmp_ptr_ver);
        return false;
    }
    std::cout << "Falcon signature verification successful!\n";
    free(tmp_ptr_ver);
    
    // Verify Merkle authentication path
    // First hash y up to the leaf value used in the public Merkle tree
    Bytes current_node = pi.y;
    if (t == 0) {
        std::cout << "Invalid t value\n";
        return false;
    }
    uint32_t hash_times = 0;
    if (t > 0 && j <= t - 1) {
        hash_times = (t - 1) - j;
    }
    for (uint32_t ht = 0; ht < hash_times; ht++) {
    Bytes tmp(IVRF::HASH_SIZE);
    hash(tmp, current_node);
    current_node = tmp;
    }
    // The public Merkle tree leaves are H(x_{i,t-1} || pk_i). Combine
    // the hashed y (which is x_{i,t-1}) with the provided per-period
    // public key bytes before hashing to obtain the leaf value.
    {
    Bytes leaf_combined;
    leaf_combined.insert(leaf_combined.end(), current_node.begin(), current_node.end());
    leaf_combined.insert(leaf_combined.end(), pi.pk_t.begin(), pi.pk_t.end());
    Bytes leaf_hash(IVRF::HASH_SIZE);
    hash(leaf_hash, leaf_combined);
    current_node = leaf_hash;
    }
    Bytes computed_root(IVRF::HASH_SIZE);
    uint32_t node_index = i;
    
    size_t tree_height = static_cast<size_t>(std::log2(N));
    for (size_t level = 0; level < tree_height; level++) {
    Bytes sibling(pi.auth_path.begin() + level * IVRF::HASH_SIZE,
              pi.auth_path.begin() + (level + 1) * IVRF::HASH_SIZE);
        
        // Compute parent node
        Bytes combined;
        if (node_index & 1) {
            // Current node is right child
            combined.insert(combined.end(), sibling.begin(), sibling.end());
            combined.insert(combined.end(), current_node.begin(), current_node.end());
        } else {
            // Current node is left child
            combined.insert(combined.end(), current_node.begin(), current_node.end());
            combined.insert(combined.end(), sibling.begin(), sibling.end());
        }
        
        hash(computed_root, combined);
        current_node = computed_root;
        node_index >>= 1;
    }
    
    if (computed_root != pk.root) {
        std::cout << "Merkle path verification failed!\n";
        return false;
    }
    std::cout << "Merkle path verification successful!\n";
    
    // We've already verified the Falcon signature and recomputed the Merkle
    // root to confirm inclusion of the per-period public key. That is
    // sufficient to accept the per-period public key.
    std::cout << "Per-period public key verified via signature and Merkle root.\n";
    std::cout << "All verifications passed successfully!\n";
    return true;
}

void print_bytes(const Bytes& data) {
    for (u8 byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}

void get_input_bytes(Bytes& buffer, const std::string& prompt) {
    std::cout << prompt << std::endl;
    std::string hex;
    for (size_t i = 0; i < buffer.size(); i++) {
        std::cout << "Byte " << i << ": ";
        std::cin >> hex;
        buffer[i] = static_cast<u8>(std::stoi(hex, nullptr, 16));
    }
}

uint32_t IVRF::get_N() const {
    return N;
}

uint32_t IVRF::get_t() const {
    return t;
}