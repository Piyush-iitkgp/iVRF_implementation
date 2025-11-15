#include "ivrf.hpp"
using namespace std;

// Converts hexadecimal string to byte vector
// Supports both hex format (e.g., "68656c6c6f") and ASCII input
static Bytes hex_to_bytes(const string &hex) {
    Bytes out;
    if (hex.empty()) return out;
    string s = hex;
    s.erase(remove_if(s.begin(), s.end(), ::isspace), s.end());
    if (s.size() % 2 != 0) return out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        char a = s[i], b = s[i+1];
        if (!isxdigit(a) || !isxdigit(b)) return Bytes();
        uint8_t hi = static_cast<uint8_t>(isdigit(a) ? a - '0' : tolower(a) - 'a' + 10);
        uint8_t lo = static_cast<uint8_t>(isdigit(b) ? b - '0' : tolower(b) - 'a' + 10);
        out.push_back((hi << 4) | lo);
    }
    return out;
}

// Interactive demo for Authenticated MT-iVRF (Section 3.2 of paper)
// Demonstrates key generation, VRF evaluation, and verification
int main() {
    cout << "\n╔═══════════════════════════════════════╗\n";
    cout << "║   Interactive MT-iVRF Demo (C++)    ║\n";
    cout << "╚═══════════════════════════════════════╝\n";

    // Parameter selection: N (Number of Rounds) and t (iterations)
    uint32_t N_override = 0, t_override = 0;
    cout << "\n[Parameter Selection]\n";
    cout << "  1) Random N and t\n";
    cout << "  2) Manual N and t\n";
    cout << "Choice: ";
    int choice = 1;
    if (!(cin >> choice)) return 0;
    
    if (choice == 2) {
        cout << "N (power of 2): ";
        cin >> N_override;
        cout << "t (iterations): ";
        cin >> t_override;
    }
    
    string dummy;
    getline(cin, dummy);

    // Initialize iVRF instance and generate keys
    IVRF ivrf(N_override, t_override);
    IVRF::PublicKey pk;
    IVRF::SecretKey sk;

    if (!ivrf.keygen(pk, sk)) {
        cerr << "Key generation failed!\n";
        return -1;
    }

    cout << "\n[Active Parameters]\n";
    cout << "  N = " << ivrf.get_N() << " (Number of Rounds)\n";
    cout << "  t = " << ivrf.get_t() << " (iterations)\n";
    cout << "  Message size: arbitrary (hash input)\n";

    while (true) {
        cout << "\n[Main Menu]\n";
        cout << "  1) Evaluate VRF\n";
        cout << "  2) Regenerate keys\n";
        cout << "  3) Exit\n";
        cout << "Choice: ";
        int sel = 1;
        if (!(cin >> sel)) break;
        getline(cin, dummy);

        if (sel == 3) break;

        if (sel == 2) {
            if (!ivrf.keygen(pk, sk)) {
                cerr << "\nKey generation failed!\n";
                break;
            }
            continue;
        }

        cout << "\n[Input Messages]";
        cout << "\nμ₁ (hex or ASCII): ";
        string mu1hex;
        getline(cin, mu1hex);
        cout << "μ₂ (hex or ASCII): ";
        string mu2hex;
        getline(cin, mu2hex);
        Bytes mu1 = hex_to_bytes(mu1hex);
        Bytes mu2 = hex_to_bytes(mu2hex);
        
        if (mu1.empty() && !mu1hex.empty()) mu1 = Bytes(mu1hex.begin(), mu1hex.end());
        if (mu2.empty() && !mu2hex.empty()) mu2 = Bytes(mu2hex.begin(), mu2hex.end());
        if (mu1.empty() || mu2.empty()) {
            cout << "\nInvalid input. Provide hex or ASCII.\n";
            continue;
        }

        // Get index (i, j) where i is round number and j is iteration
        uint32_t i = 0, j = 0;
        cout << "Round i (0-" << ivrf.get_N()-1 << "): ";
        if (!(cin >> i)) break;
        cout << "Iteration j (0-" << ivrf.get_t()-1 << "): ";
        if (!(cin >> j)) break;
        getline(cin, dummy);

        // Evaluate VRF and generate proof
        Bytes v(IVRF::HASH_SIZE), sigma;
        IVRF::Proof pi;
        
        if (!ivrf.eval(pk, sk, mu1, mu2, i, j, v, sigma, pi)) {
            cout << "\n[ERROR] Evaluation failed\n";
            continue;
        }

        // Verify the VRF output and proof
        if (!ivrf.verify(pk, mu1, mu2, i, j, v, sigma, pi)) {
            cout << "\n[ERROR] Verification failed\n";
        }
    }

    cout << "\nExiting...\n";
    return 0;
}