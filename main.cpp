#include "ivrf.hpp"
using namespace std;

// parse a hex string (no 0x) into bytes; returns empty on invalid input
static Bytes hex_to_bytes(const string &hex) {
    Bytes out;
    if (hex.empty()) return out;
    string s = hex;
    // remove whitespace
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

int main() {
    cout << "Interactive MT-iVRF Demo (C++ version)\n";
    cout << "====================================\n";

    // One-time parameter selection and key generation. User can choose to
    // regenerate keys later from the menu.
    uint32_t N_override = 0, t_override = 0;
    cout << "\nChoose parameters:\n";
    cout << "1) Random N and t\n";
    cout << "2) Enter N and t manually\n";
    cout << "Select (1 or 2): ";
    int choice = 1;
    if (!(cin >> choice)) return 0;
    if (choice == 2) {
        cout << "Enter N (power of two, e.g. 256): ";
        cin >> N_override;
        cout << "Enter t (iteration count, e.g. 4): ";
        cin >> t_override;
    }
    string dummy; getline(cin, dummy); // consume newline

    IVRF ivrf(0, N_override, t_override);
    IVRF::PublicKey pk;
    IVRF::SecretKey sk;

    if (!ivrf.keygen(pk, sk)) {
        cerr << "Key generation failed!\n";
        return -1;
    }

    cout << "\nParameters:\n";
    cout << "N = " << ivrf.get_N() << "\n";
    cout << "t = " << ivrf.get_t() << "\n";

    // Main interactive menu: evaluate with same keys, regenerate keys, or exit
    while (true) {
        cout << "\nMenu:\n";
        cout << "1) Evaluate (choose i/j, enter mu1/mu2 hex on single lines)\n";
        cout << "2) Regenerate keys\n";
        cout << "3) Exit\n";
        cout << "Select (1-3): ";
        int sel = 1;
        if (!(cin >> sel)) break;
        getline(cin, dummy);

        if (sel == 3) break;

        if (sel == 2) {
            if (!ivrf.keygen(pk, sk)) {
                cerr << "Key generation failed!\n";
                break;
            }
            cout << "Regenerated keys.\n";
            continue;
        }

        // sel == 1: do an evaluation
        cout << "Enter mu1 (hex, single line, e.g. 68656c6c6f): ";
        string mu1hex; getline(cin, mu1hex);
        cout << "Enter mu2 (hex, single line): ";
        string mu2hex; getline(cin, mu2hex);
        Bytes mu1 = hex_to_bytes(mu1hex);
        Bytes mu2 = hex_to_bytes(mu2hex);
        // Accept either hex input or raw ASCII: if hex parser returned empty
        // but the user provided a non-empty string, treat it as raw bytes.
        if (mu1.empty() && !mu1hex.empty()) mu1 = Bytes(mu1hex.begin(), mu1hex.end());
        if (mu2.empty() && !mu2hex.empty()) mu2 = Bytes(mu2hex.begin(), mu2hex.end());
        if (mu1.empty() || mu2.empty()) {
            cout << "Invalid input for mu1/mu2. Provide hex or ASCII. Try again.\n";
            continue;
        }

        uint32_t i = 0, j = 0;
        cout << "Enter time period (0-" << ivrf.get_N()-1 << "): ";
        if (!(cin >> i)) break;
        cout << "Enter iteration (0-" << ivrf.get_t()-1 << "): ";
        if (!(cin >> j)) break;
        getline(cin, dummy);

        Bytes v(IVRF::HASH_SIZE), sigma; IVRF::Proof pi;
        if (!ivrf.eval(pk, sk, mu1, mu2, i, j, v, sigma, pi)) {
            cout << "Evaluation failed!\n";
            continue;
        }

        if (!ivrf.verify(pk, mu1, mu2, i, j, v, sigma, pi)) {
            cout << "Verification failed!\n";
        } else {
            cout << "Verification succeeded.\n";
        }

        // After evaluation, loop back to menu (keys are reused unless regenerated)
    }

    cout << "Exiting demo.\n";
    return 0;
}