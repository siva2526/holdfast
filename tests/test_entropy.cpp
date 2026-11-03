// tests/test_entropy.cpp -- unit tests for shannon_entropy().
#include "entropy.hpp"
#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

int main() {
    // All-zero buffer: zero entropy.
    {
        std::vector<uint8_t> d(1024, 0);
        double e = shannon_entropy(d.data(), d.size());
        assert(e == 0.0);
    }

    // Uniform 0..255 repeated: maximal entropy, 8.0 bits/byte.
    {
        std::vector<uint8_t> d;
        for (int rep = 0; rep < 16; ++rep)
            for (int b = 0; b < 256; ++b) d.push_back(static_cast<uint8_t>(b));
        double e = shannon_entropy(d.data(), d.size());
        assert(e > 7.99 && e <= 8.0);
    }

    // Two symbols in equal proportion: exactly 1.0 bit/byte.
    {
        std::vector<uint8_t> d;
        for (int i = 0; i < 500; ++i) { d.push_back('A'); d.push_back('B'); }
        double e = shannon_entropy(d.data(), d.size());
        assert(e > 0.99 && e < 1.01);
    }

    // Empty buffer: defined as zero, not NaN/UB.
    {
        double e = shannon_entropy(nullptr, 0);
        assert(e == 0.0);
    }

    // Plain English text: low-ish entropy (well under the 7.5 default
    // high-water mark used by AnomalyEngine), unlike encrypted bytes.
    {
        std::string text = "the quick brown fox jumps over the lazy dog "
                            "the quick brown fox jumps over the lazy dog";
        double e = shannon_entropy(reinterpret_cast<const uint8_t*>(text.data()), text.size());
        assert(e < 5.0);
    }

    std::cout << "test_entropy: ALL PASSED\n";
        // Bias correction: random 128/256-byte buffers must land >= 7.5 after
    // correction, while 256 bytes of English-like text must stay well below.
    {
        unsigned seed = 12345;
        int hit128 = 0, hit256 = 0;
        for (int trial = 0; trial < 200; ++trial) {
            std::vector<uint8_t> a(128), b(256);
            for (auto& x : a) { seed = seed * 1664525u + 1013904223u; x = static_cast<uint8_t>(seed >> 24); }
            for (auto& x : b) { seed = seed * 1664525u + 1013904223u; x = static_cast<uint8_t>(seed >> 24); }
            if (bias_corrected_entropy(shannon_entropy(a.data(), a.size()), a.size()) >= 7.5) ++hit128;
            if (bias_corrected_entropy(shannon_entropy(b.data(), b.size()), b.size()) >= 7.5) ++hit256;
        }
        assert(hit128 >= 190 && hit256 >= 190);
        std::string txt = "The quarterly report shows revenue growth across all regions, with particular strength in the northern division where new contracts were signed. ";
        txt += txt;
        std::vector<uint8_t> t(txt.begin(), txt.begin() + 256);
        assert(bias_corrected_entropy(shannon_entropy(t.data(), t.size()), t.size()) < 6.5);
        assert(bias_corrected_entropy(3.0, 64) == 3.0);   // too small: unchanged
    }

    return 0;
}
