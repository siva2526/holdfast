// tests/test_content_delta.cpp -- differential content signals.
#include "content_delta.hpp"
#include <cassert>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

static std::vector<uint8_t> rnd(size_t n, unsigned seed) {
    std::vector<uint8_t> v(n);
    for (auto& x : v) { seed = seed * 1664525u + 1013904223u; x = static_cast<uint8_t>(seed >> 24); }
    return v;
}
int main() {
    // JPEG -> different JPEG: both high entropy, signature kept => benign.
    {
        auto a = rnd(4096, 1), b = rnd(4096, 2);
        a[0] = 0xFF; a[1] = 0xD8; a[2] = 0xFF; b[0] = 0xFF; b[1] = 0xD8; b[2] = 0xFF;
        double hn = bias_corrected_entropy(shannon_entropy(b.data(), b.size()), b.size());
        auto v = compare_old_new(a.data(), a.size(), b.data(), b.size(), 0, hn, 1.0);
        assert(v.old_known && !v.content_suspicious());
    }
    // JPEG -> ciphertext: signature destroyed, no entropy jump => still caught.
    {
        auto a = rnd(4096, 1), c = rnd(4096, 3);
        a[0] = 0xFF; a[1] = 0xD8; a[2] = 0xFF;
        double hn = bias_corrected_entropy(shannon_entropy(c.data(), c.size()), c.size());
        auto v = compare_old_new(a.data(), a.size(), c.data(), c.size(), 0, hn, 1.0);
        assert(v.type_destroyed && !v.entropy_jump && v.content_suspicious());
    }
    // Text -> ciphertext (any size >= 32): text_destroyed + jump.
    {
        std::string t(200, 'A');
        auto c = rnd(200, 4);
        double hn = bias_corrected_entropy(shannon_entropy(c.data(), c.size()), c.size());
        auto v = compare_old_new(reinterpret_cast<const uint8_t*>(t.data()), t.size(), c.data(), c.size(), 4096, hn, 1.0);
        assert(v.text_destroyed && v.entropy_jump);
        // 64-byte piece: too small for entropy, caught by the text rule.
        std::string t2(64, 'x'); auto c2 = rnd(64, 5);
        auto v2 = compare_old_new(reinterpret_cast<const uint8_t*>(t2.data()), 64, c2.data(), 64, 0, shannon_entropy(c2.data(), 64), 1.0);
        assert(v2.text_destroyed);
    }
    // Text -> text edit: benign.
    {
        std::string a(300, 'a'), b = std::string(150, 'b') + std::string(150, 'c');
        auto v = compare_old_new(reinterpret_cast<const uint8_t*>(a.data()), a.size(), reinterpret_cast<const uint8_t*>(b.data()), b.size(), 0, 1.0, 1.0);
        assert(!v.content_suspicious());
    }
    // Unknown old content => not "known".
    {
        auto c = rnd(100, 6);
        auto v = compare_old_new(nullptr, 0, c.data(), c.size(), 0, 8.0, 1.0);
        assert(!v.old_known && !v.content_suspicious());
    }
        // Random over random where the OLD region is a short EOF tail: no spurious jump.
    {
        auto a = rnd(64, 7), c = rnd(256, 8);
        double hn = bias_corrected_entropy(shannon_entropy(c.data(), c.size()), c.size());
        auto v = compare_old_new(a.data(), a.size(), c.data(), c.size(), 7936, hn, 1.0);
        assert(!v.entropy_jump && !v.content_suspicious());
    }
    assert(detect_magic(reinterpret_cast<const uint8_t*>("%PDF-1.7"), 8) == FileType::Pdf);
    assert(detect_magic(reinterpret_cast<const uint8_t*>("PK\x03\x04zz"), 6) == FileType::Zip);
    std::cout << "test_content_delta: ALL PASSED\n";
    return 0;
}
