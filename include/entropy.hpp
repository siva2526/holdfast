#pragma once
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>

// Shannon entropy of a byte buffer, in bits/byte (range 0.0 - 8.0).
//
// A sudden jump to high entropy on writes to a previously low-entropy
// file is one of the classic weak signals surveyed in the literature
// review (CryptoLock, DaD, UNVEIL). It is deliberately treated here as
// ONE input among several, never as a standalone detector, because the
// review's Gap 1 explicitly notes entropy-only heuristics misfire on
// legitimate compression/encryption.
inline double shannon_entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;

    std::array<size_t, 256> counts{};
    for (size_t i = 0; i < len; ++i) {
        counts[data[i]]++;
    }

    double entropy = 0.0;
    const double n = static_cast<double>(len);
    for (size_t c : counts) {
        if (c == 0) continue;
        double p = static_cast<double>(c) / n;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// Small-sample bias correction (added after audit finding M1).
//
// The plug-in Shannon estimate is biased low for short buffers: a
// truly random n-byte write has expected entropy of only about
// 8 - 255/(2 n ln 2) bits/byte (6.55 at n=128, 7.18 at n=256, versus
// 8.0 for large n). Compared against a fixed 7.5 high-water mark, an
// attacker who encrypts in 128-256-byte pieces (or overwrites just file
// headers) therefore never looks "high entropy". We add back the
// expected shortfall so random data scores ~8 at any size >= 128 bytes,
// while structured data (text ~4-5 bits) still stays far below the
// mark. Below 128 bytes the estimate is too noisy to be a useful signal
// and the raw value is returned unchanged.
inline double bias_corrected_entropy(double raw, size_t len) {
    if (len < 128) return raw;
    const double shortfall = 255.0 / (2.0 * static_cast<double>(len) * 0.6931471805599453);
    double adj = raw + shortfall;
    return adj > 8.0 ? 8.0 : adj;
}
