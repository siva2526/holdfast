#pragma once
// Differential content analysis against the PRESERVED ORIGINAL bytes.
//
// rrfs already keeps the pre-write bytes of every file it is about to
// modify. That gives it something a content-blind detector lacks: ground
// truth about what the write is replacing. Instead of asking "is the new
// data high entropy?" (which flags every copy of a JPEG over an older
// JPEG) we ask "did this write turn recognisable data into noise?":
//
//   * type_destroyed  - the old bytes began with a known file signature
//                       (JPEG, PNG, PDF, ZIP/OOXML, gzip, ...) and the new
//                       bytes at offset 0 do not carry the same signature;
//   * text_destroyed  - the old region was almost all printable text and
//                       the new region is mostly non-printable (works for
//                       writes too small for a reliable entropy estimate);
//   * entropy_jump    - entropy rose by at least `jump_min` bits/byte
//                       relative to the bytes being replaced.
//
// A high-entropy overwrite of high-entropy data whose signature survives
// (cp of one photo over another) is judged benign. Re-encryption of data
// that has no known signature and is already near 8 bits/byte is a
// documented blind spot.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/types.h>
#include "entropy.hpp"

enum class FileType {
    None, Jpeg, Png, Pdf, Zip, Gzip, SevenZ, Rar, Gif, Mp4, Sqlite, Elf, Bmp, Ole, Riff, Bzip2, Xz
};

inline FileType detect_magic(const uint8_t* d, size_t n) {
    auto is = [&](const char* sig, size_t len, size_t off = 0) {
        return n >= off + len && std::memcmp(d + off, sig, len) == 0;
    };
    if (is("\xFF\xD8\xFF", 3)) return FileType::Jpeg;
    if (is("\x89PNG", 4)) return FileType::Png;
    if (is("%PDF", 4)) return FileType::Pdf;
    if (is("PK\x03\x04", 4)) return FileType::Zip;
    if (is("\x1F\x8B", 2)) return FileType::Gzip;
    if (is("7z\xBC\xAF", 4)) return FileType::SevenZ;
    if (is("Rar!", 4)) return FileType::Rar;
    if (is("GIF8", 4)) return FileType::Gif;
    if (is("ftyp", 4, 4)) return FileType::Mp4;
    if (is("SQLite format 3", 15)) return FileType::Sqlite;
    if (is("\x7F" "ELF", 4)) return FileType::Elf;
    if (is("BM", 2) && n >= 6) return FileType::Bmp;
    if (is("\xD0\xCF\x11\xE0", 4)) return FileType::Ole;
    if (is("RIFF", 4)) return FileType::Riff;
    if (is("BZh", 3)) return FileType::Bzip2;
    if (is("\xFD" "7zXZ", 5)) return FileType::Xz;
    return FileType::None;
}

inline double printable_ratio(const uint8_t* d, size_t n) {
    if (n == 0) return 1.0;
    size_t p = 0;
    for (size_t i = 0; i < n; ++i)
        if ((d[i] >= 0x20 && d[i] < 0x7F) || d[i] == '\n' || d[i] == '\r' || d[i] == '\t') ++p;
    return static_cast<double>(p) / static_cast<double>(n);
}

struct DeltaVerdict {
    bool old_known = false;       // we had original bytes to compare against
    bool old_typed = false;       // original began with a known file signature (offset 0 only)
    bool type_destroyed = false;
    bool text_destroyed = false;
    bool entropy_jump = false;
    double h_old = 0.0;
    // True when the write turned recognisable data into noise.
    bool content_suspicious() const { return entropy_jump || type_destroyed || text_destroyed; }
};

// old/new are the bytes of the SAME file range: old_b[0..old_n) is what
// is being replaced, new_b[0..new_n) what replaces it. `offset` is the
// file offset of the range (type checks apply only at offset 0).
inline DeltaVerdict compare_old_new(const uint8_t* old_b, size_t old_n,
                                    const uint8_t* new_b, size_t new_n,
                                    off_t offset, double h_new, double jump_min, bool type_conversion_benign = false) {
    DeltaVerdict v;
    if (old_n == 0 || new_n == 0) return v;
    v.old_known = true;
    size_t m = old_n < new_n ? old_n : new_n;
    v.h_old = bias_corrected_entropy(shannon_entropy(old_b, m), m);
    // Below 128 bytes the entropy estimate of the OLD region is too noisy (and is not
    // bias-corrected), which manufactured a spurious "jump" for random-over-random
    // writes straddling EOF. Only compare when both sides are reliable.
    v.entropy_jump = m >= 128 && (h_new - v.h_old) >= jump_min;
    if (offset == 0 && old_n >= 4 && new_n >= 8) {
        FileType t = detect_magic(old_b, old_n);
        v.old_typed = t != FileType::None;
        if (t != FileType::None) {
            FileType nt = detect_magic(new_b, new_n);
            // A conversion between two KNOWN formats (JPEG->PNG re-encode) is not destruction; if the new data is
            // also noise the ambiguous-write policy, not the type signal, deals with it.
            if (nt != t && !(type_conversion_benign && nt != FileType::None)) v.type_destroyed = true;
        }
    }
    if (m >= 32 && printable_ratio(old_b, m) >= 0.9 && printable_ratio(new_b, m) <= 0.6)
        v.text_destroyed = true;
    return v;
}
