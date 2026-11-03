// tests/test_ext_tracker.cpp -- unit tests for ExtensionTracker.
//
// The on_rename() test cases specifically pin down a real bug found
// during development: an earlier version reused the same-path
// on_write() check for renames, comparing the FROM path's extension
// against its own history -- which never changes on a rename, so the
// classic "doc.txt -> doc.txt.locked" ransomware signature was never
// actually detected. These tests exist so that regression can't
// silently reappear.
#include "ext_tracker.hpp"
#include <cassert>
#include <iostream>

int main() {
    // First write to a path is never a "change" (no prior history).
    {
        ExtensionTracker t;
        assert(t.on_write("doc.txt") == false);
    }

    // Same extension on repeated writes: not a change.
    {
        ExtensionTracker t;
        t.on_write("doc.txt");
        assert(t.on_write("doc.txt") == false);
    }

    // *** The actual bug this module fixes ***
    // Renaming doc.txt -> doc.txt.locked must be detected as an
    // extension change, even though doc.txt (the FROM path) never
    // itself had a differing extension recorded.
    {
        ExtensionTracker t;
        t.on_write("doc.txt");                              // establish history for doc.txt
        bool changed = t.on_rename("doc.txt", "doc.txt.locked");
        assert(changed == true);
    }

    // Renaming with no prior write history for the source still
    // detects a real extension change between from/to.
    {
        ExtensionTracker t;
        bool changed = t.on_rename("report.docx", "report.encrypted");
        assert(changed == true);
    }

    // Renaming to the SAME extension (e.g. a case-normalize or a
    // benign move) must NOT be flagged.
    {
        ExtensionTracker t;
        bool changed = t.on_rename("notes.txt", "archive/notes.txt");
        assert(changed == false);
    }

    // Dropping an extension entirely (doc.txt -> doc) counts as a change.
    {
        ExtensionTracker t;
        bool changed = t.on_rename("doc.txt", "doc");
        assert(changed == true);
    }

    // Gaining an extension where there was none also counts.
    {
        ExtensionTracker t;
        bool changed = t.on_rename("README", "README.locked");
        assert(changed == true);
    }

    // After a rename, the tracker's identity for the path follows the
    // NEW name: writing again to `to` with the same extension is not
    // itself flagged as a further change.
    {
        ExtensionTracker t;
        t.on_rename("doc.txt", "doc.txt.locked");
        assert(t.on_write("doc.txt.locked") == false);
    }

    std::cout << "test_ext_tracker: ALL PASSED\n";
    return 0;
}
