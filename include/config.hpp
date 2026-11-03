#pragma once
#include <string>
#include <unordered_map>

// Minimal key=value config loader. Deliberately not JSON/YAML: this
// project has ~12 scalar tunables and pulling in a parsing dependency
// isn't worth it. Format (one per line, '#' comments allowed):
//
//   w_entropy = 1.0
//   promote_threshold = 10.0
//   suspend_on_detect = true
//
// Unknown keys are ignored (forward-compatible); missing keys fall
// back to the caller-supplied default.
class Config {
public:
    // Loads from `path` if it exists; silently uses defaults otherwise
    // (a missing config file is not an error -- the tool should still
    // run out of the box).
    static Config load(const std::string& path);

    double get_double(const std::string& key, double def) const;
    int get_int(const std::string& key, int def) const;
    bool get_bool(const std::string& key, bool def) const;
    std::string get_string(const std::string& key, const std::string& def) const;

private:
    std::unordered_map<std::string, std::string> values_;
};
