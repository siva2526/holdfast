#include "ext_tracker.hpp"

bool ExtensionTracker::extension_of(const std::string& path, std::string* ext) {
    auto pos = path.find_last_of('.');
    if (pos == std::string::npos) return false;
    *ext = path.substr(pos);
    return true;
}

bool ExtensionTracker::on_write(const std::string& path) {
    std::string ext;
    bool has_ext = extension_of(path, &ext);

    std::lock_guard<std::mutex> lk(mu_);
    auto it = last_ext_.find(path);
    bool changed = false;
    if (it != last_ext_.end()) {
        changed = has_ext && it->second != ext;
    }
    if (has_ext) last_ext_[path] = ext;
    return changed;
}

bool ExtensionTracker::on_rename(const std::string& from, const std::string& to) {
    std::string ext_from, ext_to;
    bool has_from = extension_of(from, &ext_from);
    bool has_to = extension_of(to, &ext_to);
    bool changed = (has_from != has_to) || (has_from && has_to && ext_from != ext_to);

    std::lock_guard<std::mutex> lk(mu_);
    last_ext_.erase(from);
    if (has_to) last_ext_[to] = ext_to;
    return changed;
}
