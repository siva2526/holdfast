#include "event_log.hpp"

#include <chrono>
#include <deque>
#include <fstream>
#include <sstream>

namespace {

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            default: out += c;
        }
    }
    return out;
}

long long now_millis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

EventLog::EventLog(std::string path) : path_(std::move(path)) {}

void EventLog::log(const std::string& type, long pid, const std::string& path,
                    double entropy, double score, const std::string& checkpoint_id,
                    const std::string& detail) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!out_.is_open() || !out_.good()) { out_.clear(); out_.open(path_, std::ios::app); }
    if (!out_) return;

    std::ostringstream ss;
    ss << "{"
       << "\"ts\":" << now_millis() << ","
       << "\"type\":\"" << json_escape(type) << "\"";
    if (pid >= 0) ss << ",\"pid\":" << pid;
    if (!path.empty()) ss << ",\"path\":\"" << json_escape(path) << "\"";
    if (entropy >= 0.0) ss << ",\"entropy\":" << entropy;
    if (score >= 0.0) ss << ",\"score\":" << score;
    if (!checkpoint_id.empty()) ss << ",\"checkpoint_id\":\"" << json_escape(checkpoint_id) << "\"";
    if (!detail.empty()) ss << ",\"detail\":\"" << json_escape(detail) << "\"";
    ss << "}\n";

    out_ << ss.str();
    out_.flush();           // live viewers (rrfs_ctl watch, the demo panel) read this file while we run
}

std::vector<std::string> EventLog::tail(int n) const {
    std::lock_guard<std::mutex> lk(mu_);
    std::ifstream in(path_);
    std::deque<std::string> buf;
    std::string line;
    while (std::getline(in, line)) {
        buf.push_back(line);
        if (static_cast<int>(buf.size()) > n) buf.pop_front();
    }
    return std::vector<std::string>(buf.begin(), buf.end());
}
