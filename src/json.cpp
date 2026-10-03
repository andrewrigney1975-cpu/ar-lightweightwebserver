#include "json.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace wsrv::json {

const Value* Value::get(std::string_view key) const {
    for (auto& [k, v] : obj_) if (k == key) return &v;
    return nullptr;
}

Value& Value::set(std::string key, Value v) {
    for (auto& [k, existing] : obj_) {
        if (k == key) { existing = std::move(v); return existing; }
    }
    obj_.emplace_back(std::move(key), std::move(v));
    return obj_.back().second;
}

std::string Quote(std::string_view s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case '<': out += "\\u003c"; break;  // safe to embed anywhere
        default:
            if (c < 0x20) {
                char buf[8];
                snprintf(buf, sizeof buf, "\\u%04x", c);
                out += buf;
            } else {
                out += char(c);
            }
        }
    }
    return out + "\"";
}

void Value::dumpTo(std::string& out) const {
    switch (type_) {
    case Type::Null: out += "null"; break;
    case Type::Bool: out += b_ ? "true" : "false"; break;
    case Type::Number: {
        char buf[32];
        if (std::floor(n_) == n_ && std::fabs(n_) < 9e15) snprintf(buf, sizeof buf, "%lld", (long long)n_);
        else snprintf(buf, sizeof buf, "%.17g", n_);
        out += buf;
        break;
    }
    case Type::String: out += Quote(s_); break;
    case Type::Array:
        out += '[';
        for (size_t i = 0; i < arr_.size(); ++i) { if (i) out += ','; arr_[i].dumpTo(out); }
        out += ']';
        break;
    case Type::Object:
        out += '{';
        for (size_t i = 0; i < obj_.size(); ++i) {
            if (i) out += ',';
            out += Quote(obj_[i].first);
            out += ':';
            obj_[i].second.dumpTo(out);
        }
        out += '}';
        break;
    }
}

std::string Value::dump() const {
    std::string out;
    dumpTo(out);
    return out;
}

namespace {

class Parser {
public:
    explicit Parser(std::string_view t) : t_(t) {}

    std::optional<Value> parseDocument() {
        auto v = parseValue(0);
        ws();
        if (!v || pos_ != t_.size()) return std::nullopt;
        return v;
    }

private:
    static constexpr int kMaxDepth = 32;

    void ws() {
        while (pos_ < t_.size() && (t_[pos_] == ' ' || t_[pos_] == '\t' || t_[pos_] == '\n' || t_[pos_] == '\r')) ++pos_;
    }
    bool lit(std::string_view w) {
        if (t_.substr(pos_, w.size()) != w) return false;
        pos_ += w.size();
        return true;
    }

    std::optional<Value> parseValue(int depth) {
        if (depth > kMaxDepth) return std::nullopt;
        ws();
        if (pos_ >= t_.size()) return std::nullopt;
        char c = t_[pos_];
        if (c == 'n') return lit("null") ? std::optional<Value>(Value()) : std::nullopt;
        if (c == 't') return lit("true") ? std::optional<Value>(Value::Bool(true)) : std::nullopt;
        if (c == 'f') return lit("false") ? std::optional<Value>(Value::Bool(false)) : std::nullopt;
        if (c == '"') {
            auto s = parseString();
            if (!s) return std::nullopt;
            return Value::String(std::move(*s));
        }
        if (c == '[') return parseArray(depth);
        if (c == '{') return parseObject(depth);
        return parseNumber();
    }

    std::optional<Value> parseNumber() {
        size_t start = pos_;
        if (pos_ < t_.size() && t_[pos_] == '-') ++pos_;
        while (pos_ < t_.size() && ((t_[pos_] >= '0' && t_[pos_] <= '9') || t_[pos_] == '.' || t_[pos_] == 'e' ||
                                    t_[pos_] == 'E' || t_[pos_] == '+' || t_[pos_] == '-'))
            ++pos_;
        if (start == pos_) return std::nullopt;
        std::string num(t_.substr(start, pos_ - start));
        char* end = nullptr;
        double d = strtod(num.c_str(), &end);
        if (!end || *end) return std::nullopt;
        return Value::Number(d);
    }

    static void AppendUtf8(std::string& out, unsigned cp) {
        if (cp < 0x80) out += char(cp);
        else if (cp < 0x800) { out += char(0xC0 | (cp >> 6)); out += char(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) {
            out += char(0xE0 | (cp >> 12)); out += char(0x80 | ((cp >> 6) & 0x3F)); out += char(0x80 | (cp & 0x3F));
        } else {
            out += char(0xF0 | (cp >> 18)); out += char(0x80 | ((cp >> 12) & 0x3F));
            out += char(0x80 | ((cp >> 6) & 0x3F)); out += char(0x80 | (cp & 0x3F));
        }
    }

    bool hex4(unsigned& out) {
        if (pos_ + 4 > t_.size()) return false;
        out = 0;
        for (int i = 0; i < 4; ++i) {
            char c = t_[pos_++];
            out <<= 4;
            if (c >= '0' && c <= '9') out |= unsigned(c - '0');
            else if (c >= 'a' && c <= 'f') out |= unsigned(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') out |= unsigned(c - 'A' + 10);
            else return false;
        }
        return true;
    }

    std::optional<std::string> parseString() {
        ++pos_;  // opening quote
        std::string out;
        while (pos_ < t_.size()) {
            char c = t_[pos_++];
            if (c == '"') return out;
            if ((unsigned char)c < 0x20) return std::nullopt;
            if (c != '\\') { out += c; continue; }
            if (pos_ >= t_.size()) return std::nullopt;
            char e = t_[pos_++];
            switch (e) {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u': {
                unsigned cp;
                if (!hex4(cp)) return std::nullopt;
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    unsigned lo;
                    if (!lit("\\u") || !hex4(lo) || lo < 0xDC00 || lo > 0xDFFF) return std::nullopt;
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    return std::nullopt;
                }
                AppendUtf8(out, cp);
                break;
            }
            default: return std::nullopt;
            }
        }
        return std::nullopt;
    }

    std::optional<Value> parseArray(int depth) {
        ++pos_;
        Value arr = Value::Array();
        ws();
        if (pos_ < t_.size() && t_[pos_] == ']') { ++pos_; return arr; }
        for (;;) {
            auto v = parseValue(depth + 1);
            if (!v) return std::nullopt;
            arr.push(std::move(*v));
            ws();
            if (pos_ >= t_.size()) return std::nullopt;
            if (t_[pos_] == ',') { ++pos_; continue; }
            if (t_[pos_] == ']') { ++pos_; return arr; }
            return std::nullopt;
        }
    }

    std::optional<Value> parseObject(int depth) {
        ++pos_;
        Value obj = Value::Object();
        ws();
        if (pos_ < t_.size() && t_[pos_] == '}') { ++pos_; return obj; }
        for (;;) {
            ws();
            if (pos_ >= t_.size() || t_[pos_] != '"') return std::nullopt;
            auto key = parseString();
            if (!key) return std::nullopt;
            ws();
            if (pos_ >= t_.size() || t_[pos_] != ':') return std::nullopt;
            ++pos_;
            auto v = parseValue(depth + 1);
            if (!v) return std::nullopt;
            obj.set(std::move(*key), std::move(*v));
            ws();
            if (pos_ >= t_.size()) return std::nullopt;
            if (t_[pos_] == ',') { ++pos_; continue; }
            if (t_[pos_] == '}') { ++pos_; return obj; }
            return std::nullopt;
        }
    }

    std::string_view t_;
    size_t pos_ = 0;
};

} // namespace

std::optional<Value> Parse(std::string_view text) { return Parser(text).parseDocument(); }

} // namespace wsrv::json
