// Tiny JSON value, parser and writer — just enough for the admin API.
#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wsrv::json {

class Value {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Value() = default;
    static Value Bool(bool b) { Value v; v.type_ = Type::Bool; v.b_ = b; return v; }
    static Value Number(double d) { Value v; v.type_ = Type::Number; v.n_ = d; return v; }
    static Value String(std::string s) { Value v; v.type_ = Type::String; v.s_ = std::move(s); return v; }
    static Value Array() { Value v; v.type_ = Type::Array; return v; }
    static Value Object() { Value v; v.type_ = Type::Object; return v; }

    Type type() const { return type_; }
    bool isNull() const { return type_ == Type::Null; }
    bool isBool() const { return type_ == Type::Bool; }
    bool isNumber() const { return type_ == Type::Number; }
    bool isString() const { return type_ == Type::String; }
    bool isArray() const { return type_ == Type::Array; }
    bool isObject() const { return type_ == Type::Object; }

    bool asBool() const { return b_; }
    double asNumber() const { return n_; }
    const std::string& asString() const { return s_; }
    const std::vector<Value>& items() const { return arr_; }
    const std::vector<std::pair<std::string, Value>>& members() const { return obj_; }

    // Object access. get() returns nullptr when missing.
    const Value* get(std::string_view key) const;
    Value& set(std::string key, Value v);
    Value& push(Value v) { arr_.push_back(std::move(v)); return arr_.back(); }

    std::string dump() const;

private:
    void dumpTo(std::string& out) const;
    Type type_ = Type::Null;
    bool b_ = false;
    double n_ = 0;
    std::string s_;
    std::vector<Value> arr_;
    std::vector<std::pair<std::string, Value>> obj_;
};

std::optional<Value> Parse(std::string_view text);
std::string Quote(std::string_view s);

} // namespace wsrv::json
