#pragma once
#include <memory>
#include <string>
#include <unordered_map>

namespace wpa3_tester{
class Actor_config;

class ActorPtr{
public:
    std::shared_ptr<Actor_config> ptr;
    explicit ActorPtr() = default;
    explicit ActorPtr(std::shared_ptr<Actor_config> p);

    Actor_config *operator->() const;
    Actor_config &operator*() const;
    std::string operator[](const std::string &key) const;
    Actor_config *get() const;
    std::shared_ptr<Actor_config> shared() const;

    friend bool operator<(const ActorPtr &lhs, const ActorPtr &rhs);

    friend bool operator==(const ActorPtr &lhs, const ActorPtr &rhs){
        return lhs.ptr == rhs.ptr;
    }
};

using ActorCMap = std::unordered_map<std::string,ActorPtr>; // <actor_name, ActorPtr>
struct hash_ActorPtr{
    size_t operator()(const ActorPtr &ap) const{
        return std::hash<std::shared_ptr<Actor_config>>{}(ap.ptr);
    }
};

inline bool operator<(const ActorPtr &lhs, const ActorPtr &rhs){
    return lhs.ptr < rhs.ptr;
}
}