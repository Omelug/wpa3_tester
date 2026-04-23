#pragma once
#include <memory>
#include <string>
#include <unordered_map>

namespace wpa3_tester::observer{
class Observer_config;

class ObserverPtr{
public:
    std::shared_ptr<Observer_config> ptr;
    explicit ObserverPtr(std::shared_ptr<Observer_config> p);

    Observer_config *operator->() const;
    Observer_config &operator*() const;
    Observer_config *get() const;
    std::shared_ptr<Observer_config> shared() const;

    friend bool operator<(const ObserverPtr &lhs, const ObserverPtr &rhs);
    friend bool operator==(const ObserverPtr &lhs, const ObserverPtr &rhs){ return lhs.ptr == rhs.ptr; }
};

using ObserverCMap = std::unordered_map<std::string,ObserverPtr>;

struct hash_ObserverPtr{
    size_t operator()(const ObserverPtr &ap) const{
        return std::hash<std::shared_ptr<Observer_config>>{}(ap.ptr);
    }
};

inline bool operator<(const ObserverPtr &lhs, const ObserverPtr &rhs){
    return lhs.ptr < rhs.ptr;
}
}