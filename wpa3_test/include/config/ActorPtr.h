#pragma once
#include <memory>
#include <string>
#include <unordered_map>
namespace  wpa3_tester{
    class Actor_config;

    class ActorPtr {
        std::shared_ptr<Actor_config> ptr;
    public:
        explicit ActorPtr(std::shared_ptr<Actor_config> p);

        Actor_config* operator->() const;
        Actor_config& operator*()  const;
        std::string operator[](const std::string& key) const;
        Actor_config* get() const;
        std::shared_ptr<Actor_config> shared() const;
    };
    using ActorCMap = std::unordered_map<std::string,ActorPtr>;
}