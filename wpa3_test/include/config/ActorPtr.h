#pragma once
#include <memory>
#include <string>
#include "Actor_config.h"

namespace wpa3_tester{
class Actor_config;

class ActorPtr{
protected:
	std::shared_ptr<Actor_config> ptr;
public:
	explicit ActorPtr() = default;
	explicit ActorPtr(std::shared_ptr<Actor_config> p);

	Actor_config *operator->() const;
	Actor_config &operator*()  const;
	Actor_config *get()        const;
	std::shared_ptr<Actor_config> shared() const;

	std::string operator[](const std::string &key) const;
	std::optional<std::string>&       operator[](SK key);
	const std::optional<std::string>& operator[](SK key) const;
	std::optional<bool>&              operator[](BK key);
	const std::optional<bool>&        operator[](BK key) const;

	friend bool operator==(const ActorPtr &lhs, const ActorPtr &rhs){ return lhs.ptr == rhs.ptr;}
	friend bool operator<(const ActorPtr &lhs, const ActorPtr &rhs){ return lhs.ptr < rhs.ptr;}
};

/*struct hash_ActorPtr{
	size_t operator()(const ActorPtr &ap) const{
		return std::hash<std::shared_ptr<Actor_config>>{}(ap.ptr);
	}
};*/
/*
inline bool operator<(const ActorPtr &lhs, const ActorPtr &rhs){
	return lhs.ptr < rhs.ptr;
}*/
}
