#include "config/ActorPtr.h"
#include "config/Actor_config.h"

#include <memory>
namespace  wpa3_tester{
    ActorPtr::ActorPtr(std::shared_ptr<Actor_config> p): ptr(std::move(p)){}
    Actor_config* ActorPtr::operator->() const { return ptr.get(); }
    Actor_config& ActorPtr::operator*()  const { return *ptr; }
    std::string ActorPtr::operator[](const std::string& key) const { return (*ptr)[key]; }
    Actor_config* ActorPtr::get() const { return ptr.get(); }
}
