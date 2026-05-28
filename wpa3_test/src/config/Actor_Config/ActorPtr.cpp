#include "config/Actor_Config/ActorPtr.h"
#include "config/Actor_Config/Actor_config.h"

#include <memory>
using namespace std;

namespace wpa3_tester{
ActorPtr::ActorPtr(shared_ptr<Actor_config> p): ptr(std::move(p)){}
Actor_config *ActorPtr::operator->() const{ return ptr.get(); }
Actor_config &ActorPtr::operator*() const{ return *ptr; }
Actor_config *ActorPtr::get() const{ return ptr.get(); }
string ActorPtr::get(const SK key) const{ return ptr.get()->get(key);}
bool ActorPtr::get(const BK key) const{ return ptr.get()->get(key);}
shared_ptr<Actor_config> ActorPtr::shared() const{ return ptr; }
string ActorPtr::operator[](const string &key) const{ return (*ptr)[key]; }
std::optional<string>& ActorPtr::operator[](const SK key) { return (*ptr)[key]; }
const std::optional<std::string> &ActorPtr::operator[](const SK key) const { return (*ptr)[key];}
std::optional<bool>& ActorPtr::operator[](const BK key) {return (*ptr)[key]; }
const std::optional<bool>& ActorPtr::operator[](const BK key) const { return (*ptr)[key]; }
}
