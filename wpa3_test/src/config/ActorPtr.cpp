#include "config/ActorPtr.h"
#include "config/Actor_config.h"

#include <memory>
using namespace std;

namespace wpa3_tester{
ActorPtr::ActorPtr(shared_ptr<Actor_config> p): ptr(std::move(p)){}
Actor_config *ActorPtr::operator->() const{ return ptr.get(); }
Actor_config &ActorPtr::operator*() const{ return *ptr; }
string ActorPtr::operator[](const string &key) const{ return (*ptr)[key]; }
Actor_config *ActorPtr::get() const{ return ptr.get(); }
shared_ptr<Actor_config> ActorPtr::shared() const{ return ptr; }
}