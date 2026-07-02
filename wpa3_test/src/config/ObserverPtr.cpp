#include "config/ObserverPtr.h"
#include <memory>
#include "config/Observer_config.h"

using namespace std;

namespace wpa3_tester::observer{
ObserverPtr::ObserverPtr(shared_ptr<Observer_config> p): ptr(std::move(p)){}
Observer_config *ObserverPtr::operator->() const{ return ptr.get(); }
Observer_config &ObserverPtr::operator*() const{ return *ptr; }
Observer_config *ObserverPtr::get() const{ return ptr.get(); }
shared_ptr<Observer_config> ObserverPtr::shared() const{ return ptr; }
}