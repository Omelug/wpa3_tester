#include "config/ObserverPtr.h"
#include "config/Observer_config.h"
#include <memory>

namespace wpa3_tester::observer{
using namespace std;
ObserverPtr::ObserverPtr(shared_ptr<Observer_config> p): ptr(move(p)){}
Observer_config *ObserverPtr::operator->() const{ return ptr.get(); }
Observer_config &ObserverPtr::operator*() const{ return *ptr; }
Observer_config *ObserverPtr::get() const{ return ptr.get(); }
shared_ptr<Observer_config> ObserverPtr::shared() const{ return ptr; }
}