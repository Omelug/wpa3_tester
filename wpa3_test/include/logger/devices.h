#pragma once
#include "config/Actor_Config/ActorPtr.h"

namespace wpa3_tester::report{
// Returns true if a new snapshot was created, false if an identical hw config already existed.
bool add_device(ActorPtr actor);
}
