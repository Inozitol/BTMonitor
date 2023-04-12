#include "thread-killer.h"

bool thread_killer_t::wait_for(const std::chrono::seconds& time) {
    std::unique_lock<std::mutex> lock(mx);
    return !cond.wait_for(lock, time, [&]{return terminate;});
}

void thread_killer_t::kill() {
    std::unique_lock<std::mutex> lock(mx);
    terminate = true;
    cond.notify_all();
}
