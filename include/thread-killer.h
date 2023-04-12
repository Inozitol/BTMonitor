#pragma once

#include <thread>
#include <condition_variable>
#include <mutex>

/** @struct thread_killer_t
 * @brief Mechanism used to preemptively kill sleeping threads.
 */
struct thread_killer_t{
    bool wait_for(const std::chrono::seconds& time);
    void kill();

    std::condition_variable cond;
    std::mutex mx;
    bool terminate = false;
};

extern thread_killer_t thread_killer;
