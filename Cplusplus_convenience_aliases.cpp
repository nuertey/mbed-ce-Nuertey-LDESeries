using SystemClock_t = std::chrono::system_clock;
using Seconds_t     = std::chrono::seconds;
using Minutes_t     = std::chrono::minutes;


// To lessen verbosity, try defining the following convenience aliases in a header:
using SystemClock_t         = std::chrono::system_clock;
using SteadyClock_t         = std::chrono::steady_clock;
using HighClock_t           = std::chrono::high_resolution_clock;
using SharedDelay_t         = std::atomic<SystemClock_t::duration>;
using Minutes_t             = std::chrono::minutes;
using Seconds_t             = std::chrono::seconds;
using MilliSecs_t           = std::chrono::milliseconds;
using MicroSecs_t           = std::chrono::microseconds;
using NanoSecs_t            = std::chrono::nanoseconds;
using DoubleSecs_t          = std::chrono::duration<double>;
using FloatingMilliSecs_t   = std::chrono::duration<double, std::milli>;
using FloatingMicroSecs_t   = std::chrono::duration<double, std::micro>;