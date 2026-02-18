// timewriter.h

#ifndef TIMEWRITER_H
#define TIMEWRITER_H

#include <string>
#include <fstream>
#include <chrono>
#include <thread>
#include <atomic>

class TimeWriter {
private:
    std::ofstream time_file;
    std::ofstream memory_file;
    std::string filename_time;
    std::string filename_memory;
    std::thread memory_thread;
    std::atomic<bool> stop_logging{false};

    // Returns the current date and time as a formatted timestamp string.
    std::string getCurrentTimestamp();

    // Returns the current memory usage of the specified type as a string.
    std::string getCurrentMemory(const std::string& type);

    // Returns a timestamp string suitable for use in file names.
    std::string getFileTimestamp();

public:
    TimeWriter() = default;
    ~TimeWriter();

    // Creates and returns a new TimeWriter instance writing to files named after the given identifier.
    static TimeWriter* initialize_timewriter(const std::string& filename);

    // Writes a timestamped log entry with the given message to the time log file.
    void log_timewriter(const std::string& msg);
};

#endif // TIMEWRITER_H