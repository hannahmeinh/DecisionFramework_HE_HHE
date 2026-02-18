// timewriter.cpp

#include <iomanip>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <iostream>

#include "timewriter.h"
#include "../Parameters/parameters.h"

// Returns the current timestamp as a formatted string with microsecond precision.
std::string TimeWriter::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()) % 1000000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(6) << microseconds.count();
    return ss.str();
}

// Reads and returns a specific memory metric from /proc/self/status by its type key.
std::string TimeWriter::getCurrentMemory(const std::string& type) {
    std::ifstream file("/proc/self/status");
    std::string line;
    
    while (std::getline(file, line)) {
        if (line.find(type) == 0) {
            size_t start = line.find_first_of("0123456789");
            if (start != std::string::npos) {
                size_t end = line.find(" kB", start);
                if (end != std::string::npos) {
                    return line.substr(start, end - start) + " kB";
                }
            }
        }
    }
    return "0 kB";
}

// Returns the current timestamp formatted for use in filenames.
std::string TimeWriter::getFileTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d_%H-%M-%S");
    return ss.str();
}

// Stops the memory logging thread and closes all open output files.
TimeWriter::~TimeWriter() {
    stop_logging = true;
    if (memory_thread.joinable()) {
        memory_thread.join();
    }
    if (time_file.is_open()) {
        time_file.close();
    }
    if (memory_file.is_open()) {
        memory_file.close();
    }
}

// Creates and initializes a TimeWriter instance with output files for time and memory logging.
TimeWriter* TimeWriter::initialize_timewriter(const std::string& filename) {
    TimeWriter* writer = new TimeWriter();
    
    std::filesystem::path timeDir("../../Performance_Measurement/data_time");
    if (!std::filesystem::exists(timeDir)) {
        std::filesystem::create_directories(timeDir);
    }
    std::filesystem::path memoryDir("../../Performance_Measurement/data_memory");
    if (!std::filesystem::exists(memoryDir)) {
        std::filesystem::create_directories(memoryDir);
    }
    
    std::string filename_prefix = writer->getFileTimestamp() + "_" + ParameterClass::get_encryption_variant() + "_BatchNr:" + std::to_string(ParameterClass::get_batch_number()) + "_BatchSize:" + std::to_string(ParameterClass::get_batch_size()) + "_IntSize:" + std::to_string(ParameterClass::get_integer_size()) + "_" + filename + ".txt";

    writer->filename_time = "../../Performance_Measurement/data_time/" + filename_prefix;
    writer->filename_memory = "../../Performance_Measurement/data_memory/" + filename_prefix;
    
    writer->time_file.open(writer->filename_time, std::ios::app);
    writer->memory_file.open(writer->filename_memory, std::ios::app);

    std::cout << "Time measurements stored in file " << writer->filename_time << std::endl;
    std::cout << "Memory measurements stored in file " << writer->filename_memory << std::endl;
    
    return writer;
}

// Logs a timestamped message along with current memory usage metrics to both output files.
void TimeWriter::log_timewriter(const std::string& msg) {
    if (time_file.is_open()) {
        time_file << getCurrentTimestamp() << " : " << msg << std::endl;
        time_file.flush();
    }
    if (memory_file.is_open()) {
        auto timestamp = getCurrentTimestamp();
        memory_file << timestamp << " : " << msg << std::endl;
        memory_file << timestamp << " SWAP: " << getCurrentMemory("VmSwap:") << std::endl;
        memory_file << timestamp << " RAM Peak: " << getCurrentMemory("VmHWM:") << std::endl;
        memory_file << timestamp << " RAM: " << getCurrentMemory("VmRSS:") << std::endl;
        memory_file << timestamp << " Virtual Memory Peak: " << getCurrentMemory("VmPeak:") << std::endl;
        memory_file << timestamp << " Virtual Memory: " << getCurrentMemory("VmSize:") << std::endl;
        memory_file.flush();
    }
}