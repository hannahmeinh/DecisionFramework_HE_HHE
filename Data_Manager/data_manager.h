// data_management.h

#ifndef FILE_STORE_H
#define FILE_STORE_H

#include <cstdint>
#include <string>
#include <vector>
#include <iosfwd>
#include <stdexcept>
#include <mutex>

#include "../hybrid-HE-framework/ciphers/common/TFHE_Cipher.h"
#include "include/tfhe.h"

// Appends a vector of bytes to a file with thread-safe locking.
void append_vector_to_file(const std::string& path, const std::vector<uint8_t>& data);

// Appends a vector of TFHE ciphertexts to a file after serialization.
void append_vector_to_file(const std::string& path,
                           const TFHECiphertextVec& data,
                           TFheGateBootstrappingParameterSet* params);

// Returns the path of the most recently modified file in the given directory.
std::string get_latest_file_in_directory(const std::string& directory_path);

// Provides sequential reading of binary vectors from a file.
class FileVectorReader {
public:
    // Opens the specified file for reading; throws on error.
    explicit FileVectorReader(const std::string& path);
    ~FileVectorReader();

    // Reads the next vector element into out; returns false at EOF.
    bool next(std::vector<uint8_t>& out);

    // Resets the read position to the beginning of the file.
    void reset();

private:
    struct Impl;
    Impl* pimpl;
};

// Provides sequential reading of TFHE ciphertext vectors from a file.
class FileTFHEVectorReader {
public:
    // Opens the specified file and configures TFHE deserialization with the given parameters.
    explicit FileTFHEVectorReader(const std::string& path, TFheGateBootstrappingParameterSet* params);
    ~FileTFHEVectorReader();

    // Reads the next TFHE ciphertext vector into out; returns false at EOF.
    bool next(TFHECiphertextVec& out);

    // Resets the read position to the beginning of the file.
    void reset();

private:
    struct Impl;
    Impl* pimpl;
};

// Sends a binary vector to the given ZeroMQ endpoint, reusing existing connections where possible.
void send_vector_via_zmq(const std::string& zmq_endpoint, const std::vector<uint8_t>& data);

// Serializes and sends a vector of TFHE ciphertexts to the given ZeroMQ endpoint.
void send_vector_via_zmq(const std::string& zmq_endpoint,
                         const TFHECiphertextVec& data,
                         TFheGateBootstrappingParameterSet* params);

// Reads all binary vectors from a file and sends them via ZeroMQ, optionally deleting the file afterwards.
void send_all_vectors_via_zmq(const std::string& path,
                             const std::string& zmq_endpoint,
                             bool remove_after_send = true);

// Reads all TFHE ciphertext vectors from a file and sends them via ZeroMQ, optionally deleting the file afterwards.
void send_all_vectors_via_zmq(const std::string& path,
                             const std::string& zmq_endpoint,
                             TFheGateBootstrappingParameterSet* params,
                             bool remove_after_send = true);

// Receives binary messages from a ZeroMQ endpoint and stores them in a file; returns the number of messages received.
size_t zmq_receive_and_store(const std::string& path,
                           const std::string& zmq_endpoint,
                           size_t max_messages = 0,
                           bool expect_eof_frame = true);

// Receives TFHE messages from a ZeroMQ endpoint, deserializes them, and stores them in a file; returns the number of messages received.
size_t zmq_receive_and_store(const std::string& path,
                           const std::string& zmq_endpoint,
                           TFheGateBootstrappingParameterSet* params,
                           size_t max_messages = 0,
                           bool expect_eof_frame = true);

// Sends a start-of-file marker to the given ZeroMQ endpoint to signal the beginning of a transmission.
void send_sof_marker(const std::string& zmq_endpoint);

#endif // FILE_STORE_H