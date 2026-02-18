// parameters.h

#ifndef PARAMETERS_H
#define PARAMETERS_H

#include <string>

enum class EncryptionVariant {
    HHE,
    HE
};

enum class IntegerSize {
    BITS_8 = 8,
    BITS_16 = 16,
    BITS_32 = 32,
    BITS_64 = 64,
    BITS_128 = 128
};

enum class DataHandling {
    ALL_AT_ONCE,
    SINGLE_COMPONENT,
    TRANSMIT_TFHE,
    TRANSMIT_KREYVIUM
};

class ParameterClass {
private:
    static const EncryptionVariant encryption_variant;
    static const IntegerSize integer_size;
    static const size_t batch_size;
    static const size_t batch_number;
    static const DataHandling data_handling;

    ParameterClass() = delete;
    ParameterClass(const ParameterClass&) = delete;
    ParameterClass& operator=(const ParameterClass&) = delete;

public:
    // Returns the configured encryption variant as a string.
    static std::string get_encryption_variant();

    // Returns the configured integer size in bits.
    static size_t get_integer_size();

    // Returns the configured number of elements per batch.
    static size_t get_batch_size();

    // Returns the configured total number of batches.
    static size_t get_batch_number();

    // Returns the configured data handling mode as a string.
    static std::string get_data_handling();
};

#endif // PARAMETERS_H