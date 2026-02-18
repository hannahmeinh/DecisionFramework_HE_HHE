// parameters.cpp

#include "parameters.h"

#include <iostream>
#include <stdexcept>
#include <cstdint>
#include <string>

// Returns the configured encryption variant as a string.
std::string ParameterClass::get_encryption_variant() {
    try {
        switch (encryption_variant) {
            case EncryptionVariant::HHE:
                return "HHE";
            case EncryptionVariant::HE:
                return "HE";
            default:
                throw std::invalid_argument("Invalid encryption variant");
        }
    } catch (const std::exception& e) {
        std::cerr << "Error in Funktion ParameterClass::get_encryption_variant: " << e.what() << std::endl;
        return "";
    }
}

// Returns the configured integer size in bits.
size_t ParameterClass::get_integer_size() {
    try {
        switch (integer_size) {
            case IntegerSize::BITS_8:
                return 8;
            case IntegerSize::BITS_16:
                return 16;
            case IntegerSize::BITS_32:
                return 32;
            case IntegerSize::BITS_64:
                return 64;
            case IntegerSize::BITS_128:
                return 128;
            default:
                throw std::invalid_argument("Invalid integer size");
        }
    } catch (const std::exception& e) {
        std::cerr << "Error in Funktion ParameterClass::get_integer_size: " << e.what() << std::endl;
        return 0;
    }
}

// Returns the configured number of elements per batch.
size_t ParameterClass::get_batch_size() {
    return batch_size;
}

// Returns the configured total number of batches.
size_t ParameterClass::get_batch_number() {
    return batch_number;
}

// Returns the configured data handling mode as a string.
std::string ParameterClass::get_data_handling() {
    try {
        switch (data_handling) {
            case DataHandling::ALL_AT_ONCE:
                return "ALL_AT_ONCE";
            case DataHandling::SINGLE_COMPONENT:
                return "SINGLE_COMPONENT";
            case DataHandling::TRANSMIT_TFHE:
                return "TRANSMIT_TFHE";
            case DataHandling::TRANSMIT_KREYVIUM:
                return "TRANSMIT_KREYVIUM";
            default:
                throw std::invalid_argument("Invalid data handling variant");
        }
    } catch (const std::exception& e) {
        std::cerr << "Error in Funktion ParameterClass::get_data_handling: " << e.what() << std::endl;
        return "";
    }
}

const EncryptionVariant ParameterClass::encryption_variant = EncryptionVariant::HHE;
const IntegerSize ParameterClass::integer_size = IntegerSize::BITS_8;
const size_t ParameterClass::batch_size = 4;
const size_t ParameterClass::batch_number = 25;
const DataHandling ParameterClass::data_handling = DataHandling::ALL_AT_ONCE;