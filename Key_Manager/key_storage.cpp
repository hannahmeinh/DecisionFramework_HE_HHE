// key_storage.cpp

#include "key_storage.h"
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace key_storage {

    // Serializes and saves a Kreyvium key byte vector to the specified file.
    void save_key_kreyvium(const std::vector<uint8_t>& key, const std::string& filepath) {
        std::ofstream file(filepath, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Can't open file: " + filepath);
        }
        
        size_t key_size = key.size();
        file.write(reinterpret_cast<const char*>(&key_size), sizeof(key_size));
        
        file.write(reinterpret_cast<const char*>(key.data()), key.size());
        
        file.close();
        if (file.fail()) {
            throw std::runtime_error("Error writing file: " + filepath);
        }
    }

    // Serializes and saves a TFHE secret key set to the specified file.
    void save_sk_tfhe(const TFheGateBootstrappingSecretKeySet* sk, const std::string& filepath) {
        FILE* file = fopen(filepath.c_str(), "wb");
        if (!file) {
            throw std::runtime_error("Can't open file: " + filepath);
        }
        
        export_tfheGateBootstrappingSecretKeySet_toFile(file, sk);
        fclose(file);
    }

    // Serializes and saves a TFHE parameter set to the specified file.
    void save_params_tfhe(const TFheGateBootstrappingParameterSet* params, const std::string& filepath) {
        if (!params) {
            throw std::runtime_error("TFHE Parameter is nullptr");
        }

        FILE* file = fopen(filepath.c_str(), "wb");
        if (!file) {
            throw std::runtime_error("Can't open file: " + filepath);
        }
        
        try {
            export_tfheGateBootstrappingParameterSet_toFile(file, params);
            fclose(file);
            std::cout << "Saved TFHE parameter" << std::endl;
        } catch (...) {
            fclose(file);
            throw;
        }
    }

    // Loads and returns a Kreyvium key byte vector from the specified file.
    std::vector<uint8_t> load_key_kreyvium(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Can't open file: " + filepath);
        }
        
        size_t key_size;
        file.read(reinterpret_cast<char*>(&key_size), sizeof(key_size));
        if (file.fail()) {
            throw std::runtime_error("Error reading key size");
        }
        
        std::vector<uint8_t> key(key_size);
        file.read(reinterpret_cast<char*>(key.data()), key_size);
        if (file.fail()) {
            throw std::runtime_error("Error reading key");
        }
        
        file.close();
        return key;
    }

    // Loads and returns a TFHE secret key set from the specified file.
    TFheGateBootstrappingSecretKeySet* load_sk_tfhe(const std::string& filepath) {
        FILE* file = fopen(filepath.c_str(), "rb");
        if (!file) {
            throw std::runtime_error("Can't open file: " + filepath);
        }
        
        TFheGateBootstrappingSecretKeySet* sk = new_tfheGateBootstrappingSecretKeySet_fromFile(file);
        fclose(file);
        
        if (!sk) {
            throw std::runtime_error("Error loading TFHE Secret Key");
        }
        
        return sk;
    }

    // Loads and returns a TFHE parameter set from the specified file.
    TFheGateBootstrappingParameterSet* load_params_tfhe(const std::string& filepath) {
        FILE* file = fopen(filepath.c_str(), "rb");
        if (!file) {
            throw std::runtime_error("Can't open file: " + filepath);
        }
        
        TFheGateBootstrappingParameterSet* params = new_tfheGateBootstrappingParameterSet_fromFile(file);
        fclose(file);
        
        if (!params) {
            throw std::runtime_error("Error loading TFHE parameters");
        }
        
        return params;
    }
}