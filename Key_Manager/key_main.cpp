// key_main.cpp

#include <iostream>
#include <random>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <filesystem>

#include "key_storage.h"
#include <include/tfhe.h>
#include <include/tfhe_io.h>
#include "../hybrid-HE-framework/ciphers/kreyvium/tfhe/kreyvium_tfhe.h"
#include "../hybrid-HE-framework/ciphers/kreyvium/plain/kreyvium_plain.h"
#include "../hybrid-HE-framework/ciphers/common/TFHE_Cipher.h"

using namespace KREYVIUM;

class KeyManagerClass {
public:
    KeyManagerClass() {}
    
    ~KeyManagerClass() {}
    
    // Generates a random Kreyvium key and TFHE key set, then saves all keys and parameters to the specified files.
    void createKeys(const std::string& path_key_kreyvium, const std::string& path_params_tfhe, const std::string& path_sk_tfhe) {
        try {
            std::vector<uint8_t> key_kreyvium(16);
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            
            for (auto& byte : key_kreyvium) {
                byte = dis(gen);
            }
            
            TFheGateBootstrappingParameterSet* params_tfhe = new_default_gate_bootstrapping_parameters(128);
            TFheGateBootstrappingSecretKeySet* sk_tfhe = new_random_gate_bootstrapping_secret_keyset(params_tfhe);
            
            key_storage::save_key_kreyvium(key_kreyvium, path_key_kreyvium);
            key_storage::save_params_tfhe(params_tfhe, path_params_tfhe);
            key_storage::save_sk_tfhe(sk_tfhe, path_sk_tfhe);
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion createKeys: " << e.what() << std::endl;
            throw;
        }
    }
};

// Initializes the key manager, creates the key storage directory, and triggers key generation.
int main() {
    KeyManagerClass key_manager;
    
    std::filesystem::create_directories("storage_keys/");

    const std::string path_key_kreyvium = "storage_keys/key_kreyvium.bin";
    const std::string path_params_tfhe = "storage_keys/params_tfhe.bin";
    const std::string path_sk_tfhe = "storage_keys/sk_tfhe.bin";
    
    try {
        key_manager.createKeys(path_key_kreyvium, path_params_tfhe, path_sk_tfhe);
        std::cout << "Key generation completed" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error during key generation: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}