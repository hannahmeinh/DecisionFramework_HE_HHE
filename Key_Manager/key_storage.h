// key_storage.h

#ifndef KEY_STORAGE_H
#define KEY_STORAGE_H

#include "../hybrid-HE-framework/ciphers/kreyvium/tfhe/kreyvium_tfhe.h"
#include "../hybrid-HE-framework/ciphers/kreyvium/plain/kreyvium_plain.h"
#include "../hybrid-HE-framework/ciphers/common/TFHE_Cipher.h"

#include <vector>
#include <string>
#include <include/tfhe.h>
#include <include/tfhe_io.h>

using namespace KREYVIUM;

namespace key_storage {

    // Serializes and saves a Kreyvium key byte vector to the specified file.
    void save_key_kreyvium(const std::vector<uint8_t>& key, const std::string& filepath);

    // Serializes and saves a TFHE secret key set to the specified file.
    void save_sk_tfhe(const TFheGateBootstrappingSecretKeySet* sk, const std::string& filepath);

    // Serializes and saves a TFHE parameter set to the specified file.
    void save_params_tfhe(const TFheGateBootstrappingParameterSet* params, const std::string& filepath);

    // Loads and returns a Kreyvium key byte vector from the specified file.
    std::vector<uint8_t> load_key_kreyvium(const std::string& filepath);

    // Loads and returns a TFHE secret key set from the specified file.
    TFheGateBootstrappingSecretKeySet* load_sk_tfhe(const std::string& filepath);

    // Loads and returns a TFHE parameter set from the specified file.
    TFheGateBootstrappingParameterSet* load_params_tfhe(const std::string& filepath);
}

#endif // KEY_STORAGE_H