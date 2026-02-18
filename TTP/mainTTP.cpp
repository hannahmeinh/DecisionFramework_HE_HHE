// mainTTP.cpp

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <include/tfhe.h>
#include <include/tfhe_io.h>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <zmq.hpp>
#include <regex>
#include <ctime>

#include "../Data_Manager/data_manager.h"
#include "../Key_Manager/key_storage.h"
#include "../Parameters/parameters.h"
#include "../Performance_Measurement/timewriter.h"

#include "../hybrid-HE-framework/ciphers/kreyvium/tfhe/kreyvium_tfhe.h"
#include "../hybrid-HE-framework/ciphers/he_only_z2/tfhe/he_only_z2_tfhe.h"

using namespace HE_ONLY;

class TTPClass {
private:
    size_t batch_index = 0;

    std::vector<std::vector<uint8_t>> data_decrypted;
    std::vector<std::vector<TFHECiphertextVec>> data_encrypted_tfhe;

    TFheGateBootstrappingParameterSet* tfhe_params = nullptr;
    TFheGateBootstrappingSecretKeySet* key_tfhe_sk = nullptr;
    std::vector<uint8_t> key_kreyvium;
    std::unique_ptr<KREYVIUM_TFHE> kreyvium_tfhe_decryptor;
    std::unique_ptr<HeOnlyTFHE> heOnlyTFHE_decryptor;

    std::string datetimestamp;
    std::string filename_prefix;
    std::string filename_tfhe;
    std::string filename_decrypted;

    std::string zmq_endpoint_client = "tcp://192.168.178.48:5557";
    //std::string zmq_endpoint_client = "tcp://192.168.178.52:5557";
    // std::string zmq_endpoint_client = "tcp://localhost:5557";
    std::string zmq_endpoint_server = "tcp://localhost:5557";

    std::unique_ptr<FileTFHEVectorReader> file_vector_reader;

    TimeWriter* time_writer;

public:
    // Initializes all TTP resources including keys, decryptors, file paths, and the performance time writer based on the configured encryption variant.
    TTPClass() {
        try {
            auto now = std::chrono::system_clock::now();
            std::time_t t = std::chrono::system_clock::to_time_t(now);
            char buf[32];
            std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", std::localtime(&t));
            datetimestamp = std::string(buf);
            filename_prefix = datetimestamp + "_" + ParameterClass::get_encryption_variant() + "_BatchNr:" + std::to_string(ParameterClass::get_batch_number()) + "_BatchSize:" + std::to_string(ParameterClass::get_batch_size()) + "_IntSize:" + std::to_string(ParameterClass::get_integer_size()) + "_";
            filename_decrypted = "../data_decrypted/" + filename_prefix + "data_decrypted.bin";
            filename_tfhe = "../data_encrypted_tfhe/" + filename_prefix + "data_tfhe.bin";

            std::string variant = ParameterClass::get_encryption_variant();
            if (variant == "HHE") {
                time_writer = TimeWriter::initialize_timewriter("ttp_HHE");
                time_writer->log_timewriter("TTP Initialisation Keys_Params Start");
                tfhe_params = key_storage::load_params_tfhe("storage_keys/params_tfhe.bin");
                key_tfhe_sk = key_storage::load_sk_tfhe("storage_keys/sk_tfhe.bin");
                kreyvium_tfhe_decryptor = std::make_unique<KREYVIUM_TFHE>();
                kreyvium_tfhe_decryptor->set_tfhe_sk(key_tfhe_sk);
                time_writer->log_timewriter("TTP Initialisation Keys_Params End");
            } else if (variant == "HE") {
                time_writer = TimeWriter::initialize_timewriter("ttp_HE");
                time_writer->log_timewriter("TTP Initialisation Keys_Params Start");
                tfhe_params = key_storage::load_params_tfhe("storage_keys/params_tfhe.bin");
                key_tfhe_sk = key_storage::load_sk_tfhe("storage_keys/sk_tfhe.bin");
                heOnlyTFHE_decryptor = std::make_unique<HeOnlyTFHE>();
                heOnlyTFHE_decryptor->set_tfhe_keys(key_tfhe_sk);
                time_writer->log_timewriter("TTP Initialisation Keys_Params End");
            }
        } catch (const std::exception& e) {
            std::cerr << "Error in ttpClass ctor: " << e.what() << std::endl;
        }
    }

    // Sets the current batch index used to address the correct slot in the data vectors.
    void set_batch_index(size_t index) {
        batch_index = index;
    }

    // Sets the file path for reading TFHE-encrypted input data.
    void set_filename_tfhe(const std::string& filename) {
        filename_tfhe = filename;
    }

    // Transfers ownership of a FileTFHEVectorReader instance into the TTP object.
    void set_file_vector_reader(std::unique_ptr<FileTFHEVectorReader>&& reader) {
        file_vector_reader = std::move(reader);
    }

    // Returns the current batch index.
    size_t get_batch_index() const {
        return batch_index;
    }

    // Returns a reference to the vector holding all decrypted plaintext data.
    std::vector<std::vector<uint8_t>>& get_data_decrypted() {
        return data_decrypted;
    }

    // Returns a reference to the vector holding all TFHE-encrypted ciphertext data.
    std::vector<std::vector<TFHECiphertextVec>>& get_data_encrypted_tfhe() {
        return data_encrypted_tfhe;
    }

    // Returns a pointer to the active TimeWriter instance used for performance logging.
    TimeWriter* get_time_writer() const {
        return time_writer;
    }

    // Returns the file path of the TFHE-encrypted data file.
    std::string get_filename_tfhe() const {
        return filename_tfhe;
    }

    // Returns a pointer to the TFHE bootstrapping parameter set.
    TFheGateBootstrappingParameterSet* get_tfhe_params() const {
        return tfhe_params;
    }

    // Clears and resizes the decrypted and encrypted data vectors to match the configured batch size.
    void clear_data() {
        try {
            data_decrypted.clear();
            data_encrypted_tfhe.clear();
            data_decrypted.resize(ParameterClass::get_batch_size());
            data_encrypted_tfhe.resize(ParameterClass::get_batch_size());
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion clear_data: " << e.what() << std::endl;
        }
    }

    // Prints the currently configured runtime parameters to standard output.
    void printParameter() const {
        try {
            std::cout << "Data handling: " << ParameterClass::get_data_handling() << std::endl;
            std::cout << "Encryption Variant: " << ParameterClass::get_encryption_variant() << std::endl;
            std::cout << "Number of Batches: " << ParameterClass::get_batch_number() << std::endl;
            std::cout << "Batch Size: " << ParameterClass::get_batch_size() << std::endl;
            std::cout << "Integer Size: " << ParameterClass::get_integer_size() << "-bit" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion printParameter: " << e.what() << std::endl;
        }
    }

    // Converts a byte vector to a space-separated string of integer values.
    std::string print_vector(const std::vector<uint8_t>& vec) {
        std::stringstream ss;
        for (uint8_t byte : vec) {
            ss << (int)byte << " ";
        }
        return ss.str();
    }

    // Receives TFHE-encrypted data via ZeroMQ from either the client or server and writes it to a binary file.
    void receive_tfhe_data() {
        try {
            size_t received = 0;
            std::string variant = ParameterClass::get_encryption_variant();
            if (variant == "HHE") {
                received = zmq_receive_and_store(filename_tfhe, zmq_endpoint_server, tfhe_params, ParameterClass::get_batch_size()*ParameterClass::get_batch_number(), true);
            } else if (variant == "HE") {
                received = zmq_receive_and_store(filename_tfhe, zmq_endpoint_client, tfhe_params, ParameterClass::get_batch_size()*ParameterClass::get_batch_number(), true);
            }
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion receive_tfhe_data: " << e.what() << std::endl;
        }
    }

    // Reads the next TFHE ciphertext from file and decrypts it using the active decryptor, storing the result in the data vector.
    void decrypt_data() {
        try {
            TFHECiphertextVec ciphertext_tfhe_vector;
            file_vector_reader->next(ciphertext_tfhe_vector);
            std::vector<uint8_t> ciphertext_decrypted;

            std::string variant = ParameterClass::get_encryption_variant();
            if (variant == "HHE") {
                time_writer->log_timewriter("TTP Integer Decryption Start");
                ciphertext_decrypted = kreyvium_tfhe_decryptor->decrypt_result(ciphertext_tfhe_vector);
                time_writer->log_timewriter("TTP Integer Decryption End : " + print_vector(ciphertext_decrypted));
            } else if (variant == "HE") {
                time_writer->log_timewriter("TTP Integer Decryption Start");
                ciphertext_decrypted = heOnlyTFHE_decryptor->decrypt_result(ciphertext_tfhe_vector);
                time_writer->log_timewriter("TTP Integer Decryption End : " + print_vector(ciphertext_decrypted));
            }

            data_decrypted[batch_index] = ciphertext_decrypted;
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion decrypt_data: " << e.what() << std::endl;
        }
    }

    // Appends all decrypted data entries from the current batch to the binary output file.
    void store_data() {
        try {
            std::ofstream file_decrypted(filename_decrypted, std::ios::binary | std::ios::app);
            file_decrypted.close();
            for (size_t i = 0; i < data_decrypted.size(); i++) {
                append_vector_to_file(filename_decrypted, data_decrypted[i]);
            }
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion store_data: " << e.what() << std::endl;
        }
    }

    // Deallocates the TimeWriter instance and releases its associated resources.
    void delete_time_writer() {
        try {
            delete time_writer;
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion delete_time_writer: " << e.what() << std::endl;
        }
    }
};

// Entry point that initializes the TTP, receives encrypted data, runs the batch decryption loop, and stores the results.
int main() {
    try {
        TTPClass ttpClass = TTPClass();
        if (ParameterClass::get_data_handling() == "TRANSMIT_TFHE") {
            std::cout << "Data handling: TRANSMIT_TFHE" << std::endl;
            ttpClass.receive_tfhe_data();
        } else {
            size_t batch_counter = 0;

            ttpClass.clear_data();

            if (ParameterClass::get_data_handling() == "SINGLE_COMPONENT") {
                ttpClass.set_filename_tfhe(get_latest_file_in_directory("../data_encrypted_tfhe/"));
            } else {
                ttpClass.receive_tfhe_data();
            }
            if (ttpClass.get_filename_tfhe().empty()) {
                std::cerr << "No TFHE encrypted data file found in ../data_encrypted_tfhe/" << std::endl;
                return 0;
            }
            ttpClass.set_file_vector_reader(std::make_unique<FileTFHEVectorReader>(ttpClass.get_filename_tfhe(), ttpClass.get_tfhe_params()));

            ttpClass.get_time_writer()->log_timewriter("TTP initialized");

            while (batch_counter < ParameterClass::get_batch_number()) {
                batch_counter++;
                ttpClass.get_time_writer()->log_timewriter("TTP Batch Start");
                for (size_t i = 0; i < ParameterClass::get_batch_size(); i++) {
                    ttpClass.set_batch_index(i);
                    ttpClass.get_time_writer()->log_timewriter("TTP Integer Start");
                    ttpClass.decrypt_data();
                    ttpClass.get_time_writer()->log_timewriter("TTP Integer End");
                }
                ttpClass.get_time_writer()->log_timewriter("TTP Batch End");
                ttpClass.get_time_writer()->log_timewriter("TTP Batch Transmission Start");
                ttpClass.store_data();
                ttpClass.clear_data();
                ttpClass.get_time_writer()->log_timewriter("TTP Batch Transmission End");
            }
        }
        ttpClass.delete_time_writer();
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error in Funktion main: " << e.what() << std::endl;
        return -1;
    }
}