// mainClient.cpp

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
#include <unistd.h>

#include "../Data_Manager/data_manager.h"
#include "../Key_Manager/key_storage.h"
#include "../Parameters/parameters.h"
#include "../Performance_Measurement/timewriter.h"

#include "../hybrid-HE-framework/ciphers/kreyvium/tfhe/kreyvium_tfhe.h"
#include "../hybrid-HE-framework/ciphers/kreyvium/plain/kreyvium_plain.h"
#include "../hybrid-HE-framework/ciphers/common/TFHE_Cipher.h"
#include "../hybrid-HE-framework/ciphers/he_only_z2/tfhe/he_only_z2_tfhe.h"

using namespace KREYVIUM;
using namespace HE_ONLY;

class ClientClass {
private:
    // parameters to be set
    size_t batch_index = 0;

    // variables to hold raw and encrypted data
    // each integer_value is a vector of bytes (vector size = integer_size/8)
    std::vector<std::vector<uint8_t>> data_raw;
    std::vector<std::vector<uint8_t>> data_encrypted_kreyvium;
    std::vector<TFHECiphertextVec> data_encrypted_tfhe;

    // variables to hold encryption keys
    TFheGateBootstrappingParameterSet* tfhe_params = nullptr;
    TFheGateBootstrappingSecretKeySet* key_tfhe_sk = nullptr;
    std::vector<uint8_t> key_kreyvium;
    // kreyvium instance for encryption
    std::unique_ptr<Kreyvium> kreyvium_encryptor;
    // HeOnlyTFHE instance for encryption
    std::unique_ptr<HeOnlyTFHE> heOnlyTFHE_encryptor;

    // get date and time as string for filenames
    // move initialization into constructor (avoid std::format dependency)
    std::string datetimestamp;
    std::string filename_prefix;
    // filepaths to store data
    std::string filename_kreyvium;
    std::string filename_tfhe;

    // ZeroMQ-Endpoint (Address of server and ttp)
    std::string zmq_endpoint_sender_HHE = "tcp://*:5556";
    std::string zmq_endpoint_sender_HE = "tcp://*:5557";

    // performance measurement
    TimeWriter* time_writer;

public:

    // Initializes the client by setting up timestamps, loading keys, creating encryptor instances, and establishing ZMQ connections based on the configured encryption variant.
    ClientClass() {
        try {
            auto now = std::chrono::system_clock::now();
            std::time_t t = std::chrono::system_clock::to_time_t(now);
            char buf[32];
            std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", std::localtime(&t));
            datetimestamp = std::string(buf);
            filename_prefix = datetimestamp + "_" + ParameterClass::get_encryption_variant() + "_BatchNr:" + std::to_string(ParameterClass::get_batch_number()) + "_BatchSize:" + std::to_string(ParameterClass::get_batch_size()) + "_IntSize:" + std::to_string(ParameterClass::get_integer_size()) + "_";
            std::string variant = ParameterClass::get_encryption_variant();
            if (variant == "HHE") {
                time_writer = TimeWriter::initialize_timewriter("client_HHE");
                filename_kreyvium = "../data_kreyvium/" + filename_prefix + "data_kreyvium.bin";
                time_writer->log_timewriter("Client Initialisation Keys_Params Start");
                key_kreyvium = key_storage::load_key_kreyvium("storage_keys/key_kreyvium.bin");
                kreyvium_encryptor = std::make_unique<Kreyvium>(key_kreyvium);
                time_writer->log_timewriter("Client Initialisation Keys_Params End");
                std::cout << "Kreyvium-Instance created" << std::endl;
            } else if (variant == "HE") {
                time_writer = TimeWriter::initialize_timewriter("client_HE");
                filename_tfhe = "../data_tfhe/" + filename_prefix + "data_tfhe.bin";
                time_writer->log_timewriter("Client Initialisation Keys_Params Start");
                tfhe_params = key_storage::load_params_tfhe("storage_keys/params_tfhe.bin");
                key_tfhe_sk = key_storage::load_sk_tfhe("storage_keys/sk_tfhe.bin");
                heOnlyTFHE_encryptor = std::make_unique<HeOnlyTFHE>();
                heOnlyTFHE_encryptor->set_tfhe_keys(key_tfhe_sk);
                time_writer->log_timewriter("Client Initialisation Keys_Params End");
                std::cout << "HeOnlyTFHE-Instance created" << std::endl;
            }
            time_writer->log_timewriter("Client Initialisation ZeroMQ Start");
            initialize_zmq_connection();
            time_writer->log_timewriter("Client Initialisation ZeroMQ End");
        } catch (const std::exception& e) {
            std::cerr << "Error in ServerClass ctor: " << e.what() << std::endl;
        }
    }

    // Sets the current batch index used to address the correct slot in data vectors.
    void set_batch_index(size_t index) {
        batch_index = index;
    }

    // Returns the current batch index.
    size_t get_batch_index() const {
        return batch_index;
    }

    // Returns a reference to the raw data vector.
    std::vector<std::vector<uint8_t>>& get_data_raw() {
        return data_raw;
    }

    // Returns a reference to the Kreyvium-encrypted data vector.
    std::vector<std::vector<uint8_t>>& get_data_encrypted_kreyvium() {
        return data_encrypted_kreyvium;
    }

    // Returns a reference to the TFHE-encrypted data vector.
    std::vector<TFHECiphertextVec>& get_data_encrypted_tfhe() {
        return data_encrypted_tfhe;
    }

    // Returns the ZMQ endpoint address used for HHE data transmission.
    std::string get_zmq_endpoint_sender_HHE() const {
        return zmq_endpoint_sender_HHE;
    }

    // Returns the ZMQ endpoint address used for HE data transmission.
    std::string get_zmq_endpoint_sender_HE() const {
        return zmq_endpoint_sender_HE;
    }

    // Returns a pointer to the TimeWriter instance used for performance logging.
    TimeWriter* get_time_writer() const {
        return time_writer;
    }

    // Clears and reinitializes the raw and encrypted data vectors to the configured batch size.
    void clear_data() {
        try {
            data_raw.clear();
            data_encrypted_kreyvium.clear();
            data_encrypted_tfhe.clear();
            data_raw.resize(ParameterClass::get_batch_size());
            data_encrypted_kreyvium.resize(ParameterClass::get_batch_size());
            data_encrypted_tfhe.resize(ParameterClass::get_batch_size());
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion clear_data: " << e.what() << std::endl;
        }
    }

    // Prints the currently configured parameters such as data handling mode, encryption variant, batch settings, and integer size.
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

    // Converts a byte vector to a human-readable space-separated string of integer values.
    std::string print_vector(const std::vector<uint8_t>& vec) {
        std::stringstream ss;
        for (uint8_t byte : vec) {
            ss << (int)byte << " ";
        }
        return ss.str();
    }

    // Generates random raw data of the configured integer size and stores it at the current batch index.
    void create_raw_data() {
        try {
            size_t integer_value_vector_size = ParameterClass::get_integer_size() / 8;
            for (size_t j = 0; j < integer_value_vector_size; j++) {
                uint8_t integer_value = static_cast<uint8_t>(rand() % 256);
                data_raw[batch_index].push_back(integer_value);
            }
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion create_raw_data: " << e.what() << std::endl;
        }
    }

    // Sends a start-of-file marker via ZMQ to the given endpoint to signal the beginning of a transmission.
    void initialize_zmq_connection() {
        try {
            std::string variant = ParameterClass::get_encryption_variant();
            if (variant == "HHE") {
                send_sof_marker(zmq_endpoint_sender_HHE);
            } else if (variant == "HE") {
                send_sof_marker(zmq_endpoint_sender_HE);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        } catch (const std::exception& e) {
            std::cerr << "Error in initialize_zmq_connection: " << e.what() << std::endl;
        }
    }

    // Encrypts the raw data at the current batch index using Kreyvium and stores the ciphertext.
    void encrypt_data_kreyvium() {
        try {
            time_writer->log_timewriter("Client Integer Encryption Start : " + print_vector(data_raw[batch_index]));
            std::vector<uint8_t> ciphertext = kreyvium_encryptor->encrypt(data_raw[batch_index], data_raw[batch_index].size() * 8);
            time_writer->log_timewriter("Client Integer Encryption End : " + print_vector(data_raw[batch_index]));
            data_encrypted_kreyvium[batch_index] = ciphertext;
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion encrypt_data_kreyvium: " << e.what() << std::endl;
        }
    }

    // Encrypts the raw data at the current batch index using TFHE and stores the ciphertext.
    void encrypt_data_tfhe() {
        try {
            time_writer->log_timewriter("Client Integer Encryption Start : " + print_vector(data_raw[batch_index]));
            TFHECiphertextVec ciphertext = heOnlyTFHE_encryptor->HE_encrypt(data_raw[batch_index], data_raw[batch_index].size() * 8);
            time_writer->log_timewriter("Client Integer Encryption End : " + print_vector(data_raw[batch_index]));
            data_encrypted_tfhe[batch_index] = ciphertext;
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion encrypt_data_tfhe: " << e.what() << std::endl;
        }
    }

    // Dispatches encryption to the appropriate method based on the configured encryption variant.
    void encrypt_data() {
        try {
            std::string variant = ParameterClass::get_encryption_variant();
            if (variant == "HHE") {
                encrypt_data_kreyvium();
            } else if (variant == "HE") {
                encrypt_data_tfhe();
            }
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion encrypt_data: " << e.what() << std::endl;
        }
    }

    // Transmits all Kreyvium-encrypted data either by appending to a file or sending via ZMQ, depending on the data handling mode.
    void transmit_data_kreyvium() {
        try {
            std::string variant = ParameterClass::get_data_handling();
            if (variant == "SINGLE_COMPONENT") {
                std::ofstream file_kreyvium(filename_kreyvium, std::ios::binary | std::ios::app);
                file_kreyvium.close();
                for (size_t i = 0; i < data_encrypted_kreyvium.size(); i++) {
                    append_vector_to_file(filename_kreyvium, data_encrypted_kreyvium[i]);
                }
            } else if (variant == "ALL_AT_ONCE") {
                for (size_t i = 0; i < data_encrypted_kreyvium.size(); i++) {
                    send_vector_via_zmq(zmq_endpoint_sender_HHE, data_encrypted_kreyvium[i]);
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion transmit_data_kreyvium: " << e.what() << std::endl;
        }
    }

    // Transmits all TFHE-encrypted data either by appending to a file or sending via ZMQ, depending on the data handling mode.
    void transmit_data_tfhe() {
        try {
            std::string variant = ParameterClass::get_data_handling();
            if (variant == "SINGLE_COMPONENT") {
                std::ofstream file_tfhe(filename_tfhe, std::ios::binary | std::ios::app);
                file_tfhe.close();
                for (size_t i = 0; i < data_encrypted_tfhe.size(); i++) {
                    append_vector_to_file(filename_tfhe, data_encrypted_tfhe[i], tfhe_params);
                }
            } else if (variant == "ALL_AT_ONCE") {
                for (size_t i = 0; i < data_encrypted_tfhe.size(); i++) {
                    send_vector_via_zmq(zmq_endpoint_sender_HE, data_encrypted_tfhe[i], tfhe_params);
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion transmit_data_tfhe: " << e.what() << std::endl;
        }
    }

    // Dispatches data transmission to the appropriate method based on the configured encryption variant.
    void transmit_data() {
        try {
            std::string variant = ParameterClass::get_encryption_variant();
            if (variant == "HHE") {
                transmit_data_kreyvium();
            } else if (variant == "HE") {
                transmit_data_tfhe();
            }
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion transmit_data: " << e.what() << std::endl;
        }
    }

    // Reads the most recently created encrypted data file and transmits its contents via ZMQ, followed by an EOF marker.
    void transmit_latest_data() {
        try {
            std::string variant = ParameterClass::get_encryption_variant();
            if (variant == "HHE") {
                std::string latest_file = get_latest_file_in_directory("../data_kreyvium/");
                send_all_vectors_via_zmq(latest_file, zmq_endpoint_sender_HHE);
                std::vector<uint8_t> eof_marker = { 0xFF };
                send_vector_via_zmq(zmq_endpoint_sender_HHE, eof_marker);
            } else if (variant == "HE") {
                std::string latest_file = get_latest_file_in_directory("../data_tfhe/");
                send_all_vectors_via_zmq(latest_file, zmq_endpoint_sender_HE, tfhe_params);
                std::vector<uint8_t> eof_marker = { 0xFF };
                send_vector_via_zmq(zmq_endpoint_sender_HE, eof_marker);
            }
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion transmit_latest_data: " << e.what() << std::endl;
        }
    }

    // Releases the memory allocated for the TimeWriter instance.
    void delete_time_writer() {
        try {
            delete time_writer;
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion delete_time_writer: " << e.what() << std::endl;
        }
    }
};

// Entry point: initializes the client, processes all batches by generating, encrypting, and transmitting data, then signals end of transmission.
int main() {
    try {        
        ClientClass clientClass = ClientClass();
        if (ParameterClass::get_data_handling() == "TRANSMIT_TFHE" || ParameterClass::get_data_handling() == "TRANSMIT_KREYVIUM") {
            std::cout << "Data handling: TRANSMIT DATA" << std::endl;
            clientClass.transmit_latest_data();
        } else {
            size_t batch_counter = 0;

            clientClass.printParameter();
            clientClass.clear_data();

            clientClass.get_time_writer()->log_timewriter("Client initialized");

            while (batch_counter < ParameterClass::get_batch_number()) {
                batch_counter++;
                clientClass.get_time_writer()->log_timewriter("Client Batch Start");
                for (size_t i = 0; i < ParameterClass::get_batch_size(); i++) {
                    clientClass.set_batch_index(i);
                    clientClass.get_time_writer()->log_timewriter("Client Integer Start");
                    clientClass.create_raw_data();
                    clientClass.encrypt_data();
                    clientClass.get_time_writer()->log_timewriter("Client Integer End");
                }
                clientClass.get_time_writer()->log_timewriter("Client Batch End");
                clientClass.get_time_writer()->log_timewriter("Client Batch Transmission Start");
                clientClass.transmit_data();
                clientClass.clear_data();
                clientClass.get_time_writer()->log_timewriter("Client Batch Transmission End");
            }
            if (ParameterClass::get_data_handling() != "SINGLE_COMPONENT") {
                std::string variant = ParameterClass::get_encryption_variant();
                if (variant == "HHE") {
                    std::vector<uint8_t> eof_marker = { 0xFF };
                    send_vector_via_zmq(clientClass.get_zmq_endpoint_sender_HHE(), eof_marker);
                } else if (variant == "HE") {
                    std::vector<uint8_t> eof_marker = { 0xFF };
                    send_vector_via_zmq(clientClass.get_zmq_endpoint_sender_HE(), eof_marker);
                }
            }
        }
        clientClass.delete_time_writer();
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error in Funktion main: " << e.what() << std::endl;
        return -1;
    }
}
