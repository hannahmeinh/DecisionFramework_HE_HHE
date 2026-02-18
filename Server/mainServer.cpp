// mainServer.cpp

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

class ServerClass {
private:
    size_t batch_index = 0;

    std::vector<std::vector<uint8_t>> data_raw;
    std::vector<TFHECiphertextVec> data_tfhe;

    TFheGateBootstrappingParameterSet* tfhe_params = nullptr;
    TFheGateBootstrappingSecretKeySet* key_tfhe_sk = nullptr;
    const TFheGateBootstrappingCloudKeySet* key_tfhe_pk = nullptr;
    std::vector<uint8_t> key_kreyvium;
    std::unique_ptr<KREYVIUM_TFHE> kreyvium_tfhe_transcipherer;

    std::string datetimestamp;
    std::string filename_prefix;
    std::string filename_kreyvium;
    std::string filename_tfhe;

    //std::string zmq_endpoint_receiver = "tcp://192.168.178.48:5556";
    std::string zmq_endpoint_receiver = "tcp://192.168.178.52:5556";
    std::string zmq_endpoint_sender = "tcp://localhost:5557";

    std::unique_ptr<FileVectorReader> file_vector_reader;

    TimeWriter* time_writer;

public:
    // Initializes all server resources including keys, the Kreyvium transcipherer, file paths, and the performance time writer.
    ServerClass() {
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", std::localtime(&t));
        datetimestamp = std::string(buf);
        filename_prefix = datetimestamp + "_" + ParameterClass::get_encryption_variant() + "_BatchNr:" + std::to_string(ParameterClass::get_batch_number()) + "_BatchSize:" + std::to_string(ParameterClass::get_batch_size()) + "_IntSize:" + std::to_string(ParameterClass::get_integer_size()) + "_";
        filename_tfhe = "../data_tfhe/" + filename_prefix + "data_tfhe.bin";
        filename_kreyvium = "../data_kreyvium/" + filename_prefix + "data_kreyvium.bin";
        
        time_writer = TimeWriter::initialize_timewriter("server_HHE");

        time_writer->log_timewriter("Server Initialisation Keys_Params Start");
        tfhe_params = key_storage::load_params_tfhe("storage_keys/params_tfhe.bin");
        key_tfhe_sk = key_storage::load_sk_tfhe("storage_keys/sk_tfhe.bin");
        key_tfhe_pk = &key_tfhe_sk->cloud;
        key_kreyvium = key_storage::load_key_kreyvium("storage_keys/key_kreyvium.bin");
        kreyvium_tfhe_transcipherer = std::make_unique<KREYVIUM_TFHE>(key_kreyvium);
        kreyvium_tfhe_transcipherer->set_tfhe_keys(tfhe_params, key_tfhe_sk, key_tfhe_pk);
        kreyvium_tfhe_transcipherer->encrypt_key();
        time_writer->log_timewriter("Server Initialisation Keys_Params End");
    }

    // Sets the current batch index used to address the correct slot in the data vectors.
    void set_batch_index(size_t index) {
        batch_index = index;
    }

    // Sets the file path for reading Kreyvium-encrypted input data.
    void set_filename_kreyvium(const std::string& filename) {
        filename_kreyvium = filename;
    }

    // Transfers ownership of a FileVectorReader instance into the server object.
    void set_file_vector_reader(std::unique_ptr<FileVectorReader>&& reader) {
        file_vector_reader = std::move(reader);
    }

    // Returns the current batch index.
    size_t get_batch_index() const {
        return batch_index;
    }

    // Returns a reference to the vector holding all raw plaintext data.
    std::vector<std::vector<uint8_t>>& get_data_raw() {
        return data_raw;
    }

    // Returns a reference to the vector holding all TFHE-encrypted ciphertext data.
    std::vector<TFHECiphertextVec>& get_data_tfhe() {
        return data_tfhe;
    }

    // Returns the ZeroMQ endpoint address used to send data to the TTP.
    std::string get_zmq_endpoint_sender() const {
        return zmq_endpoint_sender;
    }

    // Returns a pointer to the active TimeWriter instance used for performance logging.
    TimeWriter* get_time_writer() const {
        return time_writer;
    }

    // Returns the file path of the Kreyvium-encrypted data file.
    std::string get_filename_kreyvium() const {
        return filename_kreyvium;
    }

    // Returns a pointer to the TFHE bootstrapping parameter set.
    TFheGateBootstrappingParameterSet* get_tfhe_params() const {
        return tfhe_params;
    }

    // Clears and resizes the raw and TFHE data vectors to match the configured batch size.
    void clear_data() {
        try {
            data_raw.clear();
            data_tfhe.clear();
            data_raw.resize(ParameterClass::get_batch_size());
            data_tfhe.resize(ParameterClass::get_batch_size());
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

    // Receives Kreyvium-encrypted data from the client via ZeroMQ and writes it to a binary file.
    void receive_client_data() {
        try {
            size_t received = zmq_receive_and_store(filename_kreyvium, zmq_endpoint_receiver, ParameterClass::get_batch_size()*ParameterClass::get_batch_number(), true);
            std::cout << "Received " << received << " messages and stored to " << filename_kreyvium << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion receive_client_data: " << e.what() << std::endl;
        }
    }

    // Reads the next Kreyvium ciphertext from file, transciphers it to a TFHE ciphertext, and stores the result in the data vector.
    void transcipher_data() {
        try {
            std::vector<uint8_t> ciphertext_kreyvium_vector;
            file_vector_reader->next(ciphertext_kreyvium_vector);

            time_writer->log_timewriter("Server Integer Transciphering Start");
            TFHECiphertextVec ciphertext_tfhe = kreyvium_tfhe_transcipherer->HE_decrypt(ciphertext_kreyvium_vector, ciphertext_kreyvium_vector.size() * 8);
            time_writer->log_timewriter("Server Integer Transciphering End");
            data_tfhe[batch_index] = ciphertext_tfhe;
            std::cout << batch_index << ". 8-bit block of the integer_value transciphered." << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion transcipher_data: " << e.what() << std::endl;
        }
    }

    // Transmits the current batch of TFHE-encrypted data either to a file or to the TTP via ZeroMQ, depending on the configured data handling mode.
    void transmit_data() {
        try {
            std::string variant = ParameterClass::get_data_handling();
            if (variant == "SINGLE_COMPONENT") {
                std::ofstream file_tfhe(filename_tfhe, std::ios::binary | std::ios::app);
                file_tfhe.close();
                for (size_t i = 0; i < data_tfhe.size(); i++) {
                    append_vector_to_file(filename_tfhe, data_tfhe[i], tfhe_params);
                }
                std::cout << "Stored TFHE encrypted data in file " << filename_tfhe << std::endl;
            } else if (variant == "ALL_AT_ONCE") {
                for (size_t i = 0; i < data_tfhe.size(); i++) {
                    send_vector_via_zmq(zmq_endpoint_sender, data_tfhe[i], tfhe_params);
                }
                std::cout << "Transmitted TFHE encrypted data" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion transmit_data: " << e.what() << std::endl;
        }
    }

    // Reads all TFHE-encrypted vectors from the most recent data file and sends them to the TTP via ZeroMQ, followed by an EOF marker.
    void transmit_latest_data() {
        try {
            std::string latest_file = get_latest_file_in_directory("../data_tfhe/");
            send_all_vectors_via_zmq(latest_file, zmq_endpoint_sender, tfhe_params);
            std::vector<uint8_t> eof_marker = { 0xFF };
            send_vector_via_zmq(zmq_endpoint_sender, eof_marker);
            std::cout << "Transmitted TFHE encrypted data from file " << latest_file << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion transmit_latest_data: " << e.what() << std::endl;
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

// Entry point that initializes the server, receives or transmits data according to the configured mode, and runs the batch transciphering loop.
int main() {
    try {
        ServerClass serverClass = ServerClass();
        if (ParameterClass::get_data_handling() == "TRANSMIT_KREYVIUM") {
            std::cout << "Data handling: TRANSMIT_KREYVIUM" << std::endl;
            serverClass.receive_client_data();
        } else if (ParameterClass::get_data_handling() == "TRANSMIT_TFHE") {
            std::cout << "Data handling: TRANSMIT_TFHE" << std::endl;
            serverClass.transmit_latest_data();
        } else {
            size_t batch_counter = 0;

            serverClass.printParameter();
            serverClass.clear_data();

            if (ParameterClass::get_data_handling() == "SINGLE_COMPONENT") {
                serverClass.set_filename_kreyvium(get_latest_file_in_directory("../data_kreyvium/"));
            } else {
                serverClass.receive_client_data();
            }
            serverClass.set_file_vector_reader(std::make_unique<FileVectorReader>(serverClass.get_filename_kreyvium()));

            serverClass.get_time_writer()->log_timewriter("Server initialized");

            while (batch_counter < ParameterClass::get_batch_number()) {
                batch_counter++;
                serverClass.get_time_writer()->log_timewriter("Server Batch Start");
                for (size_t i = 0; i < ParameterClass::get_batch_size(); i++) {
                    serverClass.set_batch_index(i);
                    serverClass.get_time_writer()->log_timewriter("Server Integer Start");
                    serverClass.transcipher_data();
                    serverClass.get_time_writer()->log_timewriter("Server Integer End");
                }
                serverClass.get_time_writer()->log_timewriter("Server Batch End");
                serverClass.get_time_writer()->log_timewriter("Server Batch Transmission Start");
                if (batch_counter == 1) {
                    serverClass.get_time_writer()->log_timewriter("Server Initialisation ZeroMQ Start");
                    serverClass.transmit_data();
                    serverClass.get_time_writer()->log_timewriter("Server Initialisation ZeroMQ End");
                } else {
                    serverClass.transmit_data();
                }
                serverClass.clear_data();
                serverClass.get_time_writer()->log_timewriter("Server Batch Transmission End");
                std::cout << batch_counter << ". Batch of " << ParameterClass::get_batch_size() << " " << ParameterClass::get_integer_size() << "-Bit integer values processed." << std::endl;
            }
            if (ParameterClass::get_data_handling() != "SINGLE_COMPONENT") {
                std::vector<uint8_t> eof_marker = { 0xFF };
                send_vector_via_zmq(serverClass.get_zmq_endpoint_sender(), eof_marker);
            }
        }
        serverClass.delete_time_writer();
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error in Funktion main: " << e.what() << std::endl;
        return -1;
    }
}