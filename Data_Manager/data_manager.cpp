// data_manager.cpp

#include "data_manager.h"
#include <filesystem>
#include <fstream>
#include <zmq.hpp>
#include <cstdio>
#include <system_error>
#include <iostream>
#include <limits>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <map>
#include <stdexcept>
#include <mutex>
#include <vector>
#include <string>
#include <unordered_map>
#include <regex>

#include "include/tfhe.h"
#include "../hybrid-HE-framework/ciphers/common/TFHE_Cipher.h"

namespace {
    static std::mutex g_map_mutex;
    static std::map<std::string, std::shared_ptr<std::mutex>> g_path_mutexes;

    // Returns a per-path mutex, creating one if it does not yet exist.
    std::shared_ptr<std::mutex> get_mutex_for_path(const std::string& path) {
        std::lock_guard<std::mutex> lk(g_map_mutex);
        auto it = g_path_mutexes.find(path);
        if (it != g_path_mutexes.end()) return it->second;
        auto m = std::make_shared<std::mutex>();
        g_path_mutexes[path] = m;
        return m;
    }

    constexpr uint32_t MAX_REASONABLE_SIZE = 1u << 30; // 1 GiB sanity cap
}

// Writes a length-prefixed byte payload to an ofstream in network byte order.
static void write_length_prefixed_bytes_to_ofstream(std::ofstream& ofs, const uint8_t* data, size_t size) {
    uint32_t len = static_cast<uint32_t>(size);
    if (len != size) throw std::runtime_error("payload too large for uint32_t length prefix");
    uint32_t be = htonl(len);
    ofs.write(reinterpret_cast<const char*>(&be), sizeof(be));
    if (!ofs) throw std::runtime_error("write_length_prefixed_bytes: failed to write length");
    if (len) {
        ofs.write(reinterpret_cast<const char*>(data), len);
        if (!ofs) throw std::runtime_error("write_length_prefixed_bytes: failed to write payload");
    }
}

// Reads one length-prefixed byte payload from an ifstream; returns false at EOF.
static bool read_length_prefixed_bytes_from_ifstream(std::ifstream& ifs, std::vector<uint8_t>& out) {
    out.clear();
    uint32_t len_be;
    ifs.read(reinterpret_cast<char*>(&len_be), sizeof(len_be));
    if (!ifs) {
        if (ifs.eof()) return false;
        throw std::runtime_error("read_length_prefixed_bytes: failed to read length");
    }
    uint32_t len = ntohl(len_be);
    if (len > MAX_REASONABLE_SIZE) throw std::runtime_error("read_length_prefixed_bytes: suspicious length");
    out.resize(len);
    if (len) {
        ifs.read(reinterpret_cast<char*>(out.data()), len);
        if (!ifs) throw std::runtime_error("read_length_prefixed_bytes: failed to read payload");
    }
    return true;
}

// Writes a length-prefixed byte payload to a FILE pointer in network byte order.
static void write_length_prefixed_bytes_to_FILE(FILE* f, const uint8_t* data, size_t size) {
    uint32_t len = static_cast<uint32_t>(size);
    if (len != size) throw std::runtime_error("payload too large for uint32_t length prefix");
    uint32_t be = htonl(len);
    if (fwrite(&be, sizeof(be), 1, f) != 1) throw std::runtime_error("write_length_prefixed_bytes_to_FILE: write length failed");
    if (len) {
        if (fwrite(data, 1, len, f) != len) throw std::runtime_error("write_length_prefixed_bytes_to_FILE: write payload failed");
    }
}

// Reads one length-prefixed byte payload from a FILE pointer; returns false at EOF.
static bool read_length_prefixed_bytes_from_FILE(FILE* f, std::vector<uint8_t>& out) {
    out.clear();
    uint32_t len_be = 0;
    size_t r = fread(&len_be, 1, sizeof(len_be), f);
    if (r == 0) return false;
    if (r != sizeof(len_be)) throw std::runtime_error("corrupted file (incomplete length header)");
    uint32_t len = ntohl(len_be);
    if (len > MAX_REASONABLE_SIZE) throw std::runtime_error("suspicious length");
    out.resize(len);
    if (len) {
        if (fread(out.data(), 1, len, f) != len) throw std::runtime_error("corrupted file (payload truncated)");
    }
    return true;
}

// Appends a byte vector to a file in length-prefixed format with per-path thread-safe locking.
void append_vector_to_file(const std::string& path, const std::vector<uint8_t>& data) {
    try {
        auto m = get_mutex_for_path(path);
        std::lock_guard<std::mutex> lk(*m);

        std::filesystem::path file_path(path);
        std::filesystem::create_directories(file_path.parent_path());

        std::ofstream ofs(path, std::ios::binary | std::ios::app);
        if (!ofs.is_open()) {
            throw std::system_error(errno, std::generic_category(), "append_vector_to_file: cannot open file");
        }
        write_length_prefixed_bytes_to_ofstream(ofs, data.data(), data.size());
        ofs.flush();
    } catch (const std::exception& e) {
        std::cerr << "Error in Funktion append_vector_to_file: " << e.what() << std::endl;
    }
}

// Returns the path of the most recently created file in the given directory based on a timestamp prefix in the filename.
std::string get_latest_file_in_directory(const std::string& directory_path) {
    try {
        if (!std::filesystem::exists(directory_path) || !std::filesystem::is_directory(directory_path)) {
            return "";
        }
        std::string latest_file = "";
        std::string latest_timestamp = "";
        std::regex timestamp_regex("^(\\d{8}_\\d{6}).*");
        for (const auto& entry : std::filesystem::directory_iterator(directory_path)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                std::smatch match;
                if (std::regex_search(filename, match, timestamp_regex) && match.size() > 1) {
                    std::string timestamp = match[1];
                    if (timestamp > latest_timestamp) {
                        latest_timestamp = timestamp;
                        latest_file = entry.path().string();
                    }
                }
            }
        }
        return latest_file;
    } catch (const std::exception& e) {
        std::cerr << "Error in Funktion get_latest_file_in_directory: " << e.what() << std::endl;
        return "";
    }
}

struct FileVectorReader::Impl {
    std::ifstream ifs;
    std::string path;
    std::shared_ptr<std::mutex> mtx;
    Impl(const std::string& p) : ifs(p, std::ios::binary), path(p) {
        if (!ifs.is_open()) throw std::runtime_error("FileVectorReader: cannot open file: " + p);
    }
};

// Opens the specified file for sequential binary vector reading; throws if the file cannot be opened.
FileVectorReader::FileVectorReader(const std::string& path) {
    pimpl = new Impl(path);
    pimpl->mtx = get_mutex_for_path(path);
}

FileVectorReader::~FileVectorReader() { delete pimpl; }

// Resets the read position to the beginning of the file.
void FileVectorReader::reset() {
    std::lock_guard<std::mutex> lk(*pimpl->mtx);
    pimpl->ifs.clear();
    pimpl->ifs.seekg(0);
}

// Reads the next length-prefixed byte vector from the file into out; returns false at EOF.
bool FileVectorReader::next(std::vector<uint8_t>& out) {
    std::lock_guard<std::mutex> lk(*pimpl->mtx);
    return read_length_prefixed_bytes_from_ifstream(pimpl->ifs, out);
}

// Reads all length-prefixed byte vectors from a file and returns them as a collection.
static std::vector<std::vector<uint8_t>> read_all_vectors_from_file(const std::string& path) {
    std::vector<std::vector<uint8_t>> result;
    FileVectorReader reader(path);
    std::vector<uint8_t> tmp;
    while (reader.next(tmp)) {
        result.push_back(std::move(tmp));
        tmp.clear();
    }
    return result;
}

// Manages a pool of persistent ZeroMQ PUSH sockets, one per endpoint, for efficient repeated sending.
class ZmqPushManager {
private:
    ZmqPushManager() : context_(1) {}
    ~ZmqPushManager() = default;
    zmq::context_t context_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<zmq::socket_t>> sockets_;
    
public:
    // Returns the singleton instance of ZmqPushManager.
    static ZmqPushManager& instance() {
        static ZmqPushManager mgr;
        return mgr;
    }

    // Sends a byte buffer to the given endpoint, creating and binding a new socket if necessary.
    void send_to_endpoint(const std::string& endpoint, const std::vector<uint8_t>& data) {
        try {
            std::unique_lock<std::mutex> lock(mutex_);
            auto it = sockets_.find(endpoint);
            if (it == sockets_.end()) {
                auto sock_ptr = std::make_unique<zmq::socket_t>(context_, zmq::socket_type::push);
                int linger_ms = 1000;
                sock_ptr->set(zmq::sockopt::linger, linger_ms);
                sock_ptr->bind(endpoint);
                it = sockets_.emplace(endpoint, std::move(sock_ptr)).first;
            }
            zmq::socket_t* sock = it->second.get();
            lock.unlock();

            zmq::message_t msg(data.data(), data.size());
            auto send_result = sock->send(msg, zmq::send_flags::none);
            if (!send_result.has_value()) {
                throw std::runtime_error("ZmqPushManager::send_to_endpoint: send failed");
            }
        } catch (const std::exception& e) {
            std::cerr << "Error in Funktion ZmqPushManager::send_to_endpoint: " << e.what() << std::endl;
        }
    }
};

// Sends a byte vector to the given ZeroMQ endpoint via the shared push manager.
void send_vector_via_zmq(const std::string& zmq_endpoint, const std::vector<uint8_t>& data) {
    ZmqPushManager::instance().send_to_endpoint(zmq_endpoint, data);
}

// Serializes a TFHECiphertextVec to a byte buffer using a temporary file as intermediate storage.
static bool serialize_TFHECiphertextVec_to_buffer(const TFHECiphertextVec& v,
                                                  TFheGateBootstrappingParameterSet* params,
                                                  std::vector<uint8_t>& out) {
    if (!params) return false;
    FILE* tmp = tmpfile();
    if (!tmp) return false;
    uint32_t n = static_cast<uint32_t>(v.size());
    uint32_t be = htonl(n);
    if (fwrite(&be, sizeof(be), 1, tmp) != 1) { fclose(tmp); return false; }
    for (uint32_t i = 0; i < n; ++i) {
        const LweSample& bit = v[i];
        export_gate_bootstrapping_ciphertext_toFile(tmp, &bit, params);
    }
    fflush(tmp);
    long pos = ftell(tmp);
    if (pos < 0) { fclose(tmp); return false; }
    rewind(tmp);
    out.resize(static_cast<size_t>(pos));
    size_t r = fread(out.data(), 1, out.size(), tmp);
    fclose(tmp);
    return r == out.size();
}

// Deserializes a byte buffer into a TFHECiphertextVec using a temporary file as intermediate storage.
static bool deserialize_buffer_to_TFHECiphertextVec(const std::vector<uint8_t>& in,
                                                    TFheGateBootstrappingParameterSet* params,
                                                    TFHECiphertextVec& out) {
    if (!params) return false;
    if (in.size() < sizeof(uint32_t)) return false;
    FILE* tmp = tmpfile();
    if (!tmp) return false;
    if (fwrite(in.data(), 1, in.size(), tmp) != in.size()) { fclose(tmp); return false; }
    rewind(tmp);
    uint32_t be_n = 0;
    if (fread(&be_n, sizeof(be_n), 1, tmp) != 1) { fclose(tmp); return false; }
    uint32_t n = ntohl(be_n);
    out.init(static_cast<int>(n), params);
    for (uint32_t i = 0; i < n; ++i) {
        import_gate_bootstrapping_ciphertext_fromFile(tmp, &out[i], params);
    }
    fclose(tmp);
    return true;
}

// Appends a serialized TFHECiphertextVec to a file in length-prefixed format with per-path thread-safe locking.
void append_vector_to_file(const std::string& path,
                           const TFHECiphertextVec& data,
                           TFheGateBootstrappingParameterSet* params) {
    try {
        auto m = get_mutex_for_path(path);
        std::lock_guard<std::mutex> lk(*m);

        std::filesystem::path file_path(path);
        std::filesystem::create_directories(file_path.parent_path());

        FILE* f = fopen(path.c_str(), "ab");
        if (!f) throw std::runtime_error("failed to open file for append: " + path);

        std::vector<uint8_t> buf;
        if (!serialize_TFHECiphertextVec_to_buffer(data, params, buf)) {
            fclose(f);
            throw std::runtime_error("TFHE serialization failed for an element");
        }
        write_length_prefixed_bytes_to_FILE(f, buf.data(), buf.size());

        fflush(f);
        fclose(f);
    } catch (const std::exception& e) {
        std::cerr << "Error in Funktion append_vector_to_file: " << e.what() << std::endl;
    }
}

struct FileTFHEVectorReader::Impl {
    FILE* f = nullptr;
    TFheGateBootstrappingParameterSet* params = nullptr;
    std::string path;
    std::shared_ptr<std::mutex> mtx;
};

// Opens the specified file for sequential TFHE ciphertext vector reading with the given deserialization parameters.
FileTFHEVectorReader::FileTFHEVectorReader(const std::string& path, TFheGateBootstrappingParameterSet* params) {
    pimpl = new Impl();
    pimpl->params = params;
    pimpl->path = path;
    pimpl->mtx = get_mutex_for_path(path);
    pimpl->f = fopen(path.c_str(), "rb");
    if (!pimpl->f) pimpl->f = nullptr;
}

FileTFHEVectorReader::~FileTFHEVectorReader() {
    if (pimpl->f) fclose(pimpl->f);
    delete pimpl;
}

// Reads the next TFHE ciphertext vector from the file into out; returns false at EOF.
bool FileTFHEVectorReader::next(TFHECiphertextVec& out) {
    if (!pimpl->f) return false;
    std::lock_guard<std::mutex> lk(*pimpl->mtx);
    std::vector<uint8_t> buf;
    if (!read_length_prefixed_bytes_from_FILE(pimpl->f, buf)) return false;
    if (!deserialize_buffer_to_TFHECiphertextVec(buf, pimpl->params, out)) {
        throw std::runtime_error("TFHE deserialization failed");
    }
    return true;
}

// Resets the read position to the beginning of the file.
void FileTFHEVectorReader::reset() {
    if (!pimpl->f) return;
    std::lock_guard<std::mutex> lk(*pimpl->mtx);
    fseek(pimpl->f, 0, SEEK_SET);
}

// Reads all byte vectors from a file and sends them via ZeroMQ, optionally truncating the file afterwards.
void send_all_vectors_via_zmq(const std::string& path,
                              const std::string& zmq_endpoint,
                              bool remove_after_send) {
    auto items = read_all_vectors_from_file(path);
    if (items.empty()) return;
    for (auto &vec : items) {
        send_vector_via_zmq(zmq_endpoint, vec);
    }
    if (remove_after_send) {
        auto m = get_mutex_for_path(path);
        std::lock_guard<std::mutex> lk(*m);
        FILE* f = fopen(path.c_str(), "wb");
        if (f) fclose(f);
    }
}

// Serializes a single TFHECiphertextVec and sends it as a byte buffer via ZeroMQ.
void send_vector_via_zmq(const std::string& zmq_endpoint,
                         const TFHECiphertextVec& data,
                         TFheGateBootstrappingParameterSet* params) {
    if (!params) throw std::runtime_error("TFHE params required for serialization");
    std::vector<uint8_t> buf;
    if (!serialize_TFHECiphertextVec_to_buffer(data, params, buf)) {
        throw std::runtime_error("TFHE serialization failed in send_vector_via_zmq");
    }
    send_vector_via_zmq(zmq_endpoint, buf);
}

// Reads all TFHE ciphertext vectors from a file, serializes them, and sends each via ZeroMQ, optionally truncating the file afterwards.
void send_all_vectors_via_zmq(const std::string& path,
                              const std::string& zmq_endpoint,
                              TFheGateBootstrappingParameterSet* params,
                              bool remove_after_send) {
    FileTFHEVectorReader reader(path, params);
    TFHECiphertextVec item;
    while (reader.next(item)) {
        std::vector<uint8_t> buf;
        if (!serialize_TFHECiphertextVec_to_buffer(item, params, buf)) {
            throw std::runtime_error("TFHE serialization failed during send_all");
        }
        send_vector_via_zmq(zmq_endpoint, buf);
    }
    if (remove_after_send) {
        auto m = get_mutex_for_path(path);
        std::lock_guard<std::mutex> lk(*m);
        FILE* f = fopen(path.c_str(), "wb");
        if (f) fclose(f);
    }
}

// Receives binary messages from a ZeroMQ PULL socket and appends them to a file; stops on an EOF marker frame or after max_messages; returns the number of stored messages.
size_t zmq_receive_and_store(const std::string& path,
                                       const std::string& zmq_endpoint,
                                       size_t max_messages,
                                       bool expect_eof_frame) {
    zmq::context_t ctx{1};
    zmq::socket_t sock{ctx, zmq::socket_type::pull};
    sock.connect(zmq_endpoint);

    size_t received = 0;
    auto m = get_mutex_for_path(path);

    while (max_messages == 0 || received < max_messages) {
        zmq::message_t msg;
        auto recv_result = sock.recv(msg, zmq::recv_flags::none);
        if (!recv_result.has_value()) {
            continue;
        }
        size_t sz = msg.size();
        const uint8_t* data = static_cast<const uint8_t*>(msg.data());

        if (sz >= 1 && data[0] == 0xFE) {
            continue;
        }

        if (expect_eof_frame && sz >= 1 && data[0] == 0xFF) {
            break;
        }

        std::vector<uint8_t> v;
        v.assign(data, data + sz);
        {
            std::lock_guard<std::mutex> lk(*m);
            std::ofstream ofs(path, std::ios::binary | std::ios::app);
            if (!ofs.is_open()) throw std::runtime_error("zmq_receive_and_store: cannot open file for append");
            write_length_prefixed_bytes_to_ofstream(ofs, v.data(), v.size());
            ofs.flush();
        }
        ++received;
    }

    return received;
}

// Receives raw messages from a ZeroMQ endpoint and stores them in a file; delegates to the byte-level overload since TFHE deserialization is deferred.
size_t zmq_receive_and_store(const std::string& path,
                             const std::string& zmq_endpoint,
                             [[maybe_unused]] TFheGateBootstrappingParameterSet* params,
                             size_t max_messages,
                             bool expect_eof_frame) {
    size_t received = zmq_receive_and_store(path, zmq_endpoint, max_messages, expect_eof_frame);
    return received;
}

// Sends a start-of-file marker byte (0xFE) to the given ZeroMQ endpoint to signal the beginning of a transmission.
void send_sof_marker(const std::string& zmq_endpoint) {
    std::vector<uint8_t> sof_marker = { 0xFE };
    send_vector_via_zmq(zmq_endpoint, sof_marker);
}