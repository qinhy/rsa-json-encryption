#include "InfInt.h"
#include "base64.hpp"
#include "json.hpp"
#include "zstr.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>


namespace rjson
{
namespace
{
    
    // zlib "wrapper" (not gzip, not raw)
    constexpr int kZlibWindowBits = 15;

    inline std::vector<uint8_t> compress_zlib(const std::vector<uint8_t>& input)
    {
        std::stringstream sink;

        // zstr::ostream( std::ostream&, std::size_t buffer, int level, int window_bits )
        {
            zstr::ostream zouts(sink, /*buffer*/ 1 << 15, /*level*/ Z_BEST_COMPRESSION, /*window_bits*/ kZlibWindowBits);
            if (!input.empty()) {
                zouts.write(reinterpret_cast<const char*>(input.data()),
                            static_cast<std::streamsize>(input.size()));
            }
            // zouts dtor flushes/finishes
        }

        const std::string out = sink.str();
        return std::vector<uint8_t>(out.begin(), out.end());
    }

    inline std::vector<uint8_t> decompress_zlib(const std::vector<uint8_t>& input)
    {
        if (input.empty()) return {};

        std::string compressed(reinterpret_cast<const char*>(input.data()),
                            static_cast<std::size_t>(input.size()));
        std::stringstream source(compressed);

        // zstr::istream( std::istream&, std::size_t buffer, bool throw_on_error, int window_bits )
        zstr::istream zins(source, /*buffer*/ 1 << 15, /*throw_on_error*/ true, /*window_bits*/ kZlibWindowBits);

        std::vector<uint8_t> output;
        std::array<char, 4096> buf{};
        while (true) {
            zins.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            std::streamsize got = zins.gcount();
            if (got > 0) output.insert(output.end(), buf.data(), buf.data() + got);
            if (zins.eof()) break;
            if (!zins.good()) throw std::runtime_error("zlib decompression failed");
        }
        return output;
    }

    InfInt bytes_to_int(const std::vector<uint8_t> &bytes)
    {
        InfInt result = 0;
        for (uint8_t byte : bytes)
        {
            result *= 256;
            result += byte;
        }
        return result;
    }

    std::vector<uint8_t> int_to_bytes(const InfInt &value, size_t min_size = 0)
    {
        // Use library first, then normalize endianness by detection.
        std::vector<uint8_t> bytes = value.to_bytes();

        // Detect library endianness once using 0x01_02_03
        static const bool lib_is_be = [](){
            InfInt test = 0;
            test = 1;        // 0x01
            test *= 256; test += 2; // 0x0102
            test *= 256; test += 3; // 0x010203
            std::vector<uint8_t> b = test.to_bytes();
            return (b.size() >= 3 && b[0]==0x01 && b[1]==0x02 && b[2]==0x03);
        }();

        if (!lib_is_be) {
            std::reverse(bytes.begin(), bytes.end());
        }

        if (bytes.size() < min_size) {
            bytes.insert(bytes.begin(), min_size - bytes.size(), 0);
        }
        return bytes;
    }


    size_t bit_length(const InfInt &value)
    {
        if (value == 0)
        {
            return 0;
        }

        std::vector<uint8_t> bytes = value.to_bytes();
        if (bytes.empty())
        {
            return 0;
        }

        size_t bits = (bytes.size() - 1) * 8;
        uint8_t msb = bytes.front();
        while (msb != 0)
        {
            ++bits;
            msb >>= 1;
        }
        return bits;
    }

    InfInt mod_exp(InfInt base, InfInt exp, const InfInt &mod)
    {
        if (mod == 1)
        {
            return 0;
        }

        base %= mod;
        InfInt result = 1;
        while (exp > 0)
        {
            if (exp % 2 != 0)
            {
                result = (result * base) % mod;
            }
            exp /= 2;
            if (exp > 0)
            {
                base = (base * base) % mod;
            }
        }
        return result;
    }

    std::vector<uint8_t> string_to_bytes(const std::string &input)
    {
        return std::vector<uint8_t>(input.begin(), input.end());
    }

    std::string bytes_to_string(const std::vector<uint8_t> &data)
    {
        return std::string(data.begin(), data.end());
    }

    std::vector<std::string> split(const std::string &input, char delimiter)
    {
        std::vector<std::string> parts;
        std::string token;
        std::istringstream stream(input);
        while (std::getline(stream, token, delimiter))
        {
            parts.push_back(token);
        }
        return parts;
    }

    bool is_valid_utf8(const std::vector<uint8_t> &data)
    {
        size_t i = 0;
        while (i < data.size())
        {
            uint8_t c = data[i];
            size_t remaining = 0;

            if ((c & 0x80u) == 0)
            {
                remaining = 0;
            }
            else if ((c & 0xE0u) == 0xC0u)
            {
                remaining = 1;
                if ((c & 0xFEu) == 0xC0u)
                {
                    return false;
                }
            }
            else if ((c & 0xF0u) == 0xE0u)
            {
                remaining = 2;
            }
            else if ((c & 0xF8u) == 0xF0u && c <= 0xF4u)
            {
                remaining = 3;
            }
            else
            {
                return false;
            }

            if (i + remaining >= data.size())
            {
                return false;
            }

            for (size_t j = 1; j <= remaining; ++j)
            {
                if ((data[i + j] & 0xC0u) != 0x80u)
                {
                    return false;
                }
            }
            i += remaining + 1;
        }
        return true;
    }

} // namespace

struct ASN1Element
{
    uint8_t tag = 0;
    size_t length = 0;
    std::vector<uint8_t> value;
    size_t next_index = 0;
};

class PEMFileReader
{
public:
    explicit PEMFileReader(std::string file_path) : file_path_(std::move(file_path))
    {
        key_bytes_ = read_pem_file();
    }
    
    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> load_public_pkcs8_key()
    {
        auto [data, data_index] = parse_asn1_der_sequence(key_bytes_, 0);
        size_t index = 0;

        // Parse algorithm identifier SEQUENCE (skip it)
        std::tie(std::ignore, index) = parse_asn1_der_sequence(data, index);

        // Parse BIT STRING
        auto [tag, bit_string_length, value, new_index] = parse_asn1_der_element(data, index);
        if (tag != 0x03 || value[0] != 0x00)
        {
            throw std::runtime_error("Expected BIT STRING");
        }
        std::vector<uint8_t> public_key_bytes(value.begin() + 1, value.end());

        // Parse RSAPublicKey SEQUENCE
        auto [rsa_key_data, rsa_key_data_index] = parse_asn1_der_sequence(public_key_bytes, 0);
        index = 0;

        // Parse modulus (n) and exponent (e)
        std::vector<uint8_t> n, e;
        std::tie(n, index) = parse_asn1_der_integer(rsa_key_data, index);
        std::tie(e, index) = parse_asn1_der_integer(rsa_key_data, index);

        return std::make_tuple(e, n);
    }

    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> load_private_pkcs8_key()
    {
        auto [data, data_index] = parse_asn1_der_sequence(key_bytes_, 0);
        size_t index = 0;

        // Parse version INTEGER (skip it)
        std::tie(std::ignore, index) = parse_asn1_der_integer(data, index);

        // Parse algorithm identifier SEQUENCE (skip it)
        std::tie(std::ignore, index) = parse_asn1_der_sequence(data, index);

        // Parse privateKey OCTET STRING
        auto [tag, octet_length, private_key_bytes, new_index] = parse_asn1_der_element(data, index);
        if (tag != 0x04)
        {
            throw std::runtime_error("Expected OCTET STRING");
        }

        // Parse RSAPrivateKey SEQUENCE
        auto [rsa_key_data, rsa_key_data_index] = parse_asn1_der_sequence(private_key_bytes, 0);
        index = 0;

        // Parse version INTEGER (skip it)
        std::tie(std::ignore, index) = parse_asn1_der_integer(rsa_key_data, index);

        // Parse modulus (n), publicExponent (e), and privateExponent (d)
        std::vector<uint8_t> n, e, d;
        std::tie(n, index) = parse_asn1_der_integer(rsa_key_data, index);
        std::tie(e, index) = parse_asn1_der_integer(rsa_key_data, index);
        std::tie(d, index) = parse_asn1_der_integer(rsa_key_data, index);

        return std::make_tuple(d, n);
    }

private:
    std::string file_path_;
    std::vector<uint8_t> key_bytes_;

    std::vector<uint8_t> read_pem_file()
    {
        std::ifstream file(file_path_, std::ios::in);
        if (!file) {
            throw std::runtime_error("Cannot open PEM file: " + file_path_);
        }

        std::string line, key_data;
        while (std::getline(file, line)) {
            // remove CR and spaces/tabs that some PEM writers add
            line.erase(std::remove_if(line.begin(), line.end(),
                    [](unsigned char ch){ return ch=='\r' || ch==' ' || ch=='\t'; }),
                    line.end());
            if (line.empty()) continue;
            if (line.find("BEGIN") != std::string::npos) continue;
            if (line.find("END")   != std::string::npos) continue;
            key_data += line;
        }
        // Just in case, purge any leftover whitespace
        key_data.erase(std::remove_if(key_data.begin(), key_data.end(),
                    [](unsigned char c){ return std::isspace(c); }), key_data.end());
        return base64::decode(key_data);
    }


    std::tuple<uint8_t, size_t, std::vector<uint8_t>, size_t>
    parse_asn1_der_element(const std::vector<uint8_t>& data, size_t index)
    {
        if (index >= data.size()) throw std::runtime_error("ASN.1: out of data (tag)");
        uint8_t tag = data[index++];

        if (index >= data.size()) throw std::runtime_error("ASN.1: out of data (length)");
        uint8_t length_byte = data[index++];

        size_t length = 0;
        if ((length_byte & 0x80u) == 0u) {
            length = length_byte & 0x7Fu;
        } else {
            size_t num_length_bytes = length_byte & 0x7Fu;
            if (num_length_bytes == 0) throw std::runtime_error("ASN.1: indefinite length not supported");
            if (index + num_length_bytes > data.size()) throw std::runtime_error("ASN.1: length OOB");
            for (size_t i = 0; i < num_length_bytes; ++i) {
                length = (length << 8) | data[index++];
            }
        }

        if (index + length > data.size()) throw std::runtime_error("ASN.1: value OOB");
        std::vector<uint8_t> value(data.begin() + index, data.begin() + index + length);
        index += length;

        return {tag, length, value, index};
    }



    std::tuple<std::vector<uint8_t>, size_t> parse_asn1_der_integer(const std::vector<uint8_t>& data, size_t index) {
        auto [tag, _, value, new_index] = parse_asn1_der_element(data, index);
        if (tag != 0x02) {
            throw std::runtime_error("Expected INTEGER");
        }
        return {value, new_index};
    }

    std::tuple<std::vector<uint8_t>, size_t> parse_asn1_der_sequence(const std::vector<uint8_t> &data, size_t index)
    {
        auto [tag, length, value, new_index] = parse_asn1_der_element(data, index);
        if (tag != 0x30)
            throw std::runtime_error("Expected SEQUENCE");

        return {value, new_index};
    }
};

class SimpleRSAChunkEncryptor
{
public:
    SimpleRSAChunkEncryptor(
        std::optional<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>> public_key,
        std::optional<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>> private_key = std::nullopt)
    {
        if (public_key) {
            const auto& [e_bytes, n_bytes] = *public_key;
            public_key_.emplace(bytes_to_int(e_bytes), bytes_to_int(n_bytes));
        }
        if (private_key) {
            const auto& [d_bytes, n_bytes] = *private_key;
            private_key_.emplace(bytes_to_int(d_bytes), bytes_to_int(n_bytes));
        }

        const InfInt* modulus = nullptr;
        if (public_key_)      modulus = &std::get<1>(*public_key_);
        else if (private_key_) modulus = &std::get<1>(*private_key_);

        if (modulus) {
            modulus_bytes_ = (bit_length(*modulus) + 7) / 8;
        }

        if (public_key_) {
            if (modulus_bytes_ == 0) throw std::runtime_error("Invalid RSA modulus");
            if (modulus_bytes_ <= 1) throw std::runtime_error("Modulus too small");
            data_chunk_bytes_ = modulus_bytes_ - 1; // room for 0x01 prefix
        }
    }

    std::string encrypt_string(const std::string &plaintext, bool compress = true) const
    {
        if (!public_key_)
        {
            throw std::runtime_error("Public key required for encryption.");
        }

        std::vector<uint8_t> data_bytes = string_to_bytes(plaintext);
        if (compress)
        {
            data_bytes = compress_zlib(data_bytes);
        }

        const InfInt &e = std::get<0>(*public_key_);
        const InfInt &n = std::get<1>(*public_key_);

        std::vector<std::string> encoded_chunks;
        for (size_t offset = 0; offset < data_bytes.size(); offset += data_chunk_bytes_)
        {
            size_t end = std::min(offset + data_chunk_bytes_, data_bytes.size());
            std::vector<uint8_t> chunk(data_bytes.begin() + offset, data_bytes.begin() + end);

            std::vector<uint8_t> chunk_with_prefix;
            chunk_with_prefix.reserve(chunk.size() + 1);
            chunk_with_prefix.push_back(0x01);
            chunk_with_prefix.insert(chunk_with_prefix.end(), chunk.begin(), chunk.end());

            InfInt chunk_int = bytes_to_int(chunk_with_prefix);
            InfInt encrypted_int = mod_exp(chunk_int, e, n);

            std::vector<uint8_t> encrypted_bytes = int_to_bytes(encrypted_int, modulus_bytes_);
            encoded_chunks.push_back(base64::encode(encrypted_bytes));
        }

        std::ostringstream oss;
        for (size_t i = 0; i < encoded_chunks.size(); ++i)
        {
            if (i > 0)
            {
                oss << '|';
            }
            oss << encoded_chunks[i];
        }

        return oss.str();
    }

    std::string decrypt_string(const std::string &encrypted_data) const
    {
        if (!private_key_)
        {
            throw std::runtime_error("Private key required for decryption.");
        }

        if (modulus_bytes_ == 0)
        {
            throw std::runtime_error("Invalid RSA modulus");
        }

        const InfInt &d = std::get<0>(*private_key_);
        const InfInt &n = std::get<1>(*private_key_);

        std::vector<uint8_t> decrypted_bytes;
        for (const std::string &chunk_encoded : split(encrypted_data, '|'))
        {
            if (chunk_encoded.empty())
            {
                continue;
            }

            std::vector<uint8_t> encrypted_chunk = base64::decode(chunk_encoded);
            InfInt encrypted_int = bytes_to_int(encrypted_chunk);
            InfInt decrypted_int = mod_exp(encrypted_int, d, n);

            std::vector<uint8_t> chunk_with_prefix = int_to_bytes(decrypted_int, modulus_bytes_);
            auto first_non_zero = std::find_if(chunk_with_prefix.begin(), chunk_with_prefix.end(),
                                               [](uint8_t b)
                                               {
                                                   return b != 0;
                                               });

            if (first_non_zero == chunk_with_prefix.end() || *first_non_zero != 0x01)
            {
                throw std::runtime_error("Invalid chunk prefix during decryption.");
            }

            std::vector<uint8_t> chunk(first_non_zero + 1, chunk_with_prefix.end());
            decrypted_bytes.insert(decrypted_bytes.end(), chunk.begin(), chunk.end());
        }

        if (is_valid_utf8(decrypted_bytes))
        {
            return bytes_to_string(decrypted_bytes);
        }

        try
        {
            std::vector<uint8_t> decompressed = decompress_zlib(decrypted_bytes);
            return bytes_to_string(decompressed);
        }
        catch (const std::exception &)
        {
            throw std::runtime_error("Failed to decode data after all attempts.");
        }
    }

private:
    std::optional<std::tuple<InfInt, InfInt>> public_key_;
    std::optional<std::tuple<InfInt, InfInt>> private_key_;
    size_t modulus_bytes_ = 0;
    size_t data_chunk_bytes_ = 0;
};

std::string dump_rJSONs(const std::string &json_string, const std::string &public_pkcs8_key_path, bool compress)
{
    SimpleRSAChunkEncryptor encryptor(
        std::make_optional(PEMFileReader(public_pkcs8_key_path).load_public_pkcs8_key()));
    return encryptor.encrypt_string(json_string, compress);
}

std::string load_rJSONs(const std::string &encrypted_data, const std::string &private_pkcs8_key_path)
{
    SimpleRSAChunkEncryptor decryptor(
        std::nullopt,
        std::make_optional(PEMFileReader(private_pkcs8_key_path).load_private_pkcs8_key()));
    return decryptor.decrypt_string(encrypted_data);
}

void dump_rJSON(const std::string &json_string, const std::string &path, const std::string &public_pkcs8_key_path, bool compress)
{
    std::ofstream file(path);
    if (!file)
    {
        throw std::runtime_error("Cannot open file for writing: " + path);
    }
    file << dump_rJSONs(json_string, public_pkcs8_key_path, compress);
}

std::string load_rJSON(const std::string &path, const std::string &private_pkcs8_key_path)
{
    std::ifstream file(path);
    if (!file)
    {
        throw std::runtime_error("Cannot open file for reading: " + path);
    }

    std::ostringstream oss;
    oss << file.rdbuf();
    return load_rJSONs(oss.str(), private_pkcs8_key_path);
}

std::string dump_rJSONs(const nlohmann::json &json, const std::string &public_pkcs8_key_path, bool compress)
{
    return dump_rJSONs(json.dump(), public_pkcs8_key_path, compress);
}

nlohmann::json load_rJSONs_json(const std::string &encrypted_data, const std::string &private_pkcs8_key_path)
{
    return nlohmann::json::parse(load_rJSONs(encrypted_data, private_pkcs8_key_path));
}

void dump_rJSON(const nlohmann::json &json, const std::string &path, const std::string &public_pkcs8_key_path, bool compress)
{
    dump_rJSON(json.dump(), path, public_pkcs8_key_path, compress);
}

nlohmann::json load_rJSON_json(const std::string &path, const std::string &private_pkcs8_key_path)
{
    return nlohmann::json::parse(load_rJSON(path, private_pkcs8_key_path));
}

} // namespace rjson
