#include "InfInt.h"
#include "base64.hpp"
#include "json.hpp"

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

#include <zlib.h>

namespace rjson
{
namespace
{
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
        std::vector<uint8_t> bytes = value.to_bytes();
        if (bytes.size() < min_size)
        {
            std::vector<uint8_t> padded(min_size - bytes.size(), 0);
            padded.insert(padded.end(), bytes.begin(), bytes.end());
            return padded;
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

    std::vector<uint8_t> compress_zlib(const std::vector<uint8_t> &input)
    {
        uLong source_len = static_cast<uLong>(input.size());
        uLong dest_len = compressBound(source_len);
        std::vector<uint8_t> output(dest_len);

        int status = compress2(output.data(), &dest_len, input.data(), source_len, Z_BEST_COMPRESSION);
        if (status != Z_OK)
        {
            throw std::runtime_error("zlib compression failed");
        }

        output.resize(dest_len);
        return output;
    }

    std::vector<uint8_t> decompress_zlib(const std::vector<uint8_t> &input)
    {
        if (input.empty())
        {
            return {};
        }

        z_stream stream{};
        stream.next_in = const_cast<Bytef *>(reinterpret_cast<const Bytef *>(input.data()));
        stream.avail_in = static_cast<uInt>(input.size());

        if (inflateInit(&stream) != Z_OK)
        {
            throw std::runtime_error("Failed to initialise zlib inflate");
        }

        std::vector<uint8_t> output;
        output.reserve(input.size() * 2);

        const size_t chunk_size = 4096;
        int ret = Z_OK;
        do
        {
            size_t previous_size = output.size();
            output.resize(previous_size + chunk_size);
            stream.next_out = output.data() + previous_size;
            stream.avail_out = static_cast<uInt>(chunk_size);

            ret = inflate(&stream, Z_NO_FLUSH);
            if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR)
            {
                inflateEnd(&stream);
                throw std::runtime_error("zlib decompression failed");
            }

            output.resize(previous_size + (chunk_size - stream.avail_out));
        } while (ret != Z_STREAM_END);

        inflateEnd(&stream);
        return output;
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

    std::tuple<InfInt, InfInt> load_public_pkcs8_key()
    {
        auto [data, _] = parse_asn1_der_sequence(key_bytes_, 0);
        size_t index = 0;

        std::tie(std::ignore, index) = parse_asn1_der_sequence(data, index);

        ASN1Element bit_string = parse_asn1_der_element(data, index);
        if (bit_string.tag != 0x03 || bit_string.value.empty() || bit_string.value.front() != 0x00)
        {
            throw std::runtime_error("Expected BIT STRING");
        }

        std::vector<uint8_t> public_key_bytes(bit_string.value.begin() + 1, bit_string.value.end());

        auto [rsa_key_data, __] = parse_asn1_der_sequence(public_key_bytes, 0);
        index = 0;

        std::vector<uint8_t> n_bytes;
        std::vector<uint8_t> e_bytes;
        std::tie(n_bytes, index) = parse_asn1_der_integer(rsa_key_data, index);
        std::tie(e_bytes, index) = parse_asn1_der_integer(rsa_key_data, index);

        return std::make_tuple(bytes_to_int(e_bytes), bytes_to_int(n_bytes));
    }

    std::tuple<InfInt, InfInt> load_private_pkcs8_key()
    {
        auto [data, _] = parse_asn1_der_sequence(key_bytes_, 0);
        size_t index = 0;

        std::tie(std::ignore, index) = parse_asn1_der_integer(data, index);
        std::tie(std::ignore, index) = parse_asn1_der_sequence(data, index);

        ASN1Element private_key_octet = parse_asn1_der_element(data, index);
        if (private_key_octet.tag != 0x04)
        {
            throw std::runtime_error("Expected OCTET STRING");
        }

        auto [rsa_key_data, __] = parse_asn1_der_sequence(private_key_octet.value, 0);
        index = 0;

        std::tie(std::ignore, index) = parse_asn1_der_integer(rsa_key_data, index);

        std::vector<uint8_t> n_bytes;
        std::vector<uint8_t> e_bytes;
        std::vector<uint8_t> d_bytes;
        std::tie(n_bytes, index) = parse_asn1_der_integer(rsa_key_data, index);
        std::tie(e_bytes, index) = parse_asn1_der_integer(rsa_key_data, index);
        std::tie(d_bytes, index) = parse_asn1_der_integer(rsa_key_data, index);

        return std::make_tuple(bytes_to_int(d_bytes), bytes_to_int(n_bytes));
    }

private:
    std::string file_path_;
    std::vector<uint8_t> key_bytes_;

    std::vector<uint8_t> read_pem_file()
    {
        std::ifstream file(file_path_);
        if (!file)
        {
            throw std::runtime_error("Cannot open PEM file: " + file_path_);
        }

        std::string line;
        std::string key_data;
        while (std::getline(file, line))
        {
            if (line.find("BEGIN") == std::string::npos && line.find("END") == std::string::npos)
            {
                key_data += line;
            }
        }
        return base64::decode(key_data);
    }

    ASN1Element parse_asn1_der_element(const std::vector<uint8_t> &data, size_t index)
    {
        if (index >= data.size())
        {
            throw std::runtime_error("Unexpected end of ASN.1 data");
        }

        ASN1Element element;
        element.tag = data[index++];

        if (index >= data.size())
        {
            throw std::runtime_error("Unexpected end of ASN.1 data while reading length");
        }

        uint8_t length_byte = data[index++];
        if ((length_byte & 0x80u) == 0)
        {
            element.length = length_byte & 0x7Fu;
        }
        else
        {
            size_t num_length_bytes = length_byte & 0x7Fu;
            if (index + num_length_bytes > data.size())
            {
                throw std::runtime_error("Invalid ASN.1 length encoding");
            }

            element.length = 0;
            for (size_t i = 0; i < num_length_bytes; ++i)
            {
                element.length = (element.length << 8) | data[index++];
            }
        }

        if (index + element.length > data.size())
        {
            throw std::runtime_error("ASN.1 element length exceeds buffer");
        }

        element.value.assign(data.begin() + index, data.begin() + index + element.length);
        element.next_index = index + element.length;
        return element;
    }

    std::tuple<std::vector<uint8_t>, size_t> parse_asn1_der_integer(const std::vector<uint8_t> &data, size_t index)
    {
        ASN1Element element = parse_asn1_der_element(data, index);
        if (element.tag != 0x02)
        {
            throw std::runtime_error("Expected ASN.1 INTEGER");
        }
        return std::make_tuple(element.value, element.next_index);
    }

    std::tuple<std::vector<uint8_t>, size_t> parse_asn1_der_sequence(const std::vector<uint8_t> &data, size_t index)
    {
        ASN1Element element = parse_asn1_der_element(data, index);
        if (element.tag != 0x30)
        {
            throw std::runtime_error("Expected ASN.1 SEQUENCE");
        }
        return std::make_tuple(element.value, element.next_index);
    }
};

class SimpleRSAChunkEncryptor
{
public:
    SimpleRSAChunkEncryptor(std::optional<std::tuple<InfInt, InfInt>> public_key = std::nullopt,
                            std::optional<std::tuple<InfInt, InfInt>> private_key = std::nullopt)
        : public_key_(std::move(public_key)),
          private_key_(std::move(private_key))
    {
        const InfInt *modulus = nullptr;
        if (public_key_)
        {
            modulus = &std::get<1>(*public_key_);
        }
        else if (private_key_)
        {
            modulus = &std::get<1>(*private_key_);
        }

        if (modulus)
        {
            modulus_bytes_ = (bit_length(*modulus) + 7) / 8;
        }

        if (public_key_)
        {
            if (modulus_bytes_ == 0)
            {
                throw std::runtime_error("Invalid RSA modulus");
            }

            if (modulus_bytes_ <= 1)
            {
                throw std::runtime_error("The modulus 'n' is too small. Please use a larger key size.");
            }
            data_chunk_bytes_ = modulus_bytes_ - 1;
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
