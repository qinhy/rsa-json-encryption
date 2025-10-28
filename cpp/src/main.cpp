#include "rjson.hpp"

#include <exception>
#include <iostream>
#include <optional>
#include <string>

int main()
{
    const std::string public_key_path = "../../tmp/public_key.pem";
    const std::string private_key_path = "../../tmp/private_key.pem";

    try
    {
        auto public_key = rjson::PEMFileReader(public_key_path).load_public_pkcs8_key();
        auto private_key = rjson::PEMFileReader(private_key_path).load_private_pkcs8_key();

        rjson::SimpleRSAChunkEncryptor encryptor(
            std::make_optional(public_key),
            std::make_optional(private_key));

        const std::string plaintext = "Hello, RSA encryption with .pem support!";
        std::cout << "Original Plaintext:[" << plaintext << "]\n";

        std::string encrypted_text = encryptor.encrypt_string(plaintext);
        std::cout << "\nEncrypted (Base64 encoded):[" << encrypted_text << "]\n";

        std::string decrypted_text = encryptor.decrypt_string(encrypted_text);
        std::cout << "\nDecrypted Text:[" << decrypted_text << "]\n";
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Error: " << ex.what() << '\n';
        return 1;
    }

    using nlohmann::json;
    try {
        std::string plain = R"({"msg":"hello","n":123})";
        std::string enc = rjson::dump_rJSONs(plain, public_key_path, /*compress=*/true);
        std::string dec = rjson::load_rJSONs(enc, private_key_path);
        std::cout << dec << std::endl; // should print the JSON
    } catch (const std::exception& ex) {
        std::cerr << "ERR: " << ex.what() << std::endl;
    }

    return 0;
}
