#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cmath>
#include <tuple>
#include <cstdint>

namespace base64
{

    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    inline bool is_base64(unsigned char c)
    {
        return (c == 43 ||              // '+'
                (c >= 47 && c <= 57) || // '0'-'9'
                (c >= 65 && c <= 90) || // 'A'-'Z'
                (c >= 97 && c <= 122)); // 'a'-'z'
    }

    // Encode a vector of bytes (uint8_t) to a base64 string
    inline std::string encode(const std::vector<uint8_t> &input)
    {
        std::string output;
        int i = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];

        size_t len = input.size();
        auto it = input.begin();

        while (len--)
        {
            char_array_3[i++] = *(it++);
            if (i == 3)
            {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (i = 0; i < 4; i++)
                {
                    output += chars[char_array_4[i]];
                }
                i = 0;
            }
        }

        if (i > 0)
        {
            for (int j = i; j < 3; j++)
                char_array_3[j] = '\0';

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

            for (int j = 0; j < i + 1; j++)
            {
                output += chars[char_array_4[j]];
            }

            while (i++ < 3)
                output += '=';
        }

        return output;
    }

    // Decode a base64 string into a vector of bytes (uint8_t)
    inline std::vector<uint8_t> decode(const std::string &input)
    {
        size_t len = input.size();
        int i = 0, in = 0;
        unsigned char char_array_4[4], char_array_3[3];
        std::vector<uint8_t> output;

        while (len-- && (input[in] != '=') && is_base64(input[in]))
        {
            char_array_4[i++] = input[in++];
            if (i == 4)
            {
                for (i = 0; i < 4; i++)
                {
                    char_array_4[i] = static_cast<unsigned char>(chars.find(char_array_4[i]));
                }

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (i = 0; i < 3; i++)
                    output.push_back(char_array_3[i]);
                i = 0;
            }
        }

        if (i > 0)
        {
            for (int j = i; j < 4; j++)
                char_array_4[j] = 0;

            for (int j = 0; j < 4; j++)
            {
                char_array_4[j] = static_cast<unsigned char>(chars.find(char_array_4[j]));
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (int j = 0; j < i - 1; j++)
                output.push_back(char_array_3[j]);
        }

        return output;
    }

} // namespace base64
