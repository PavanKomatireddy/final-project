#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <sstream>

// SHA-256 constants
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xedef2b1c, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x9836ed1d,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
    0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
    0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354,
    0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1,
    0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x27b5a5d6, 0x2e1b2138, 0x4d2c6dfc
};

// Right rotate a 32-bit value
inline uint32_t right_rotate(uint32_t value, uint32_t bits) {
    return (value >> bits) | (value << (32 - bits));
}

// SHA-256 padding
std::vector<uint8_t> pad_message(const std::vector<uint8_t> &message) {
    uint64_t original_length = message.size() * 8;  // Length in bits
    std::vector<uint8_t> padded_message(message);

    // Append a 1 bit (0x80 byte)
    padded_message.push_back(0x80);

    while ((padded_message.size() * 8) % 512 != 448) {
        padded_message.push_back(0x00);
    }

    // Append the original message length as a 64-bit big-endian integer
    for (int i = 7; i >= 0; --i) {
        padded_message.push_back(static_cast<uint8_t>((original_length >> (i * 8)) & 0xFF));
    }

    return padded_message;
}

// SHA-256 compression function
void sha256_compress(const uint8_t block[64], uint32_t hash[8]) {
    uint32_t w[64];
    
    // Prepare the message schedule
    for (int i = 0; i < 16; i++) {
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
               (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }

    for (int i = 16; i < 64; i++) {
        w[i] = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] += w[i - 7] + right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
        w[i] += w[i - 16];
    }

    uint32_t a = hash[0], b = hash[1], c = hash[2], d = hash[3];
    uint32_t e = hash[4], f = hash[5], g = hash[6], h = hash[7];

   
    for (int i = 0; i < 64; i++) {
        uint32_t temp1 = h + right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25) +
                         ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t temp2 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22) +
                         ((a & b) ^ (a & c) ^ (b & c));

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}

// Convert the hash to a hexadecimal string
std::string hash_to_string(const uint32_t hash[8]) {
    std::stringstream ss;
    for (int i = 0; i < 8; i++) {
        ss << std::setw(8) << std::setfill('0') << std::hex << hash[i];
    }
    return ss.str();
}

// Function to read file contents
std::vector<uint8_t> read_file(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Could not open the file!" << std::endl;
        exit(1);
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        file.close();
    }

    return buffer;
}

int main() {
    std::string filename = "gospel.txt";  
    std::vector<uint8_t> file_data = read_file(filename);

    std::vector<uint8_t> padded_message = pad_message(file_data);

    uint32_t hash[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Process each 512-bit block
    for (size_t i = 0; i < padded_message.size() / 64; i++) {
        uint8_t block[64];
        std::memcpy(block, &padded_message[i * 64], 64);
        sha256_compress(block, hash);
    }

    // Output the final hash
    std::string result = hash_to_string(hash);
    std::cout << "SHA-256 Hash of the file: " << result << std::endl;

    return 0;
}
