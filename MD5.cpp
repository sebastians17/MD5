#include <iostream>
#include <stdio.h>
#include <string>
#include <openssl/evp.h>

int main() {
    const char* filename = "Filename.exe";
    FILE* inFile = fopen(filename, "rb");
    int bytes;
    unsigned char data[1024];
    std::string checksum;

    EVP_MD_CTX* mdctx;
    unsigned int md5_digest_len = EVP_MD_size(EVP_md5());

    if (inFile == nullptr) {
        printf("%s can't be opened.\n", filename);
        return 0;
    }

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr);

    while ((bytes = fread(data, 1, 1024, inFile)) != 0) {
        EVP_DigestUpdate(mdctx, data, bytes);
    }

    unsigned char* md5_digest = static_cast<unsigned char*>(OPENSSL_malloc(md5_digest_len));
    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len);
    EVP_MD_CTX_free(mdctx);

    // Print MD5
    for (int i = 0; i < md5_digest_len; i++) {
        printf("%02x", md5_digest[i]);
    }

    // MD5 to string
    checksum.resize(md5_digest_len * 2);
    for (unsigned int i = 0; i < md5_digest_len; ++i) {
        std::sprintf(&checksum[i * 2], "%02x", md5_digest[i]);
    }
    std::cout << "MD5: " << checksum << std::endl;

    return 0;
}