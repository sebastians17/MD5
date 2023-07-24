#include <stdio.h>
#include <openssl/evp.h>

int main() {
    const char* filename = "Filename.exe";
    FILE* inFile = fopen(filename, "rb");
    int bytes;
    unsigned char data[1024];

    EVP_MD_CTX* mdctx;
    unsigned char* md5_digest;
    unsigned int md5_digest_len = EVP_MD_size(EVP_md5());

    if (inFile == NULL) {
        printf("%s can't be opened.\n", filename);
        return 0;
    }

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);

    while ((bytes = fread(data, 1, 1024, inFile)) != 0) {
        EVP_DigestUpdate(mdctx, data, bytes);
    }

    md5_digest = (unsigned char*)OPENSSL_malloc(md5_digest_len);
    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len);
    EVP_MD_CTX_free(mdctx);
    for (int i = 0; i < md5_digest_len; i++) {
        printf("%02x", md5_digest[i]);
    }

    return 0;
}