#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

#define ROUNDS 32

typedef uint32_t u32;

u32 key[4] = {0x23423423, 0x45645645, 0x67867867, 0x89A89A89};

void madryga_encrypt(u32 *v, u32 *k) {
    u32 v0=v[0], v1=v[1], sum=0, i;
    u32 delta=0x9e3779b9;
    for ( i = 0; i < ROUNDS; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    v[0]=v0; v[1]=v1;
}

void madryga_decrypt(u32 *v, u32 *k) {
    u32 v0=v[0], v1=v[1], sum=0xC6EF3720, i;
    u32 delta=0x9e3779b9;
    for ( i = 0; i < ROUNDS; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= delta;
    }
    v[0]=v0; v[1]=v1;
}
// take pointer to data and it's length
void madryga_encrypt_data(unsigned char *data, int data_len) {
    int i;
    uint32_t *ptr = (uint32_t *)data; // cast to uint32_t pointer for 4 byte block processing
    for (i = 0; i < data_len; i += 8) {
        madryga_encrypt(ptr, key);
        ptr += 2;
    }
    // check for remaining bytes
    int remaining = data_len % 8;
    if (remaining != 0) {
        // pad with NOPs
        unsigned char pad[8] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        memcpy(pad, ptr, remaining);
        madryga_encrypt((uint32_t *)pad, key); // encrypt with the padded block
        memcpy(ptr, pad, remaining);
    }
}

void madryga_decrypt_data(unsigned char *data, int data_len) {
    int i;
    uint32_t *ptr = (uint32_t *)data;
    for (i = 0; i < data_len / 8; i++) {
        madryga_decrypt(ptr, key);
        ptr += 2;
    }
    // check for remaining bytes
    int remaining = data_len % 8;
    if (remaining != 0) {
        // pad with NOPs
        unsigned char pad[8] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        memcpy(pad, ptr, remaining);
        madryga_decrypt((uint32_t *)pad, key);
        memcpy(ptr, pad, remaining);
    }
}

// file encryption and decryption logic
void encrypt_file(const char* input_path, const char* output_path) {
    FILE* input_file = fopen(input_path, "rb");
    FILE* output_file = fopen(output_path, "wb");

    if (!input_file || !output_file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    
    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    unsigned char* file_contents = (unsigned char*)malloc(file_size);
    fread(file_contents, 1, file_size, input_file);

    for (int i = 0; i < file_size / 8; i++) {
        madryga_encrypt_data(file_contents + i * 8, 8);
    }

    fwrite(file_contents, 1, file_size, output_file);

    fclose(input_file);
    fclose(output_file);
    free(file_contents);
}

void decrypt_file(const char* input_path, const char* output_path) {
    FILE* input_file = fopen(input_path, "rb");
    FILE* output_file = fopen(output_path, "wb");

    if (!input_file || !output_file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    unsigned char* file_contents = (unsigned char*)malloc(file_size);
    fread(file_contents, 1, file_size, input_file);

    for (int i = 0; i < file_size / 8; i++) {
        madryga_decrypt_data(file_contents + i * 8, 8);
    }

    fwrite(file_contents, 1, file_size, output_file);

    fclose(input_file);
    fclose(output_file);
    free(file_contents);
}

int main() {
    encrypt_file("test.txt", "test-encrypted.bin");
    Sleep(30000); // wait 30 seconds
    decrypt_file("test-encrypted.bin", "test-decrypted.txt");
    return 0;
}