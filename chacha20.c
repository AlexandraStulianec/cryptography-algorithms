#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Left rotate a 32-bit integer by b bits
#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

// ChaCha quarter round function
#define QR(a, b, c, d) ( \
    a += b, d ^= a, d = ROTL(d, 16), \
    c += d, b ^= c, b = ROTL(b, 12), \
    a += b, d ^= a, d = ROTL(d, 8), \
    c += d, b ^= c, b = ROTL(b, 7))
#define ROUNDS 20  // Standard number of ChaCha rounds

// Context holds ChaCha state matrix (16 words)
typedef struct {
    uint32_t input[16];
} chacha20_ctx;

// Generate one ChaCha20 keystream block (64 bytes)
void chacha20_block(chacha20_ctx *ctx, uint8_t output[64]) {
    uint32_t x[16];
    int i;
    
    // Copy internal state to working state
    for (i = 0; i < 16; ++i) {
        x[i] = ctx->input[i];
    }
    
    // Apply 20 rounds: 10 column + 10 diagonal rounds
    for (i = 0; i < ROUNDS; i += 2) {
        // Column rounds
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        
        // Diagonal rounds
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    
    // Add the original input back to the working state and serialize to output
    for (i = 0; i < 16; ++i) {
        x[i] += ctx->input[i];
        output[4 * i + 0] = (x[i] >> 0) & 0xff;
        output[4 * i + 1] = (x[i] >> 8) & 0xff;
        output[4 * i + 2] = (x[i] >> 16) & 0xff;
        output[4 * i + 3] = (x[i] >> 24) & 0xff;
    }
}

// Initialize ChaCha20 state with key and nonce
void chacha20_init(chacha20_ctx *ctx, const uint8_t key[32], const uint8_t nonce[12]) {
    const char *constants = "expand 32-byte k";
    
    // Load constant (constants) into state
    for (int i = 0; i < 4; ++i) {
        ctx->input[i] = ((uint32_t)(uint8_t)constants[i * 4]) |
                        ((uint32_t)(uint8_t)constants[i * 4 + 1] << 8) |
                        ((uint32_t)(uint8_t)constants[i * 4 + 2] << 16) |
                        ((uint32_t)(uint8_t)constants[i * 4 + 3] << 24);
    }

    // Load 256-bit key into state
    for (int i = 0; i < 8; ++i) {
        ctx->input[4 + i] = ((uint32_t)key[i * 4]) |
                            ((uint32_t)key[i * 4 + 1] << 8) |
                            ((uint32_t)key[i * 4 + 2] << 16) |
                            ((uint32_t)key[i * 4 + 3] << 24);
    }

    // Initialize 64-bit counter to 0
    ctx->input[12] = 0;
    ctx->input[13] = 0;

    // Load 96-bit nonce into last 3 state words
    for (int i = 0; i < 3; ++i) {
        ctx->input[14 + i] = ((uint32_t)nonce[i * 4]) |
                             ((uint32_t)nonce[i * 4 + 1] << 8) |
                             ((uint32_t)nonce[i * 4 + 2] << 16) |
                             ((uint32_t)nonce[i * 4 + 3] << 24);
    }
}

// Encrypt or decrypt data using ChaCha20
void chacha20_crypt(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t block[64]; // Keystream block
    size_t i, block_pos = 0; // Position in block
    
    for (i = 0; i < len; ++i) {
        // Generate new block when needed
        if (block_pos == 0) {
            chacha20_block(ctx, block);

            // Increment 64-bit counter (input[12] and input[13])
            if (++ctx->input[12] == 0) {
                ++ctx->input[13];
            }
        }

        // XOR input byte with keystream byte
        out[i] = in[i] ^ block[block_pos];

        // Move to next byte in block
        block_pos = (block_pos + 1) % 64;
    }
}

// Encrypt or decrypt a file using ChaCha20
void process_file(const char *input_file, const char *output_file, const uint8_t key[32], const uint8_t nonce[12]) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if (!in || !out) {
        perror("File error");
        exit(1);
    }
    
    chacha20_ctx ctx;
    chacha20_init(&ctx, key, nonce);
    
    uint8_t buffer[4096];
    uint8_t output[4096];
    size_t bytes_read;
    
     // Read input, encrypt/decrypt, and write output
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        chacha20_crypt(&ctx, buffer, output, bytes_read);
        fwrite(output, 1, bytes_read, out);
    }
    
    fclose(in);
    fclose(out);
}

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s -e plaintext -k key -o output    (encrypt)\n", prog_name);
    fprintf(stderr, "  %s -d enc_file -k key -o decrypted  (decrypt)\n", prog_name);
    fprintf(stderr, "\nKey file must contain 32 bytes (256 bits)\n");
}

int main(int argc, char *argv[]) {
    int encrypt_mode = -1; /// -1: not set, 0: decrypt, 1: encrypt 2: generate
    char *input_file = NULL;
    char *key_file = NULL;
    char *output_file = NULL;
    int opt;
    
    while ((opt = getopt(argc, argv, "e:d:k:o:")) != -1) {
        switch (opt) {
            case 'e':
                encrypt_mode = 1;
                input_file = optarg;
                break;
            case 'd':
                encrypt_mode = 0;
                input_file = optarg;
                break;
            case 'k':
                key_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (encrypt_mode == -1 || !input_file || !key_file || !output_file) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Read key from file
    uint8_t key[32];
    uint8_t nonce[12] = {0}; // Fixed nonce for simplicity (in real use, should be random)
    
    FILE *kf = fopen(key_file, "rb");
    if (!kf || fread(key, 1, 32, kf) != 32) {
        fprintf(stderr, "Error reading key file (needs exactly 32 bytes)\n");
        if (kf) fclose(kf);
        return 1;
    }
    fclose(kf);
    
    // Process the file
    process_file(input_file, output_file, key, nonce);
    
    printf("Operation completed successfully.\n");
    printf("%s -> %s using key from %s\n", 
           input_file, output_file, key_file);
    
    return 0;
} 