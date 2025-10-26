//./salsa20 -e excel.xls -o encrypted.bin -k key.txt -encryption part
//./salsa20 -d encrypted.bin -o output.xls -k key.txt -decryption part
// ./salsa20 -g Generated new 256-bit key in key.txt

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b)))) // Rotate left
#define QR(a, b, c, d) ( \
    b ^= ROTL(a + d, 7), \
    c ^= ROTL(b + a, 9), \
    d ^= ROTL(c + b, 13), \
    a ^= ROTL(d + c, 18))  // Quarter-round function 
#define ROUNDS 20  // Total Salsa20 rounds (10 double rounds)

typedef struct {
    uint32_t input[16]; // State input matrix
} salsa20_ctx;


void salsa20_block(salsa20_ctx *ctx, uint8_t output[64]) {
    uint32_t x[16];
    int i;
    
    // Copy input matrix to working array
    for (i = 0; i < 16; ++i) {
        x[i] = ctx->input[i];
    }
    
    // Perform 10 double-rounds (20 rounds total)
    for (i = 0; i < ROUNDS; i += 2) {
        // Column rounds
        QR(x[0], x[4], x[8], x[12]);
        QR(x[5], x[9], x[13], x[1]);
        QR(x[10], x[14], x[2], x[6]);
        QR(x[15], x[3], x[7], x[11]);
        
        // Row rounds
        QR(x[0], x[1], x[2], x[3]);
        QR(x[5], x[6], x[7], x[4]);
        QR(x[10], x[11], x[8], x[9]);
        QR(x[15], x[12], x[13], x[14]);
    }
    
    // Add original input and serialize to output buffer
    for (i = 0; i < 16; ++i) {
        x[i] += ctx->input[i];
        output[4 * i + 0] = (x[i] >> 0) & 0xff;
        output[4 * i + 1] = (x[i] >> 8) & 0xff;
        output[4 * i + 2] = (x[i] >> 16) & 0xff;
        output[4 * i + 3] = (x[i] >> 24) & 0xff;
    } 
}

//Helper to Convert 4 Bytes to 32-bit
static inline uint32_t pack32(const uint8_t *b) {
    return ((uint32_t)b[0]) |
           ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

//Set Fixed Constants
static void set_constants(uint32_t *input, const uint8_t *constants) {
    input[0]  = pack32(constants + 0);
    input[5]  = pack32(constants + 4);
    input[10] = pack32(constants + 8);
    input[15] = pack32(constants + 12);
}

//Load 256-bit Key + 64-bit Nonce + 64-bit Counter
static void load_key_and_nonce(salsa20_ctx *ctx, const uint8_t *key, const uint8_t *nonce) {
    // First half of the key - Load key into state
    ctx->input[1] = pack32(key + 0);
    ctx->input[2] = pack32(key + 4);
    ctx->input[3] = pack32(key + 8);
    ctx->input[4] = pack32(key + 12);

    // Nonce (first 8 bytes of IV)
    ctx->input[6] = pack32(nonce + 0);
    ctx->input[7] = pack32(nonce + 4);

    // Counter initialized to 0
    ctx->input[8] = 0;
    ctx->input[9] = 0;

    // Second half of the key
    ctx->input[11] = pack32(key + 16);
    ctx->input[12] = pack32(key + 20);
    ctx->input[13] = pack32(key + 24);
    ctx->input[14] = pack32(key + 28);
}

//Initialize Salsa20 with Key + Nonce
void salsa20_init(salsa20_ctx *ctx, const uint8_t key[32], const uint8_t nonce[8]) {
    const uint8_t sigma[16] = "expand 32-byte k"; //Salsa20 Constant

    set_constants(ctx->input, sigma);
    load_key_and_nonce(ctx, key, nonce);
}

//Encrypt/Decrypt Buffer Using Generated Keystream (CTR Mode)
void salsa20_crypt(salsa20_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t block[64];
    size_t i, block_pos = 0;
    
    for (i = 0; i < len; ++i) {
         // Generate new keystream block every 64 bytes
        if (block_pos == 0) {
            salsa20_block(ctx, block);

             // Increment counter
            if (++ctx->input[8] == 0) {
                ++ctx->input[9]; // Carry to high 32 bits
            }
        }

        // XOR input with keystream
        out[i] = in[i] ^ block[block_pos];
        block_pos = (block_pos + 1) % 64;
    }
}


//Key Generation Helpers
void generate_random_bytes(uint8_t *buf, size_t len) {
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < len; ++i) {
        buf[i] = rand() % 256;
    }
}

void generate_random_key(const char *key_file) {
    FILE *kf = fopen(key_file, "wb");
    if (!kf) {
        perror("Failed to create key file");
        exit(1);
    }

    uint8_t key[32];
    generate_random_bytes(key, 32);

    fwrite(key, 1, 32, kf);
    fclose(kf);
    printf("Generated new 256-bit key in %s\n", key_file);
}

//File Encrypt/Decrypt (Nonce Handling)
void process_file(const char *input_file, const char *output_file, const uint8_t key[32], int encrypt_mode) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if (!in || !out) {
        perror("File error");
        exit(1);
    }

    uint8_t nonce[8];
    salsa20_ctx ctx;

    if (encrypt_mode) { 
        generate_random_bytes(nonce, 8); // Random nonce for CTR
        fwrite(nonce, 1, 8, out);        // Write nonce at start -  Save nonce in output
        salsa20_init(&ctx, key, nonce);    
    } else {
        // Read nonce from beginning of encrypted file
        if (fread(nonce, 1, 8, in) != 8) {
            fprintf(stderr, "Failed to read nonce from input file\n");
            exit(1);
        }
        salsa20_init(&ctx, key, nonce);
    }

    uint8_t buffer[4096];
    uint8_t output[4096];
    size_t bytes_read;

    // Encrypt/decrypt in chunks
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        salsa20_crypt(&ctx, buffer, output, bytes_read);
        fwrite(output, 1, bytes_read, out);
    }

    fclose(in);
    fclose(out);
}


void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s -e plaintext [-k key.txt] [-o encrypted.txt]  (encrypt)\n", prog_name);
    fprintf(stderr, "  %s -d encrypted.bin -k key.txt [-o decrypted.txt]  (decrypt)\n", prog_name);
    fprintf(stderr, "  %s -g  (generate new key.txt)\n", prog_name);
    fprintf(stderr, "\nDefaults:\n");
    fprintf(stderr, "  -o encrypted.txt for encryption\n");
    fprintf(stderr, "  -o decrypted.txt for decryption\n");
    fprintf(stderr, "  -k key.txt for key file\n");
}

int main(int argc, char *argv[]) {
    int encrypt_mode = -1;  
    char *input_file = NULL;
    char *key_file = "key.txt";
    char *output_file = NULL;
    int opt;

     // Parse command-line options
    while ((opt = getopt(argc, argv, "e:d:k:o:g")) != -1) {
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
            case 'g':
                generate_random_key("key.txt");
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }


    // Ensure required args are provided
    if (encrypt_mode == -1 || input_file == NULL || output_file == NULL) {
        print_usage(argv[0]);
        return 1;
    }

    // Load key from file or generate
    uint8_t key[32];
    FILE *kf = fopen(key_file, "rb");
    if (!kf) {
        fprintf(stderr, "Key file not found. Generating new key.txt...\n");
        generate_random_key("key.txt");
        kf = fopen("key.txt", "rb");
        if (!kf) {
            perror("Failed to open generated key file");
            return 1;
        }
    }

    if (fread(key, 1, 32, kf) != 32) {
        fprintf(stderr, "Invalid key size (needs exactly 32 bytes)\n");
        fclose(kf);
        return 1;
    }
    fclose(kf);

    process_file(input_file, output_file, key, encrypt_mode);

    printf("Operation completed successfully.\n");
    printf("%s -> %s using key from %s\n", input_file, output_file, key_file);

    return 0;
} 