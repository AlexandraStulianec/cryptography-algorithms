#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <gmp.h>

#define MAX_FILE_SIZE (1024 * 1024)  // 1 MB

// Miller-Rabin primality test
/*
 * Probabilistic primality test to check if a number is probably prime.
 * `k` determines the number of rounds, improving confidence.
 */
int is_probably_prime(mpz_t n, int k) {
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, time(NULL)); // Seed random generator

    mpz_t d, n_minus_1, a, x, tmp;
    int r = 0, i, j;

    mpz_inits(d, n_minus_1, a, x, tmp, NULL);
    mpz_sub_ui(n_minus_1, n, 1);
    mpz_set(d, n_minus_1);

     // Write n-1 as 2^r * d
    while (mpz_even_p(d)) {
        mpz_fdiv_q_2exp(d, d, 1);
        r++;
    }

    // Run k rounds of Miller-Rabin test
    for (i = 0; i < k; i++) {
        mpz_urandomm(a, state, n_minus_1); // Random a ∈ [0, n-2]
        mpz_add_ui(a, a, 2);  // a ∈ [2, n-2]

        mpz_powm(x, a, d, n); // x = a^d mod n
        if (mpz_cmp_ui(x, 1) == 0 || mpz_cmp(x, n_minus_1) == 0)
            continue;

        for (j = 0; j < r - 1; j++) {
            mpz_powm_ui(x, x, 2, n); // x = x^2 mod n
            if (mpz_cmp(x, n_minus_1) == 0)
                break;
        }
        if (j == r - 1) return 0;  // composite
    }

    mpz_clears(d, n_minus_1, a, x, tmp, NULL);
    gmp_randclear(state);
    return 1; // Probably prime
}

// Prime Generator
void generate_large_prime(mpz_t prime, int bits) {
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, time(NULL));

    do {
        mpz_urandomb(prime, state, bits);  // Generate random bits
        mpz_setbit(prime, bits - 1);  // Ensure high bit is set
        mpz_setbit(prime, 0);         // Ensure odd
    } while (!is_probably_prime(prime, 40));

    gmp_randclear(state);
}

// Extended Euclidean Algorithm 
/*
 * Computes gcd and Bézout coefficients x, y such that:
 * g = gcd(a, b), and ax + by = g
 */
void egcd(mpz_t g, mpz_t x, mpz_t y, mpz_t a, mpz_t b) {
    if (mpz_cmp_ui(b, 0) == 0) {
        mpz_set(g, a);
        mpz_set_ui(x, 1);
        mpz_set_ui(y, 0);
        return;
    }

    mpz_t x1, y1, q, r, temp;
    mpz_inits(x1, y1, q, r, temp, NULL);
    mpz_fdiv_qr(q, r, a, b);
    egcd(g, x1, y1, b, r);
    mpz_set(x, y1);
    mpz_mul(temp, q, y1);
    mpz_sub(y, x1, temp);
    mpz_clears(x1, y1, q, r, temp, NULL);
}

//  Modular Inverse 
void modinv(mpz_t res, mpz_t a, mpz_t m) {
    mpz_t g, x, y;
    mpz_inits(g, x, y, NULL);
    egcd(g, x, y, a, m);
    if (mpz_cmp_ui(g, 1) != 0) {
        fprintf(stderr, "Modular inverse does not exist.\n");
        exit(1);
    } else {
        mpz_mod(res, x, m);
    }
    mpz_clears(g, x, y, NULL);
}

//  RSA Encryption 
void rsa_encrypt_decrypt(const char *input_file, const char *output_file, mpz_t exp, mpz_t n) {
    FILE *fin = fopen(input_file, "rb");
    if (!fin) { perror("Input file"); exit(1); }

    FILE *fout = fopen(output_file, "wb");
    if (!fout) { perror("Output file"); exit(1); }

    unsigned char buffer[MAX_FILE_SIZE];
    size_t len = fread(buffer, 1, MAX_FILE_SIZE, fin);  // Read entire file
    fclose(fin);

    for (size_t i = 0; i < len; ++i) {
        mpz_t m, c;
        mpz_inits(m, c, NULL);
        mpz_set_ui(m, buffer[i]);               // Convert byte to integer
        mpz_powm(c, m, exp, n);                 // c = m^e mod n
        gmp_fprintf(fout, "%Zx\n", c);          // Write ciphertext in hex
        mpz_clears(m, c, NULL);
    }

    fclose(fout);
}

//  RSA Decryption 
void rsa_decrypt_file(const char *input_file, const char *output_file, mpz_t d, mpz_t n) {
    FILE *fin = fopen(input_file, "r");
    if (!fin) { perror("Input file"); exit(1); }

    FILE *fout = fopen(output_file, "wb");
    if (!fout) { perror("Output file"); exit(1); }

    mpz_t c, m;
    mpz_inits(c, m, NULL);
    char line[4096];

    while (fgets(line, sizeof(line), fin)) {
        mpz_set_str(c, line, 16);          // Read hex ciphertext
        mpz_powm(m, c, d, n);              // m = c^d mod n
        fputc((unsigned char)mpz_get_ui(m), fout);  // Write byte
    }

    mpz_clears(c, m, NULL);
    fclose(fin);
    fclose(fout);
}

//  Main Function 
int main(int argc, char *argv[]) {
    if (argc != 7) {
        printf("Usage:\n");
        printf("  %s -e <input_file> -o <encrypted_file> -k <key_file>\n", argv[0]);
        printf("  %s -d <encrypted_file> -o <decrypted_file> -k <key_file>\n", argv[0]);
        return 1;
    }

    char *input_file = NULL, *output_file = NULL, *key_file = NULL;
    int encrypt = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0) {
            encrypt = 1;
            input_file = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0) {
            encrypt = 0;
            input_file = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0) {
            key_file = argv[++i];
        }
    }

    if (!input_file || !output_file || !key_file || encrypt == -1) {
        fprintf(stderr, "Invalid arguments.\n");
        return 1;
    }

    // Initialize RSA variables
    mpz_t p, q, n, e, d, phi;
    mpz_inits(p, q, n, e, d, phi, NULL);

    if (encrypt) {
        // Generate RSA keys
        generate_large_prime(p, 1024);
        do {
            generate_large_prime(q, 1024);
        } while (mpz_cmp(p, q) == 0); // Ensure p ≠ q

        mpz_mul(n, p, q);  // n = p * q

        mpz_t p1, q1;
        mpz_inits(p1, q1, NULL);
        mpz_sub_ui(p1, p, 1);
        mpz_sub_ui(q1, q, 1);
        mpz_mul(phi, p1, q1);  // phi = (p-1)(q-1)

        mpz_set_ui(e, 65537); // Common public exponent
        modinv(d, e, phi); // d = e⁻¹ mod φ(n)

        mpz_clears(p1, q1, NULL);

        // Save key to file
        FILE *kf = fopen(key_file, "w"); 
        if (!kf) { perror("key file"); exit(1); }
        gmp_fprintf(kf, "%Zx\n%Zx\n%Zx\n", n, e, d);
        fclose(kf);

        // Encrypt the input file
        rsa_encrypt_decrypt(input_file, output_file, e, n);
    } else {
        // Load key from file
        FILE *kf = fopen(key_file, "r");
        if (!kf) { perror("key file"); exit(1); }
        gmp_fscanf(kf, "%Zx\n%Zx\n%Zx\n", n, e, d);
        fclose(kf);

        // Decrypt the input file
        rsa_decrypt_file(input_file, output_file, d, n);
    }

    mpz_clears(p, q, n, e, d, phi, NULL);
    return 0;
}
