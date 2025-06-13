// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#include "caliptra_defines.h"
#include "caliptra_isr.h"
#include <string.h>
#include <stdint.h>
#include "printf.h"
#include "sha256.h"

#ifdef CPT_VERBOSITY
  enum printf_verbosity verbosity_g = CPT_VERBOSITY;
#else
  enum printf_verbosity verbosity_g = LOW;
#endif
volatile uint32_t* stdout           = (uint32_t *)STDOUT;
volatile uint32_t  intr_count       = 0;

volatile caliptra_intr_received_s cptra_intr_rcv = {0};

inline uint32_t bitfield_field32_write(uint32_t bitfield,
                                       uint32_t mask,
                                       uint32_t index,
                                       uint32_t value) {
  bitfield &= ~(mask << index);
  bitfield |= (value & mask) << index;
  return bitfield;
}

/**
 * Supported SHA-3 modes of operation.
 */
typedef enum dif_kmac_mode_sha3 {
  /** SHA-3 with 224 bit strength. */
  kDifKmacModeSha3Len224,
  /** SHA-3 with 256 bit strength. */
  kDifKmacModeSha3Len256,
  /** SHA-3 with 384 bit strength. */
  kDifKmacModeSha3Len384,
  /** SHA-3 with 512 bit strength. */
  kDifKmacModeSha3Len512,
} dif_kmac_mode_sha3_t;

/**
 * Digest lengths in 32-bit words.
 */
#define DIGEST_LEN_SHA3_224 (224 / 32)
#define DIGEST_LEN_SHA3_256 (256 / 32)
#define DIGEST_LEN_SHA3_384 (384 / 32)
#define DIGEST_LEN_SHA3_512 (512 / 32)
#define DIGEST_LEN_SHA3_MAX DIGEST_LEN_SHA3_512

/**
 * SHA-3 test description.
 */
typedef struct sha3_test {
  dif_kmac_mode_sha3_t mode;

  const char *message;
  size_t message_len;

  const uint32_t digest[DIGEST_LEN_SHA3_MAX];
  size_t digest_len;
} sha3_test_t;

/**
 * SHA-3 tests.
 */
const sha3_test_t sha3_tests[] = {
    // Examples taken from NIST FIPS-202 Algorithm Test Vectors:
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
    {
        .mode = kDifKmacModeSha3Len224,
        .message = NULL,
        .message_len = 0,
        .digest = {0x42034e6b, 0xb7db6736, 0x45156e3b, 0xabb10e4f, 0x9a7f59d4,
                   0x3f8e071b, 0xc76b5a5b},
        .digest_len = DIGEST_LEN_SHA3_224,
    },
    {
        .mode = kDifKmacModeSha3Len256,
        .message = "\xe7\x37\x21\x05",
        .message_len = 32 / 8,
        .digest = {0x8ab6423a, 0x8cf279b0, 0x52c7a34c, 0x90276f29, 0x78fec406,
                   0xd979ebb1, 0x057f7789, 0xae46401e},
        .digest_len = DIGEST_LEN_SHA3_256,
    },
    {
        .mode = kDifKmacModeSha3Len384,
        .message = "\xa7\x48\x47\x93\x0a\x03\xab\xee\xa4\x73\xe1\xf3\xdc\x30"
                   "\xb8\x88\x15",
        .message_len = 136 / 8,
        .digest = {0x29f9a6db, 0xd6f955fe, 0xc0675f6c, 0xf1823baf, 0xb358cf7b,
                   0x16f35267, 0x3f08165c, 0x78d48fea, 0xf20369ee, 0xd20a827f,
                   0xaf5099dd, 0x00678cb4},
        .digest_len = DIGEST_LEN_SHA3_384,
    },
    {
        .mode = kDifKmacModeSha3Len512,
        .message =
            "\x66\x4e\xf2\xe3\xa7\x05\x9d\xaf\x1c\x58\xca\xf5\x20\x08\xc5\x22"
            "\x7e\x85\xcd\xcb\x83\xb4\xc5\x94\x57\xf0\x2c\x50\x8d\x4f\x4f\x69"
            "\xf8\x26\xbd\x82\xc0\xcf\xfc\x5c\xb6\xa9\x7a\xf6\xe5\x61\xc6\xf9"
            "\x69\x70\x00\x52\x85\xe5\x8f\x21\xef\x65\x11\xd2\x6e\x70\x98\x89"
            "\xa7\xe5\x13\xc4\x34\xc9\x0a\x3c\xf7\x44\x8f\x0c\xae\xec\x71\x14"
            "\xc7\x47\xb2\xa0\x75\x8a\x3b\x45\x03\xa7\xcf\x0c\x69\x87\x3e\xd3"
            "\x1d\x94\xdb\xef\x2b\x7b\x2f\x16\x88\x30\xef\x7d\xa3\x32\x2c\x3d"
            "\x3e\x10\xca\xfb\x7c\x2c\x33\xc8\x3b\xbf\x4c\x46\xa3\x1d\xa9\x0c"
            "\xff\x3b\xfd\x4c\xcc\x6e\xd4\xb3\x10\x75\x84\x91\xee\xba\x60\x3a"
            "\x76",
        .message_len = 1160 / 8,
        .digest = {0xf15f82e5, 0xd570c0a3, 0xe7bb2fa5, 0x444a8511, 0x5f295405,
                   0x69797afb, 0xd10879a1, 0xbebf6301, 0xa6521d8f, 0x13a0e876,
                   0x1ca1567b, 0xb4fb0fdf, 0x9f89bc56, 0x4bd127c7, 0x322288d8,
                   0x4e919d54},
        .digest_len = DIGEST_LEN_SHA3_512,
    },
};

/**
 * Supported SHAKE modes of operation.
 */
typedef enum dif_kmac_mode_shake {
  /** SHAKE with 128 bit strength. */
  kDifKmacModeShakeLen128,
  /** SHAKE with 256 bit strength. */
  kDifKmacModeShakeLen256,
} dif_kmac_mode_shake_t;

#define DIGEST_LEN_SHAKE_MAX 102

/**
 * SHAKE test description.
 */
typedef struct shake_test {
  dif_kmac_mode_shake_t mode;

  const char *message;
  size_t message_len;

  const uint32_t digest[DIGEST_LEN_SHAKE_MAX];
  size_t digest_len;
} shake_test_t;

/**
 * SHAKE tests.
 */
// Examples generated using a custom Go program importing package
// `golang.org/x/crypto/sha3`
const shake_test_t shake_tests[] = {
    {
        .mode = kDifKmacModeShakeLen128,
        .message = "OpenTitan",
        .message_len = 9,
        .digest = {0x235a6522, 0x3bd735ac, 0x77832247, 0xc6b12919, 0xfb80eff0,
                   0xb8308a5a, 0xcb25db1f, 0xc5ce4cf2, 0x349730fc, 0xcedf024c,
                   0xff0eefec, 0x6985fe35, 0x3c46a736, 0x0084044b, 0x6d9f9920,
                   0x7c0ab055, 0x19d1d3ce, 0xb4353949, 0xfe8ffbcd, 0x5a7f2ec6,
                   0xc3cf795f, 0xa56d0d7b, 0x520c3358, 0x11237ec9, 0x4ca5ed53,
                   0x2999edc0, 0x6c59c68f, 0x54d9890c, 0x89a33092, 0xf406c674,
                   0xe2b4ebf1, 0x14e68bb2, 0x898ceb72, 0x1878875f, 0x9d7bb8d2,
                   0x268e4a5a, 0xe5da510f, 0x97e5d3bc, 0xaae1b7bc, 0xa337f70b,
                   0xeae3cc65, 0xb8429058, 0xe4319c08, 0xd35e2786, 0xbc99af6e,
                   0x19a04aa8, 0xccbf18bf, 0xf681ebd4, 0x3d6da575, 0x2f0b9406},
        .digest_len = 1600 / 8 / 4,  // Rate (r) is 42 words.
    },
    {
        .mode = kDifKmacModeShakeLen256,
        .message = "OpenTitan",
        .message_len = 9,
        .digest = {0x6a0faccd, 0xbf29cb1a, 0xb631f604, 0xdbcab36,  0xa15d167b,
                   0x18dc668b, 0x272e411b, 0x865e651a, 0x8abedb2a, 0x8db38e78,
                   0xe503c9a2, 0xe64faca9, 0xcbd867d0, 0xdba6f20f, 0xbe129db9,
                   0x842dc15c, 0x1406410b, 0x014ce621, 0x5d24eaf2, 0x63bdf816,
                   0xfb236f50, 0xbdba910c, 0xf4ba0e9a, 0x74b5a51f, 0xd644dffd,
                   0xcd650165, 0xe4ec5e7d, 0x64df5448, 0xdcf7b5e7, 0x68709c07,
                   0x47eed1db, 0xc1e55b24, 0x3c02fad9, 0xd72db62e, 0xc5a48eaf,
                   0xd14bb0c4, 0x0f7143ba, 0x4071b63e, 0x21f0ec4b, 0x41065039,
                   0x1b3e41c0, 0xd0d3b1d0, 0xca16acb9, 0xa06f55aa, 0x7bc7ce75,
                   0x08da25ce, 0x596a654b, 0x0b57ae54, 0x4b88c863, 0x199202d7,
                   0x88c112b6, 0xf6dc4a95, 0xe1cfeffa, 0xa7809e6f, 0x3a796dcd,
                   0xb5962e44, 0x179d6ff0, 0xc898c5a9, 0xd3f02195, 0x43623028,
                   0x4c3a4fe7, 0x2fab7bda, 0x04e5b4d4, 0xe0420692, 0x32fcaa2a,
                   0x05e92f07, 0xba0564ea, 0x7b169778, 0x61d4ca3e, 0x4a5d92ec,
                   0x079cb3ba, 0x9a784e40, 0x6381498c, 0xed6d8b6a, 0x2be74d42,
                   0xa234a3db, 0x60d10de8, 0xf0c77dda, 0xc8f94b72, 0x239a2bdf,
                   0xbfeba4a6, 0xc91042e9, 0xa5a11310, 0x8b44d66a, 0xea9bff2f,
                   0x441a445f, 0xe88ee35d, 0x89386c12, 0x1a8de11e, 0x46aff650,
                   0x423323c9, 0xba7b8db4, 0x06c36eb0, 0x4fd75b36, 0xf0c70001,
                   0x0aefb1df, 0x6ae399e6, 0xf71930a6, 0xdef2206,  0x5ce2a640,
                   0x6a82fcf4, 0xa91b0815},
        .digest_len = 3264 / 8 / 4,  // Rate (r) is 34 words.
    },
};

/**
 * A KMAC operation state context.
 */
typedef struct dif_kmac_operation_state {
  /**
   * Whether the 'squeezing' phase has been started.
   */
  bool squeezing;

  /**
   * Flag indicating whether the output length (d) should be right encoded in
   * software and appended to the end of the message. The output length is
   * required to be appended to the message as part of a KMAC operation.
   */
  bool append_d;

  /**
   * Offset into the output state.
   */
  size_t offset;

  /**
   * The rate (r) in 32-bit words.
   */
  size_t r;

  /**
   * The output length (d) in 32-bit words.
   *
   * If the output length is not fixed then this field will be set to 0.
   *
   * Note: if the output length is fixed length will be modified to ensure that
   * `d - offset` always accurately reflects the number of words remaining.
   */
  size_t d;
} dif_kmac_operation_state_t;

/**
 * Poll until a given flag in the status register is set.
 *
 * @param kmac A KMAC handle.
 * @param flag the
 * @return The result of the operation.
 */
void dif_kmac_poll_status(const void *kmac, uint32_t flag) {
  while (1) {
    uint32_t reg = lsu_read_32(kmac + KMAC_STATUS_REG_OFFSET);
    if (reg & (0x1u << flag)) {
      break;
    }
  }
  return;
}

/**
 * Start a SHA-3 operation.
 *
 * SHA-3 operations have a fixed output length.
 *
 * See NIST FIPS 202 [1] for more information about SHA-3.
 *
 * @param kmac A KMAC handle.
 * @param operation_state A KMAC operation state context.
 * @param mode The SHA-3 mode of operation.
 * @return The result of the operation.
 */
void dif_kmac_mode_sha3_start(
    const void *kmac, dif_kmac_operation_state_t *operation_state,
    dif_kmac_mode_sha3_t mode) {
  if (kmac == NULL || operation_state == NULL) {
    printf("dif_kmac_mode_sha3_start: ERROR kmac or operation_state null.\n");
    while(1);
    return;
  }

  // Set key strength and calculate rate (r) and digest length (d) in 32-bit
  // words.
  uint32_t kstrength;
  switch (mode) {
    case kDifKmacModeSha3Len224:
      kstrength = KMAC_CFG_SHADOWED_KSTRENGTH_VALUE_L224;
      operation_state->offset = 0;
      operation_state->r = calculate_rate_bits(224) / 32;
      operation_state->d = 224 / 32;
      break;
    case kDifKmacModeSha3Len256:
      kstrength = KMAC_CFG_SHADOWED_KSTRENGTH_VALUE_L256;
      operation_state->offset = 0;
      operation_state->r = calculate_rate_bits(256) / 32;
      operation_state->d = 256 / 32;
      break;
    case kDifKmacModeSha3Len384:
      kstrength = KMAC_CFG_SHADOWED_KSTRENGTH_VALUE_L384;
      operation_state->offset = 0;
      operation_state->r = calculate_rate_bits(384) / 32;
      operation_state->d = 384 / 32;
      break;
    case kDifKmacModeSha3Len512:
      kstrength = KMAC_CFG_SHADOWED_KSTRENGTH_VALUE_L512;
      operation_state->offset = 0;
      operation_state->r = calculate_rate_bits(512) / 32;
      operation_state->d = 512 / 32;
      break;
    default:
      printf("dif_kmac_sha3_start: ERROR Unsupported mode.\n");
      while(1);
      return;
  }

  // Hardware must be idle to start an operation.
  if (!is_state_idle(kmac)) {
    printf("dif_kmac_sha3_start: ERROR hardware must be idle.\n");
    while(1);
    return;
  }

  operation_state->squeezing = false;
  operation_state->append_d = false;

  // Configure SHA-3 mode with the given strength.
  lsu_write_32(kmac + KMAC_CFG_SHADOWED_REG_OFFSET,
               ((kstrength << 1) & 0xE) |
               ((KMAC_CFG_SHADOWED_MODE_VALUE_SHA3 << 4) | 0x30));

  // Issue start command.
  uint32_t cmd_reg =
      bitfield_field32_write(0, KMAC_CMD_CMD_FIELD, KMAC_CMD_CMD_VALUE_START);
  lsu_write_32(kmac + KMAC_CMD_REG_OFFSET,
               ((KMAC_CMD_CMD_VALUE_START << 0) & 0x3F));

  // Poll until the status register is in the 'absorb' state.
  return dif_kmac_poll_status(kmac, KMAC_STATUS_SHA3_ABSORB_BIT);
}

/**
 * Absorb bytes from the message provided.
 *
 * If `processed` is non-NULL, then this function will write the remaining
 * space in the FIFO and update `processed` with the number of bytes written.
 * The caller should adjust the `msg` pointer and `len` parameters and call
 * again as needed until all input has been written.
 *
 * If `processed` is NULL, then this function will block until the entire
 * message has been processed or an error occurs.
 *
 * If big-endian mode is enabled for messages (`message_big_endian`) only the
 * part of the message aligned to 32-bit word boundaries will be byte swapped.
 * Unaligned leading and trailing bytes will be written into the message as-is.
 *
 * @param kmac A KMAC handle.
 * @param operation_state A KMAC operation state context.
 * @param msg Pointer to data to absorb.
 * @param len Number of bytes of data to absorb.
 * @param[out] processed Number of bytes processed (optional).
 * @preturn The result of the operation.
 */
void dif_kmac_absorb(
    const void *kmac, dif_kmac_operation_state_t *operation_state,
    const void *msg, size_t len, size_t *processed);


/**
 * Squeeze bytes into the output buffer provided.
 *
 * Requesting a squeeze operation will prevent any further absorption operations
 * from taking place.
 *
 * If `kDifKmacIncomplete` is returned then the hardware is currently
 * recomputing the state and the output was only partially written. The output
 * pointer and length should be updated according to the number of bytes
 * processed and the squeeze operation continued at a later time.
 *
 * If `processed` is not provided then this function will block until `len`
 * bytes have been written to `out` or an error occurs.
 *
 * Normally, the capacity part of Keccak state is and should not be read
 * as part of a regular cryptographic operation. However, this function
 * can also read the capacity for testing purposes.
 * When `capacity` is a non-NULL pointer, at the end of the operation, the
 * capacity part of the Keccak state is also read and written into this buffer.
 * The capacity is read for each output round, meaning that if the requested
 * digest is larger than a single Keccak round can provide (i.e. the rate), then
 * the additional rounds also update this buffer. Hence it should be large
 * enough to accommodate `ceil(digest_len/rate_len) * capacity_len`.
 * `capacity` can be set to NULL to skip reading the capacity.
 *
 * @param kmac A KMAC handle.
 * @param operation_state A KMAC operation state context.
 * @param[out] out Pointer to output buffer.
 * @param[out] len Number of 32-bit words to write to output buffer.
 * @param[out] processed Number of 32-bit words written to output buffer
 * (optional).
 * @param[out] capacity Optional buffer to read capacity along with the digest.
 * @preturn The result of the operation.
 */
void dif_kmac_squeeze(
    const void *kmac, dif_kmac_operation_state_t *operation_state,
    uint32_t *out, size_t len, size_t *processed, uint32_t *capacity);

/**
 * Ends a squeeze operation and resets the hardware so it is ready for a new
 * operation.
 *
 * @param kmac A KMAC handle.
 * @param operation_state A KMAC operation state context.
 * @return The result of the operation.
 */
void dif_kmac_end(
    const void *kmac, dif_kmac_operation_state_t *operation_state);
/**
 * Run SHA-3 test cases using single blocking absorb/squeeze operations.
 */
void run_sha3_test(const void *kmac) {
  dif_kmac_operation_state_t operation_state;
  for (int i = 0; i < ARRAYSIZE(sha3_tests); ++i) {
    sha3_test_t test = sha3_tests[i];

    dif_kmac_mode_sha3_start(kmac, &operation_state, test.mode);
    if (test.message_len > 0) {
      dif_kmac_absorb(kmac, &operation_state, test.message,
                      test.message_len, NULL);
    }
    uint32_t out[DIGEST_LEN_SHA3_MAX];
    if (DIGEST_LEN_SHA3_MAX < test.digest_len) {
      printf("test.digest_len (%d) is greater than DIGEST_LEN_SHA3_MAX.\n", test.digest_len);
      while(1);
    }
    dif_kmac_squeeze(kmac, &operation_state, out, test.digest_len,
                     /*processed=*/NULL, /*capacity=*/NULL));
    dif_kmac_end(kmac, &operation_state);

    // Wait for the hardware engine to actually finish. On FPGA, it may take
    // a while until the DONE command gets actually executed (see SecCmdDelay
    // SystemVerilog parameter).
    dif_kmac_poll_status(kmac, KMAC_STATUS_SHA3_IDLE_BIT);

    for (int j = 0; j < test.digest_len; ++j) {
      if (out[j] != test.digest[j]) {
        printf("test %d: mismatch at %d got=0x%x want=0x%x", i, j, out[j], test.digest[j]);
        while(1);
      }
    }
  }
}

void main() {

  // Entry message
  VPRINTF(LOW, "----------------------------------\n");
  VPRINTF(LOW, " SHA3 smoke test!\n"                 );
  VPRINTF(LOW, "----------------------------------\n");

  // Call interrupt init
  init_interrupts();

  VPRINTF("Running SHA3 tests.\n");
  run_sha3_test();

  //TODO remove
  //sha256_flow(sha256_block, SHA256_MODE_SHA_256, 0, 0, 0, sha256_digest);
  //sha256_zeroize();

  // Write 0xff to STDOUT for TB to terminate test.
  SEND_STDOUT_CTRL( 0xff);
  while(1);

}
