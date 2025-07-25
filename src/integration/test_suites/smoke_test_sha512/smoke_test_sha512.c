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
#include "sha512.h"

#ifdef CPT_VERBOSITY
    enum printf_verbosity verbosity_g = CPT_VERBOSITY;
#else
    enum printf_verbosity verbosity_g = LOW;
#endif
volatile uint32_t* stdout           = (uint32_t *)STDOUT;
volatile uint32_t  intr_count       = 0;

volatile caliptra_intr_received_s cptra_intr_rcv = {0};


void main() {

    uint32_t block_data[] = {0x61626380,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000000,
                             0x00000018};

    uint32_t expected_digest[] =   {0xDDAF35A1,
                                    0x93617ABA,
                                    0xCC417349,
                                    0xAE204131,
                                    0x12E6FA4E,
                                    0x89A97EA2,
                                    0x0A9EEEE6,
                                    0x4B55D39A,
                                    0x2192992A,
                                    0x274FC1A8,
                                    0x36BA3C23,
                                    0xA3FEEBBD,
                                    0x454D4423,
                                    0x643CE80E,
                                    0x2A9AC94F,
                                    0xA54CA49F};
                                    


    // Entry message
    VPRINTF(LOW, "----------------------------------\n");
    VPRINTF(LOW, " SHA512 smoke test !!\n"             );
    VPRINTF(LOW, "----------------------------------\n");

    // Call interrupt init
    init_interrupts();

    sha512_io sha512_block;
    sha512_io sha512_digest;

    sha512_block.data_size = 32;
    for (int i = 0; i < sha512_block.data_size; i++)
        sha512_block.data[i] = block_data[i];

    sha512_digest.data_size = 16;
    for (int i = 0; i < sha512_digest.data_size; i++)
        sha512_digest.data[i] = expected_digest[i];

    sha512_flow(sha512_block, SHA512_512_MODE, sha512_digest);
    sha512_zeroize();

    // Zeroize SHA512 commands
    VPRINTF(LOW, "Init and Zeroize\n");
    lsu_write_32(CLP_SHA512_REG_SHA512_CTRL,(((1 << SHA512_REG_SHA512_CTRL_INIT_LOW) & SHA512_REG_SHA512_CTRL_INIT_MASK) |
                                             ((0 << SHA512_REG_SHA512_CTRL_NEXT_LOW) & SHA512_REG_SHA512_CTRL_NEXT_MASK) |
                                             ((0 << SHA512_REG_SHA512_CTRL_RESTORE_LOW) & SHA512_REG_SHA512_CTRL_RESTORE_MASK) |
                                             ((1 << SHA512_REG_SHA512_CTRL_ZEROIZE_LOW) & SHA512_REG_SHA512_CTRL_ZEROIZE_MASK)));
    
    // wait for SHA to be ready
    while((lsu_read_32(CLP_SHA512_REG_SHA512_STATUS) & SHA512_REG_SHA512_STATUS_READY_MASK) == 0);
    if ((lsu_read_32(CLP_SHA512_REG_SHA512_STATUS) & SHA512_REG_SHA512_STATUS_VALID_MASK) != 0){
        VPRINTF(LOW, "Wrong command is not detected\n");
        printf("%c", 0x1);
    }

    VPRINTF(LOW, "Next/Restore and Zeroize\n");
    lsu_write_32(CLP_SHA512_REG_SHA512_CTRL,(((0 << SHA512_REG_SHA512_CTRL_INIT_LOW) & SHA512_REG_SHA512_CTRL_INIT_MASK) |
                                             ((1 << SHA512_REG_SHA512_CTRL_NEXT_LOW) & SHA512_REG_SHA512_CTRL_NEXT_MASK) |
                                             ((1 << SHA512_REG_SHA512_CTRL_RESTORE_LOW) & SHA512_REG_SHA512_CTRL_RESTORE_MASK) |
                                             ((1 << SHA512_REG_SHA512_CTRL_ZEROIZE_LOW) & SHA512_REG_SHA512_CTRL_ZEROIZE_MASK)));
    
    // wait for SHA to be ready
    while((lsu_read_32(CLP_SHA512_REG_SHA512_STATUS) & SHA512_REG_SHA512_STATUS_READY_MASK) == 0);
    if ((lsu_read_32(CLP_SHA512_REG_SHA512_STATUS) & SHA512_REG_SHA512_STATUS_VALID_MASK) != 0){
        VPRINTF(LOW, "Wrong command is not detected\n");
        printf("%c", 0x1);
    }
    
    // Write 0xff to STDOUT for TB to terminate test.
    SEND_STDOUT_CTRL( 0xff);
    while(1);

}
