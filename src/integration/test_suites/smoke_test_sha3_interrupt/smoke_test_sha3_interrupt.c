// Copyright lowRISC contributors (OpenTitan project).
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

#include "caliptra_isr.h"
#include "printf.h"
#include "sha3.h"
#include <string.h>

#ifdef CPT_VERBOSITY
  enum printf_verbosity verbosity_g = CPT_VERBOSITY;
#else
  enum printf_verbosity verbosity_g = LOW;
#endif
volatile uint32_t* stdout           = (uint32_t *)STDOUT;
volatile uint32_t  intr_count       = 0;

volatile caliptra_intr_received_s cptra_intr_rcv = {0};

void main() {

    // Entry message
    VPRINTF(LOW, "----------------------------------\n");
    VPRINTF(LOW, " SHA3 smoke test for interrupts!\n"   );
    VPRINTF(LOW, "----------------------------------\n");

    // Call interrupt init
    init_interrupts();

    // Enable FIFO empty interrupt
    lsu_write_32(CLP_KMAC_INTR_ENABLE, KMAC_INTR_ENABLE_FIFO_EMPTY_MASK);

    if (cptra_intr_rcv.sha3_notif == KMAC_INTR_ENABLE_FIFO_EMPTY_MASK) {
        VPRINTF(LOW, "Successfully received interrupt.\n");
        // Write 0xff to STDOUT for TB to terminate test.
        SEND_STDOUT_CTRL(0xff);
        while (1);
    } else {
        // Write 0x1 to STDOUT for TB to fail test.
        SEND_STDOUT_CTRL(0x1);
        while (1);
    }
}
