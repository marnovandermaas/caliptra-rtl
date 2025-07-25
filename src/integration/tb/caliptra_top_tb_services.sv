// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Western Digital Corporation or its affiliates.
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

// =================== DESCRIPTION ===================
// This module provides supporting functionality that is shared between the standalone
// and UVM benches for caliptra_top.
// This includes the following:
//  - Contains all SRAM exports
//  - Mem init functions (from .hex files, with ECC functionality as applicable)
//  - RV Firmware STDOUT behavior (ASCII dump + sim kill + Error injection + interrupt + security_state)
//  - RV and internal AHB interface monitoring to activity dumps
// The purpose of this module is to centralize identical code that is shared to
// improve maintainability.
// ===================================================

`default_nettype none

`include "common_defines.sv"
`include "config_defines.svh"
`include "caliptra_reg_defines.svh"
`include "caliptra_reg_field_defines.svh"


module caliptra_top_tb_services 
    import soc_ifc_pkg::*;
    import kv_defines_pkg::*;
    import caliptra_top_tb_pkg::*;
#(
    parameter UVM_TB = 0
) (
    input wire logic                   clk,

    input wire logic                   cptra_rst_b,

    // Caliptra Memory Export Interface
    el2_mem_if.veer_sram_sink          el2_mem_export,
    mldsa_mem_if.resp                  mldsa_memory_export,

    //SRAM interface for mbox
    input  wire logic mbox_sram_cs,
    input  wire logic mbox_sram_we,
    input  wire logic [CPTRA_MBOX_ADDR_W-1:0] mbox_sram_addr,
    input  wire logic [CPTRA_MBOX_DATA_AND_ECC_W-1:0] mbox_sram_wdata,
    output wire logic [CPTRA_MBOX_DATA_AND_ECC_W-1:0] mbox_sram_rdata,

    //SRAM interface for imem
    input  wire logic imem_cs,
    input  wire logic [`CALIPTRA_IMEM_ADDR_WIDTH-1:0] imem_addr,
    output logic [`CALIPTRA_IMEM_DATA_WIDTH-1:0] imem_rdata,

    // Security State
    output var security_state_t security_state,

    //Scan mode
    output logic scan_mode,

    // TB Controls
    output var   ras_test_ctrl_t ras_test_ctrl,
    output int   cycleCnt,
    output var   axi_complex_ctrl_t axi_complex_ctrl,

    //Interrupt flags
    output logic int_flag,
    output logic cycleCnt_smpl_en,

    //Reset flags
    output logic assert_hard_rst_flag,
    output logic assert_rst_flag,
    output logic deassert_hard_rst_flag,
    output logic deassert_rst_flag,

    output logic [0:`CLP_OBF_UDS_DWORDS-1][31:0] cptra_uds_tb,
    output logic [0:`CLP_OBF_FE_DWORDS-1] [31:0] cptra_fe_tb,
    output logic [0:`CLP_OBF_KEY_DWORDS-1][31:0] cptra_obf_key_tb

);

   //=========================================================================-
   // Imports
   //=========================================================================-

   //=========================================================================-
   // Parameters
   //=========================================================================-
    localparam SEED_NUM_DWORDS = 8;
    localparam MSG_NUM_DWORDS = 16;
    localparam PRIVKEY_NUM_DWORDS = 1224;
    localparam PRIVKEY_REG_NUM_DWORDS = 32;
    localparam PRIVKEY_REG_RHO_NUM_DWORDS = 8;
    localparam SIGNATURE_H_NUM_DWORDS = 21;
    localparam VERIFY_RES_NUM_DWORDS = 16;


    `ifndef VERILATOR
    int MAX_CYCLES;
    initial begin
        // To use this from the command line, add "+CLP_MAX_CYCLES=<value>"
        // to override the sim timeout
        if ($value$plusargs("CLP_MAX_CYCLES=%d", MAX_CYCLES)) begin
            $info("Received argument +CLP_MAX_CYCLES, with value %d", MAX_CYCLES);
        end
        else begin
            MAX_CYCLES = 20_000_000;
            $info("No argument provided for CLP_MAX_CYCLES, defaulting to %d", MAX_CYCLES);
        end
    end
    `else
    parameter MAX_CYCLES = 20_000_000;
    `endif

    parameter MEMTYPE_LMEM = 3'h1;
    parameter MEMTYPE_DCCM = 3'h2;
    parameter MEMTYPE_ICCM = 3'h3;
    parameter DATA_WIDTH = 32;
    localparam IV_NO = 128 / DATA_WIDTH;

    localparam ICCM_BYTE_SIZE = `RV_ICCM_SIZE*1024; // 256KiB
    localparam ICCM_PRELOADER_WIDTH = 64;
    localparam ICCM_PRELOADER_BYTE_WIDTH = ICCM_PRELOADER_WIDTH/8;
    localparam ICCM_PRELOADER_DEPTH = ICCM_BYTE_SIZE / ICCM_PRELOADER_BYTE_WIDTH;
    localparam ICCM_PRELOADER_ADDR_WIDTH = $clog2(ICCM_PRELOADER_DEPTH);
    localparam DCCM_BYTE_SIZE = `RV_DCCM_SIZE*1024; // 256KiB
    localparam DCCM_PRELOADER_WIDTH = 64;
    localparam DCCM_PRELOADER_BYTE_WIDTH = DCCM_PRELOADER_WIDTH/8;
    localparam DCCM_PRELOADER_DEPTH = DCCM_BYTE_SIZE / DCCM_PRELOADER_BYTE_WIDTH;
    localparam DCCM_PRELOADER_ADDR_WIDTH = $clog2(DCCM_PRELOADER_DEPTH);

   //=========================================================================-
   // Signals
   //=========================================================================-
    logic                       mailbox_write;
    wire [31:0]                 WriteData;
    logic                       mailbox_data_val;
    int                         commit_count;

    logic                       wb_valid;
    logic [4:0]                 wb_dest;
    logic [31:0]                wb_data;

    int                         hex_file_is_empty;
    bit                         flip_bit;

    string                      abi_reg[32]; // ABI register names

    logic [CPTRA_MBOX_DATA_AND_ECC_W-1:0] mbox_sram_wdata_bitflip;
    int cycleCntKillReq;

    int                         cycleCnt_ff;
    int                         rst_cyclecnt = 0;
    int                         wait_time_to_rst;

    logic                       cold_rst; 
    logic                       warm_rst; 
    logic                       timed_warm_rst;
    logic                       prandom_warm_rst; 
    logic                       cold_rst_done;

    logic                       inject_hmac_key;
    logic                       inject_hmac_block;
    logic                       inject_ecc_seed;
    logic                       inject_ecc_privkey;
    logic                       inject_mldsa_seed;
    logic                       inject_random_data;
    logic                       check_pcr_ecc_signing;
    logic                       check_pcr_mldsa_signing;
    logic                       inject_single_msg_for_ecc_mldsa;

    // Decode:
    //  [0] - Single bit, ICCM Error Injection
    //  [1] - Double bit, ICCM Error Injection
    //  [2] - Single bit, DCCM Error Injection
    //  [3] - Double bit, DCCM Error Injection
    veer_sram_error_injection_mode_t sram_error_injection_mode;
    // Decode:
    //  [0] - Single bit, Mailbox Error Injection
    //  [1] - Double bit, Mailbox Error Injection
    logic [1:0]                 inject_mbox_sram_error = 2'b0;

    logic                       set_wdt_timer1_period;
    logic                       set_wdt_timer2_period;
    logic                       reset_wdt_timer_period;

    logic                       inject_zero_sign_r;
    logic                       inject_zero_sign_r_needs_release;
    logic                       inject_zero_sign_s;
    logic                       inject_zero_sign_s_needs_release;
    logic                       inject_invalid_privkey;
    logic                       inject_invalid_privkey_needs_release;
    logic                       inject_invalid_dhkey;
    logic                       inject_invalid_dhkey_needs_release;
    logic                       inject_invalid_pubkeyx;
    logic                       inject_invalid_pubkeyx_needs_release;
    logic                       inject_invalid_pubkeyy;
    logic                       inject_invalid_pubkeyy_needs_release;

    logic                       en_jtag_access;
    logic                       disable_mldsa_sva;

    typedef bit  [0:11][31:0]   operand_t;

    typedef struct packed {
        operand_t   x;
        operand_t   y;
    } affn_point_t;

    typedef struct packed {
        operand_t   X;
        operand_t   Y;
        operand_t   Z;
    } proj_point_t;

    typedef struct packed {
        operand_t     hashed_msg;
        operand_t     privkey;
        affn_point_t  pubkey;
        operand_t     R;
        operand_t     S;
        operand_t     seed;
        operand_t     nonce;
        operand_t     IV;
        operand_t     privkeyB;
        operand_t     dh_sharedkey;
    } ecc_test_vector_t;

    ecc_test_vector_t ecc_test_vector;

    typedef struct packed {
          logic [0:`CLP_OBF_KEY_DWORDS-1][31:0] obf_key_uds;
          logic [0:IV_NO-1][31:0] iv_uds;
          logic [0:`CLP_OBF_UDS_DWORDS-1][31:0] uds_plaintext;
          logic [0:`CLP_OBF_UDS_DWORDS-1][31:0] uds_ciphertext;

          logic [0:`CLP_OBF_KEY_DWORDS-1][31:0] obf_key_fe;
          logic [0:IV_NO-1][31:0] iv_fe;
          logic [0:`CLP_OBF_FE_DWORDS-1] [31:0] fe_plaintext;
          logic [0:`CLP_OBF_FE_DWORDS-1] [31:0] fe_ciphertext;
    } doe_test_vector_t;

    doe_test_vector_t doe_test_vector;

    typedef struct packed {
        //logic [511:0] sha256_wntz_block_tb;
        logic [15:0][31:0] sha256_wntz_block_tb;
        logic [0:7][31:0] sha256_wntz_digest;
        logic wntz_n;
        logic [3:0] wntz_w;
    } sha256_wntz_test_vector_t;

    sha256_wntz_test_vector_t sha256_wntz_test_vector;

    typedef struct packed {
        logic [0:7][31:0] seed;
        logic [0:647][31:0] pubkey;
        logic [0:1223][31:0] privkey;
        logic [0:15][31:0] msg;
        logic [0:1156][31:0] signature;
        logic [0:15][31:0] verify_res;
        logic [0:7][31:0] sign_rnd;
    } mldsa_test_vector_t;

    mldsa_test_vector_t mldsa_test_vector;

    logic inject_makehint_failure, inject_normcheck_failure;
    logic reset_mldsa_failure;
    logic [1:0] normcheck_mode_random;
    logic inject_mldsa_timeout;
    logic random_mldsa_failure_injection;
    function automatic logic [511:0] change_endian(input logic [511:0] data);
        logic [511:0] result;
        for (int i = 0; i < 512; i = i + 8) begin
            result[i +: 8] = data[511 - i -: 8];
        end
        return result;
    endfunction

// Upwards name referencing per 23.8 of IEEE 1800-2017
`define DEC `CPTRA_TOP_PATH.rvtop.veer.dec

`define LMEM mbox_ram1.ram 

   //=========================================================================-
   // STDOUT and Trace Logic
   //=========================================================================-
    // NOTE: This aperture into the mailbox is heavily overloaded right now by
    //       various firmware "STDOUT" use-cases.
    //       Functionality currently implemented at this offset is as follows
    //       (relative to the WriteData used to trigger that function):
    //         8'h0         - Do nothing
    //         8'h1         - Kill the simulation with a Failed status
    //         8'h2 : 8'h5  - Do nothing
    //         8'h6 : 8'h7E - WriteData is an ASCII character - dump to console.log
    //         8'h7F        - Do nothing
    //         8'h80: 8'h87 - Inject ECC_SEED to kv_key register
    //         8'h88        - Toggle recovery interface emulation in AXI complex
    //         8'h89        - Use same msg in SHA512 digest for ECC/MLDSA PCR signing (used where both cryptos are running in parallel)
    //         8'h8a        - Enable FIFO in caliptra_top_tb_axi_complex to auto-read data
    //         8'h8b        - Enable FIFO in caliptra_top_tb_axi_complex to auto-write data
    //         8'h8c        - Disable FIFO in caliptra_top_tb_axi_complex to auto-read data
    //         8'h8d        - Disable FIFO in caliptra_top_tb_axi_complex to auto-write data
    //         8'h8e        - Flush the FIFO in caliptra_top_tb_axi_complex
    //         8'h8f        - Toggle random delays in AXI complex (FIFO and SRAM endpoints)
    //         8'h90        - Issue PCR signing with fixed vector   
    //         8'h91        - Issue PCR ECC signing with randomized vector
    //         8'h92        - Check PCR ECC signing with randomized vector
    //         8'h93        - Issue PCR MLDSA signing with randomized vector   
    //         8'h94        - Check PCR MLDSA signing with randomized vector
    //         8'h97        - Inject invalid dh_key into ECC
    //         8'h98        - Inject invalid zero sign_r into ECC 
    //         8'h99        - Inject zeroize into HMAC
    //         8'h9a        - Inject invalid zero sign_s into ECC 
    //         8'h9b        - Inject zeroize during keyvault read
    //         8'h9c        - Inject invalid privkey/dh_key into ECC
    //         8'h9d        - Inject invalid pubkey_x into ECC
    //         8'h9e        - Inject invalid pubkey_y into ECC
    //         8'ha0: 8'ha7 - Inject HMAC384_KEY to kv_key register
    //         8'ha8        - Inject zero as HMAC_KEY to kv_key register
    //         8'ha9: 8'haf - Inject HMAC512_KEY to kv_key register
    //         8'hb0        - Inject HMAC512_BLOCK to kv_key register
    //         8'hc0: 8'hc7 - Inject MLDSA_SEED to kv_key register
    //         8'hd6        - Inject mldsa timeout
    //         8'hd7        - Inject normcheck or makehint failure during mldsa signing 1st loop. Failure type is selected randomly
    //         8'hd9        - Perform mldsa keygen
    //         8'hda        - Perform mldsa signing
    //         8'hdb        - Perform mldsa verify
    //         8'hdc        - Perform mldsa keygen+signing
    //         8'hdd        - Inject random block input to SHA256 WNTZ module
    //         8'hde        - ICCM SRAM force loop read (requires read params written to other bytes of generic wires)
    //         8'hdf        - DCCM SRAM force loop read (requires read params written to other bytes of generic wires)
    //         8'he0        - Set random ICCM SRAM single bit error injection
    //         8'he1        - Set random ICCM SRAM double bit error injection
    //         8'he2        - Set random DCCM SRAM single bit error injection
    //         8'he3        - Set random DCCM SRAM double bit error injection
    //         8'he4        - Disable all SRAM error injection (Mailbox, ICCM, DCCM)
    //         8'he5        - Request TB to initiate Mailbox flow without lock (violation)
    //         8'he6        - Request TB to initiate Mailbox flow with out-of-order accesses (violation)
    //         8'he7        - Reset mailbox out-of-order flag when non-fatal error is masked (allows the test to continue) [Deprecated]
    //         8'he8        - Enable scan mode when DOE fsm transitions to done state
    //         8'he9        - Force dmi_reg_en input to clk gate to emulate JTAG accesses
    //         8'hea        - Set random values to WDT timer1 and timer2
    //         8'heb        - Inject fatal error
    //         8'hec        - Inject randomized UDS test vector
    //         8'hed        - Inject randomized FE test vector
    //         8'hee        - Issue random warm reset
    //         8'hef        - Enable scan mode
    //         8'hf0        - Disable scan mode
    //         8'hf1        - Release WDT timer periods so they can be set by the test
    //         8'hf2        - Force clk_gating_en (to use in smoke_test only)
    //         8'hf3        - Init PCR slot 31
    //         8'hf4        - Write random data to KV entry0
    //         8'hf5        - Issue cold reset
    //         8'hf6        - Issue warm reset
    //         8'hf7        - Issue warm reset when DOE FSM is done
    //         8'hf8        - Assert interrupt flags at fixed intervals to wake up halted core
    //         8'hf9        - Lock debug in security state
    //         8'hfa        - Unlock debug in security state
    //         8'hfb        - Set the isr_active bit
    //         8'hfc        - Clear the isr_active bit
    //         8'hfd        - Set random Mailbox SRAM single bit error injection
    //         8'hfe        - Set random Mailbox SRAM double bit error injection
    //         8'hff        - End the simulation with a Success status
    assign mailbox_write = `CPTRA_TOP_PATH.soc_ifc_top1.i_soc_ifc_reg.field_combo.CPTRA_GENERIC_OUTPUT_WIRES[0].generic_wires.load_next;
    assign WriteData = `CPTRA_TOP_PATH.soc_ifc_top1.i_soc_ifc_reg.field_combo.CPTRA_GENERIC_OUTPUT_WIRES[0].generic_wires.next;
    assign mailbox_data_val = WriteData[7:0] > 8'h5 && WriteData[7:0] < 8'h7f;

    integer fd, tp, el, sm, i;
    integer ifu_p, lsu_p, sl_p[`CALIPTRA_AHB_SLAVES_NUM];

    integer j;
    string slaveLog_fileName[`CALIPTRA_AHB_SLAVES_NUM];

    logic [7:0] isr_active = 8'h0;
    always @(negedge clk) begin
        if ((WriteData[7:0] == 8'hfc) && mailbox_write) begin
            isr_active--;
        end
        else if ((WriteData[7:0] == 8'hfb) && mailbox_write) begin
            isr_active++;
        end
    end
    always @(negedge clk or negedge cptra_rst_b) begin
        if      (!cptra_rst_b)                               inject_mbox_sram_error <= 2'b00;
        else if ((WriteData[7:0] == 8'hfd) && mailbox_write) inject_mbox_sram_error <= 2'b01;
        else if ((WriteData[7:0] == 8'hfe) && mailbox_write) inject_mbox_sram_error <= 2'b10;
        else if ((WriteData[7:0] == 8'he4) && mailbox_write) inject_mbox_sram_error <= 2'b00;
    end
    always @(negedge clk or negedge cptra_rst_b) begin
        if      (!cptra_rst_b)                               sram_error_injection_mode                       <= '{default: 1'b0};
        else if ((WriteData[7:0] == 8'he0) && mailbox_write) sram_error_injection_mode.iccm_single_bit_error <= 1'b1;
        else if ((WriteData[7:0] == 8'he1) && mailbox_write) sram_error_injection_mode.iccm_double_bit_error <= 1'b1;
        else if ((WriteData[7:0] == 8'he2) && mailbox_write) sram_error_injection_mode.dccm_single_bit_error <= 1'b1;
        else if ((WriteData[7:0] == 8'he3) && mailbox_write) sram_error_injection_mode.dccm_double_bit_error <= 1'b1;
        else if ((WriteData[7:0] == 8'he4) && mailbox_write) sram_error_injection_mode                       <= '{default: 1'b0};
    end

    always @(negedge clk or negedge cptra_rst_b) begin
        if (!cptra_rst_b) begin
            ras_test_ctrl.do_no_lock_access     <= 1'b0;
            ras_test_ctrl.do_ooo_access         <= 1'b0;
        end
        else if((WriteData[7:0] == 8'he5) && mailbox_write) begin
            ras_test_ctrl.do_no_lock_access     <= 1'b1;
            ras_test_ctrl.do_ooo_access         <= 1'b0;
        end
        else if((WriteData[7:0] == 8'he6) && mailbox_write) begin
            ras_test_ctrl.do_no_lock_access     <= 1'b0;
            ras_test_ctrl.do_ooo_access         <= 1'b1;
        end
        else if ((WriteData[7:0] == 8'he7) && mailbox_write) begin
            ras_test_ctrl.do_no_lock_access     <= 1'b0;
            ras_test_ctrl.do_ooo_access         <= 1'b0;
        end
        else begin
            ras_test_ctrl.do_no_lock_access     <= 1'b0;
            ras_test_ctrl.do_ooo_access         <= 1'b0;
        end
    end

    always @(negedge clk or negedge cptra_rst_b) begin
        if (!cptra_rst_b) begin
            ras_test_ctrl.iccm_read_burst.start <= 1'b0;
            ras_test_ctrl.iccm_read_burst.count <=   '0;
            ras_test_ctrl.iccm_read_burst.addr  <=   '0;
            ras_test_ctrl.dccm_read_burst.start <= 1'b0;
            ras_test_ctrl.dccm_read_burst.count <=   '0;
            ras_test_ctrl.dccm_read_burst.addr  <=   '0;
        end
        else if((WriteData[7:0] == 8'hde) && mailbox_write) begin
            ras_test_ctrl.iccm_read_burst.start <= 1'b1;
            ras_test_ctrl.iccm_read_burst.count <= WriteData[31:12];
            ras_test_ctrl.iccm_read_burst.addr  <= `CPTRA_TOP_PATH.soc_ifc_top1.i_soc_ifc_reg.field_storage.CPTRA_GENERIC_OUTPUT_WIRES[1].generic_wires.value;
            ras_test_ctrl.dccm_read_burst.start <= 1'b0;
            ras_test_ctrl.dccm_read_burst.count <=   '0;
            ras_test_ctrl.dccm_read_burst.addr  <=   '0;
        end
        else if((WriteData[7:0] == 8'hdf) && mailbox_write) begin
            ras_test_ctrl.iccm_read_burst.start <= 1'b0;
            ras_test_ctrl.iccm_read_burst.count <=   '0;
            ras_test_ctrl.iccm_read_burst.addr  <=   '0;
            ras_test_ctrl.dccm_read_burst.start <= 1'b1;
            ras_test_ctrl.dccm_read_burst.count <= WriteData[31:12];
            ras_test_ctrl.dccm_read_burst.addr  <= `CPTRA_TOP_PATH.soc_ifc_top1.i_soc_ifc_reg.field_storage.CPTRA_GENERIC_OUTPUT_WIRES[1].generic_wires.value;
        end
        else begin
            ras_test_ctrl.iccm_read_burst.start <= 1'b0;
            ras_test_ctrl.iccm_read_burst.count <=   '0;
            ras_test_ctrl.iccm_read_burst.addr  <=   '0;
            ras_test_ctrl.dccm_read_burst.start <= 1'b0;
            ras_test_ctrl.dccm_read_burst.count <=   '0;
            ras_test_ctrl.dccm_read_burst.addr  <=   '0;
        end
    end

    initial ras_test_ctrl.error_injection_seen = 1'b0;
    always @(negedge clk) begin
        if (mailbox_write && WriteData[7:0] == 8'hfd) begin
            ras_test_ctrl.error_injection_seen <= 1'b1;
        end
    end
    // When starting a new error injection test, reset generic_input wires to the idle value.
    // New values will be loaded to reflect the result of the RAS test.
    initial ras_test_ctrl.reset_generic_input_wires = 1'b0;
    always@(negedge clk) begin
        ras_test_ctrl.reset_generic_input_wires <= mailbox_write && (WriteData[7:0] inside {8'he0, 8'he1, 8'he2, 8'he3, 8'hfd, 8'hfe});
    end

    // AXI Complex Control
    always @(negedge clk or negedge cptra_rst_b) begin
        if (!cptra_rst_b) begin
            axi_complex_ctrl.fifo_auto_push        <= 1'b0;
            axi_complex_ctrl.fifo_auto_pop         <= 1'b0;
            axi_complex_ctrl.fifo_clear            <= 1'b0;
            axi_complex_ctrl.rand_delays           <= 1'b0;
            axi_complex_ctrl.en_recovery_emulation <= 1'b0;
        end
        else if((WriteData[7:0] == 8'h88) && mailbox_write) begin
            axi_complex_ctrl.en_recovery_emulation <= ~axi_complex_ctrl.en_recovery_emulation; // Toggle option
        end
        else if((WriteData[7:0] == 8'h8a) && mailbox_write) begin
            axi_complex_ctrl.fifo_auto_pop  <= 1'b1;
        end
        else if((WriteData[7:0] == 8'h8b) && mailbox_write) begin
            axi_complex_ctrl.fifo_auto_push <= 1'b1;
        end
        else if((WriteData[7:0] == 8'h8c) && mailbox_write) begin
            axi_complex_ctrl.fifo_auto_pop  <= 1'b0;
        end
        else if((WriteData[7:0] == 8'h8d) && mailbox_write) begin
            axi_complex_ctrl.fifo_auto_push <= 1'b0;
        end
        else if((WriteData[7:0] == 8'h8e) && mailbox_write) begin
            axi_complex_ctrl.fifo_clear     <= 1'b1;
        end
        else if((WriteData[7:0] == 8'h8f) && mailbox_write) begin
            axi_complex_ctrl.rand_delays    <= ~axi_complex_ctrl.rand_delays; // Toggle option
        end
        else begin
            axi_complex_ctrl.fifo_clear     <= 1'b0;
        end
    end

    //keyvault injection hooks
    //Inject data to KV key reg
    logic [0:15][31:0]   ecc_seed_tb      = 512'h_8FA8541C82A392CA74F23ED1DBFD73541C5966391B97EA73D744B0E34B9DF59ED0158063E39C09A5A055371EDF7A5441_00000000000000000000000000000000;
    logic [0:15][31:0]   ecc_privkey_tb   = 512'h_F274F69D163B0C9F1FC3EBF4292AD1C4EB3CEC1C5A7DDE6F80C14292934C2055E087748D0A169C772483ADEE5EE70E17_00000000000000000000000000000000;
    logic [0:15][31:0]   hmac384_key_tb   = 512'h_0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b_00000000000000000000000000000000;
    logic [0:15][31:0]   hmac512_key_tb   = 512'h0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b;
    logic [0:15][31:0]   hmac512_block_tb = 512'h_e7f1293c6f23a53289143df1399e784cb71180e3830c3869fd725fe78f0b6480559d6344edc1aaf64b7d0701e78672d2_00000000000000000000000000000000;
    logic [0:15][31:0]   mldsa_seed_tb    = 512'h_2d5cf89c46768a850768f0d4a243fe283fcee4d537071d12675fd1279340000a_55555555555555555555555555555555_00000000000000000000000000000000; //fixme padded with junk
    logic [0:15][31:0]   ecc_privkey_random;
    logic [0:15][31:0]   mldsa_seed_random;
    
    always_comb ecc_privkey_random = {ecc_test_vector.privkey, 128'h_00000000000000000000000000000000};
    always_comb mldsa_seed_random = change_endian({256'h0, mldsa_test_vector.seed});

    genvar dword_i, slot_id;
    generate 
        for (slot_id=0; slot_id < 9; slot_id++) begin : inject_slot_loop
            for (dword_i=0; dword_i < 16; dword_i++) begin : inject_dword_loop
                always @(negedge clk) begin
                    //inject valid seed dest and seed value to key reg
                    if(((WriteData[7:0] & 8'hf8) == 8'h80) && mailbox_write) begin
                        //$system("/home/mojtabab/workspace_aha_poc/ws1/Caliptra/src/ecc/tb/ecdsa_secp384r1.exe");
                        inject_ecc_seed <= 1'b1;
                        if (((WriteData[7:0] & 8'h07) == slot_id)) begin
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.next = 5'b10000;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.next = 'd11;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.next = ecc_seed_tb[dword_i][31 : 0];
                        end
                    end
                    //inject privkey value to key reg
                    else if((WriteData[7:0] == 8'h90) && mailbox_write) begin
                        inject_ecc_privkey <= 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_ECC_SIGNING].dest_valid.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_ECC_SIGNING].dest_valid.next = 5'b1000;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_ECC_SIGNING].last_dword.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_ECC_SIGNING].last_dword.next = 'd11;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[KV_ENTRY_FOR_ECC_SIGNING][dword_i].data.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[KV_ENTRY_FOR_ECC_SIGNING][dword_i].data.next = ecc_privkey_tb[dword_i][31 : 0];

                        inject_mldsa_seed <= 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_MLDSA_SIGNING].dest_valid.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_MLDSA_SIGNING].dest_valid.next = 5'b100;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_MLDSA_SIGNING].last_dword.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_MLDSA_SIGNING].last_dword.next = 'd7;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[KV_ENTRY_FOR_MLDSA_SIGNING][dword_i].data.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[KV_ENTRY_FOR_MLDSA_SIGNING][dword_i].data.next = mldsa_seed_tb[dword_i][31 : 0];
                    end
                    else if((WriteData[7:0] == 8'h91) && mailbox_write) begin
                        inject_ecc_privkey <= 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_ECC_SIGNING].dest_valid.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_ECC_SIGNING].dest_valid.next = 5'b1000;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_ECC_SIGNING].last_dword.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_ECC_SIGNING].last_dword.next = 'd11;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[KV_ENTRY_FOR_ECC_SIGNING][dword_i].data.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[KV_ENTRY_FOR_ECC_SIGNING][dword_i].data.next = ecc_privkey_random[dword_i][31 : 0];
                    end
                    else if((WriteData[7:0] == 8'h93) && mailbox_write) begin
                        inject_mldsa_seed <= 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_MLDSA_SIGNING].dest_valid.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_MLDSA_SIGNING].dest_valid.next = 5'b100;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_MLDSA_SIGNING].last_dword.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[KV_ENTRY_FOR_MLDSA_SIGNING].last_dword.next = 'd7;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[KV_ENTRY_FOR_MLDSA_SIGNING][dword_i].data.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[KV_ENTRY_FOR_MLDSA_SIGNING][dword_i].data.next = mldsa_seed_random[dword_i][31 : 0];
                    end
                    //inject valid hmac_key dest and zero hmac_key value to key reg
                    else if(((WriteData[7:0]) == 8'ha8) && mailbox_write) begin
                        inject_hmac_key <= 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.next = 5'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.next = 'd15;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.we = 1'b1;
                        force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.next = '0;
                    end
                    //inject valid hmac_key dest and hmac384_key value to key reg
                    else if((WriteData[7:0] >= 8'ha0) && (WriteData[7:0] < 8'ha8) && mailbox_write) begin
                        inject_hmac_key <= 1'b1;
                        if (((WriteData[7:0] & 8'h07) == slot_id)) begin
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.next = 5'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.next = 'd11;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.next = hmac384_key_tb[dword_i][31 : 0];
                        end
                    end
                    //inject valid hmac_key dest and hmac512_key value to key reg
                    else if((WriteData[7:0] > 8'ha8) && (WriteData[7:0] <= 8'haf) && mailbox_write) begin
                        inject_hmac_key <= 1'b1;
                        if (((WriteData[7:0] & 8'h07) == slot_id)) begin
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.next = 5'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.next = 'd15;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.next = hmac512_key_tb[dword_i][31 : 0];
                        end
                    end
                    //inject valid hmac_block dest and hmac512_block value to key reg
                    else if((WriteData[7:0] == 8'hb0) && mailbox_write) begin
                        inject_hmac_block <= 1'b1;
                        if (slot_id == 4) begin
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.next = 6'h2;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.next = 'd11;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.next = hmac512_block_tb[dword_i][31 : 0];
                        end
                    end
                    else if((WriteData[7:0] == 8'hf4) && mailbox_write) begin
                        inject_random_data <= '1;
                        if (slot_id == 0) begin
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.we = 'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.next = (32'b10000 << `KV_REG_KEY_CTRL_0_DEST_VALID_LOW);
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.next = 'd11;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.next = $urandom();
                        end
                    end
                    //inject valid mldsa seed dest and mldsa_seed value to key reg
                    else if(((WriteData[7:0] & 8'hf8) == 8'hc0) && mailbox_write) begin
                        inject_mldsa_seed <= 1'b1;
                        if (((WriteData[7:0] & 8'h07) == slot_id)) begin
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.next = 5'b100;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.next = 'd7;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.we = 1'b1;
                            force `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.next = mldsa_seed_tb[dword_i][31 : 0];
                        end
                    end
                    else begin
                        inject_ecc_seed <= '0;
                        inject_ecc_privkey <= '0;
                        inject_hmac_key <= '0;
                        inject_mldsa_seed <= '0;
                        inject_random_data <= '0;
                        inject_hmac_block <= '0;
                        release `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.we;
                        release `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].dest_valid.next;
                        release `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.we;
                        release `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_CTRL[slot_id].last_dword.next;
                        release `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.we;
                        release `CPTRA_TOP_PATH.key_vault1.kv_reg_hwif_in.KEY_ENTRY[slot_id][dword_i].data.next;
                    end
                end
            end // inject_dword_loop
        end // inject_slot_loop
    endgenerate
    

    always@(posedge clk or negedge cptra_rst_b) begin
        if (~cptra_rst_b) begin
            inject_zero_sign_r <= 1'b0;
            inject_zero_sign_r_needs_release <= 1'b0;
            inject_zero_sign_s <= 1'b0;
            inject_zero_sign_s_needs_release <= 1'b0;
            inject_invalid_privkey <= 1'b0;
            inject_invalid_privkey_needs_release <= 1'b0;
            inject_invalid_dhkey <= 1'b0;
            inject_invalid_dhkey_needs_release <= 1'b0;
            inject_invalid_pubkeyx <= 1'b0;
            inject_invalid_pubkeyx_needs_release <= 1'b0;
            inject_invalid_pubkeyy <= 1'b0;
            inject_invalid_pubkeyy_needs_release <= 1'b0;
        end
        else if((WriteData[7:0] == 8'h98) && mailbox_write) begin
            inject_zero_sign_r <= 1'b1;
        end
        else if((WriteData[7:0] == 8'h9a) && mailbox_write) begin
            inject_zero_sign_s <= 1'b1;
        end
        else if((WriteData[7:0] == 8'h9c) && mailbox_write) begin
            inject_invalid_privkey <= 1'b1;
        end
        else if((WriteData[7:0] == 8'h97) && mailbox_write) begin
            inject_invalid_dhkey <= 1'b1;
        end
        else if((WriteData[7:0] == 8'h9d) && mailbox_write) begin
            inject_invalid_pubkeyx <= 1'b1;
        end
        else if((WriteData[7:0] == 8'h9e) && mailbox_write) begin
            inject_invalid_pubkeyy <= 1'b1;
        end
        else if(inject_zero_sign_r) begin
            if (`CPTRA_TOP_PATH.ecc_top1.ecc_dsa_ctrl_i.prog_instr.reg_id == 6'd21) begin //R_ID
                force `CPTRA_TOP_PATH.ecc_top1.ecc_dsa_ctrl_i.ecc_arith_unit_i.d_o = '0;
                inject_zero_sign_r_needs_release <= 1'b1;
            end
            else if (inject_zero_sign_r_needs_release) begin
                inject_zero_sign_r <= 1'b0;
            end
        end
        else if(inject_zero_sign_s) begin
            if (`CPTRA_TOP_PATH.ecc_top1.ecc_dsa_ctrl_i.prog_instr.reg_id == 6'd22) begin //S_ID
                force `CPTRA_TOP_PATH.ecc_top1.ecc_dsa_ctrl_i.ecc_arith_unit_i.d_o = '0;
                inject_zero_sign_s_needs_release <= 1'b1;
            end
            else if (inject_zero_sign_s_needs_release) begin
                inject_zero_sign_s <= 1'b0;
            end
        end
        else if(inject_invalid_privkey) begin
            if (`CPTRA_TOP_PATH.ecc_top1.ecc_dsa_ctrl_i.prog_instr.reg_id == 6'd18) begin //PRIVKEY_ID
                force `CPTRA_TOP_PATH.ecc_top1.ecc_dsa_ctrl_i.ecc_arith_unit_i.d_o = '1;
                inject_invalid_privkey_needs_release <= 1'b1;
            end
            else if (inject_invalid_privkey_needs_release) begin
                inject_invalid_privkey <= 1'b0;
            end
        end
        else if(inject_invalid_dhkey) begin
            if (`CPTRA_TOP_PATH.ecc_top1.ecc_dsa_ctrl_i.prog_instr.reg_id == 6'd30) begin //DH_SHAREDKEY_ID
                force `CPTRA_TOP_PATH.ecc_top1.ecc_dsa_ctrl_i.ecc_arith_unit_i.d_o = '1;
                inject_invalid_dhkey_needs_release <= 1'b1;
            end
            else if (inject_invalid_dhkey_needs_release) begin
                inject_invalid_dhkey <= 1'b0;
            end
        end
        else if(inject_invalid_pubkeyx) begin
            if (`CPTRA_TOP_PATH.ecc_top1.ecc_dsa_ctrl_i.prog_instr.reg_id == 6'd19) begin //PUBKEYX_ID
                force `CPTRA_TOP_PATH.ecc_top1.ecc_dsa_ctrl_i.ecc_arith_unit_i.d_o = '1;
                inject_invalid_pubkeyx_needs_release <= 1'b1;
            end
            else if (inject_invalid_pubkeyx_needs_release) begin
                inject_invalid_pubkeyx <= 1'b0;
            end
        end
        else if(inject_invalid_pubkeyy) begin
            if (`CPTRA_TOP_PATH.ecc_top1.ecc_dsa_ctrl_i.prog_instr.reg_id == 6'd20) begin //PUBKEYY_ID
                force `CPTRA_TOP_PATH.ecc_top1.ecc_dsa_ctrl_i.ecc_arith_unit_i.d_o = '1;
                inject_invalid_pubkeyy_needs_release <= 1'b1;
            end
            else if (inject_invalid_pubkeyy_needs_release) begin
                inject_invalid_pubkeyy <= 1'b0;
            end
        end
        else begin
            release `CPTRA_TOP_PATH.ecc_top1.ecc_dsa_ctrl_i.ecc_arith_unit_i.d_o;
        end
    end

    //TIE-OFF device lifecycle
    logic assert_ss_tran;
`ifdef CALIPTRA_DEBUG_UNLOCKED
    initial security_state = '{device_lifecycle: DEVICE_PRODUCTION, debug_locked: 1'b0}; // DebugUnlocked & Production
`else
    initial begin
        if ($test$plusargs("CALIPTRA_DEBUG_UNLOCKED"))
            security_state = '{device_lifecycle: DEVICE_PRODUCTION, debug_locked: 1'b0}; // DebugUnlocked & Production
        else
            security_state = '{device_lifecycle: DEVICE_PRODUCTION, debug_locked: 1'b1}; // DebugLocked & Production
    end
`endif
    always @(negedge clk) begin
        //lock debug mode
        if ((WriteData[7:0] == 8'hf9) && mailbox_write) begin
            security_state.debug_locked <= 1'b1;
            if (UVM_TB) $warning("WARNING! Detected FW write to manually set security_state.debug_locked, but Firmware can't do this in UVM. Use a sequence in the soc_ifc_ctrl_agent to modify this field.");
        end
        //unlock debug mode
        else if ((WriteData[7:0] == 8'hfa) && mailbox_write) begin
            cycleCnt_ff <= cycleCnt;
            assert_ss_tran <= 'b1;
            //security_state.debug_locked <= 1'b0;
            if (UVM_TB) $warning("WARNING! Detected FW write to manually clear security_state.debug_locked, but Firmware can't do this in UVM. Use a sequence in the soc_ifc_ctrl_agent to modify this field.");
        end
        else if(assert_ss_tran && (cycleCnt == cycleCnt_ff + 'd100)) begin
            security_state.debug_locked <= 1'b0;
            assert_ss_tran <= 'b0;
        end
    end

    always_ff @(negedge clk or negedge cptra_rst_b) begin
        if (!cptra_rst_b)
            inject_single_msg_for_ecc_mldsa <= 'b0;
        else if ((WriteData[7:0] == 8'h89) && mailbox_write && !inject_single_msg_for_ecc_mldsa)
            inject_single_msg_for_ecc_mldsa <= 'b1; //set
        else if ((WriteData[7:0] == 8'h89) && mailbox_write && inject_single_msg_for_ecc_mldsa)
            inject_single_msg_for_ecc_mldsa <= 'b0; //reset
    end

    

    always_ff @(negedge clk or negedge cptra_rst_b) begin
        if (!cptra_rst_b) begin
            inject_makehint_failure <= 1'b0;
            inject_normcheck_failure <= 1'b0;
            inject_mldsa_timeout <= 1'b0;
            reset_mldsa_failure <= 1'b0;
            random_mldsa_failure_injection <= $urandom();
            normcheck_mode_random <= $urandom_range(0,2);
            disable_mldsa_sva <= 1'b0;
        end
        else if (((WriteData[7:0] == 8'hd7) && mailbox_write)) begin            
            if (`CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.verifying_process) begin
                inject_normcheck_failure    <= 1'b1;
                normcheck_mode_random       <= 'h0;
                inject_makehint_failure     <= 1'b0; 
                disable_mldsa_sva           <= 1'b1;  
                $display("Verify: Injecting normcheck failure with mode = %h\n", normcheck_mode_random);
            end
            else if (random_mldsa_failure_injection) begin
                inject_makehint_failure     <= 1'b1;
                inject_normcheck_failure    <= 1'b0;  
                disable_mldsa_sva           <= 1'b1;
                $display("Injecting makehint failure\n");
            end
            else begin
                inject_makehint_failure     <= 1'b0;
                inject_normcheck_failure    <= 1'b1;   
                disable_mldsa_sva           <= 1'b1;             
                $display("Injecting normcheck failure with mode = %h\n", normcheck_mode_random);
            end
        end
        else if (((WriteData[7:0] == 8'hd6) && mailbox_write)) begin
            inject_mldsa_timeout <= 1'b1;
        end
        else if (`CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.clear_verify_valid) begin //clear flags if end of signing loop or verify failed
            inject_normcheck_failure <= 1'b0;
        end
        else if (inject_normcheck_failure && `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.clear_signature_valid && (`CPTRA_TOP_PATH.mldsa.norm_check_inst.mode == normcheck_mode_random)) begin //clear flags if end of signing loop or verify failed
            inject_normcheck_failure <= 1'b0;
        end
        else if (inject_makehint_failure && `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.clear_signature_valid && `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.makehint_invalid_i) begin //clear flags if end of signing loop or verify failed
            inject_makehint_failure <= 1'b0;
        end
    end

    always_ff @(negedge clk) begin
        if (inject_makehint_failure && `CPTRA_TOP_PATH.mldsa.makehint_inst.hintgen_enable) begin
            force `CPTRA_TOP_PATH.mldsa.makehint_inst.hintsum = 'd80; //> OMEGA => makehint fails
            force `CPTRA_TOP_PATH.mldsa.norm_check_inst.invalid = 'b0;
        end
        else if (inject_makehint_failure) begin
            force `CPTRA_TOP_PATH.mldsa.norm_check_inst.invalid = 'b0;
        end       
        else if (inject_normcheck_failure && `CPTRA_TOP_PATH.mldsa.norm_check_inst.norm_check_ctrl_inst.check_enable && (`CPTRA_TOP_PATH.mldsa.norm_check_inst.mode == normcheck_mode_random))
            force `CPTRA_TOP_PATH.mldsa.norm_check_inst.invalid = 'b1;
        else begin
            release `CPTRA_TOP_PATH.mldsa.norm_check_inst.invalid;
            release `CPTRA_TOP_PATH.mldsa.makehint_inst.hintsum;
        end
        
        if (inject_mldsa_timeout)
            force `CPTRA_TOP_PATH.mldsa.makehint_inst.hintsum = 'd80;
    end

    `ifndef VERILATOR
    logic mldsa_keygen, mldsa_signing, mldsa_verify, mldsa_keygen_signing;

    always @(negedge clk or negedge cptra_rst_b) begin
        if (!cptra_rst_b) begin
            mldsa_keygen <= 'b0;
            mldsa_signing <= 'b0;
            mldsa_verify <= 'b0;
            mldsa_keygen_signing <= 'b0;
        end
        else if ((WriteData[7:0] == 8'hd9) && mailbox_write) begin
            mldsa_keygen <= 'b1;
            mldsa_signing <= 'b0;
            mldsa_verify <= 'b0;
            mldsa_keygen_signing <= 'b0;
        end
        //unlock debug mode
        else if ((WriteData[7:0] == 8'hda) && mailbox_write) begin
            mldsa_keygen <= 'b0;
            mldsa_signing <= 'b1;
            mldsa_verify <= 'b0;
            mldsa_keygen_signing <= 'b0;
        end
        else if((WriteData[7:0] == 8'hdb) && mailbox_write) begin
            mldsa_keygen <= 'b0;
            mldsa_signing <= 'b0;
            mldsa_verify <= 'b1;
            mldsa_keygen_signing <= 'b0;
        end
        else if((WriteData[7:0] == 8'hdc) && mailbox_write) begin
            mldsa_keygen <= 'b0;
            mldsa_signing <= 'b0;
            mldsa_verify <= 'b0;
            mldsa_keygen_signing <= 'b1;
        end
        else begin
            mldsa_keygen <= 'b0;
            mldsa_signing <= 'b0;
            mldsa_verify <= 'b0;
            mldsa_keygen_signing <= 'b0;
        end
    end

    genvar mldsa_dword;
    generate
        //MLDSA keygen - inject seed
        for (mldsa_dword = 0; mldsa_dword < SEED_NUM_DWORDS; mldsa_dword++) begin
            always @(negedge clk) begin
                if (mldsa_keygen | mldsa_keygen_signing) begin
                    force `CPTRA_TOP_PATH.mldsa.mldsa_reg_inst.hwif_in.MLDSA_SEED[mldsa_dword].SEED.we = 'b1;
                    force `CPTRA_TOP_PATH.mldsa.mldsa_reg_inst.hwif_in.MLDSA_SEED[mldsa_dword].SEED.next = {mldsa_test_vector.seed[mldsa_dword][7:0], mldsa_test_vector.seed[mldsa_dword][15:8], mldsa_test_vector.seed[mldsa_dword][23:16], mldsa_test_vector.seed[mldsa_dword][31:24]};
                end
                else begin
                    release `CPTRA_TOP_PATH.mldsa.mldsa_reg_inst.hwif_in.MLDSA_SEED[mldsa_dword].SEED.we;
                    release `CPTRA_TOP_PATH.mldsa.mldsa_reg_inst.hwif_in.MLDSA_SEED[mldsa_dword].SEED.next;
                end
            end
        end

        //MLDSA signing or MLDSA verify - inject msg
        for (mldsa_dword = 0; mldsa_dword < MSG_NUM_DWORDS; mldsa_dword++) begin
            always @(negedge clk) begin
                if (mldsa_signing | mldsa_verify | mldsa_keygen_signing) begin
                    force `CPTRA_TOP_PATH.mldsa.mldsa_reg_inst.hwif_in.MLDSA_MSG[mldsa_dword].MSG.we = 'b1;
                    force `CPTRA_TOP_PATH.mldsa.mldsa_reg_inst.hwif_in.MLDSA_MSG[mldsa_dword].MSG.next = {mldsa_test_vector.msg[mldsa_dword][7:0], mldsa_test_vector.msg[mldsa_dword][15:8], mldsa_test_vector.msg[mldsa_dword][23:16], mldsa_test_vector.msg[mldsa_dword][31:24]};
                end
                else begin
                    release `CPTRA_TOP_PATH.mldsa.mldsa_reg_inst.hwif_in.MLDSA_MSG[mldsa_dword].MSG.we;
                    release `CPTRA_TOP_PATH.mldsa.mldsa_reg_inst.hwif_in.MLDSA_MSG[mldsa_dword].MSG.next;
                end
            end
        end

        //MLDSA signing - inject sk
        for (mldsa_dword = 0; mldsa_dword < PRIVKEY_REG_RHO_NUM_DWORDS/2; mldsa_dword++) begin
            always @(negedge clk) begin
                if (mldsa_signing) begin
                    force `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.privatekey_reg.enc.rho[mldsa_dword] = {mldsa_test_vector.privkey[((mldsa_dword*2)+1)][7:0], mldsa_test_vector.privkey[((mldsa_dword*2)+1)][15:8], mldsa_test_vector.privkey[((mldsa_dword*2)+1)][23:16], mldsa_test_vector.privkey[((mldsa_dword*2)+1)][31:24],
                                                                                                        mldsa_test_vector.privkey[(mldsa_dword*2)][7:0], mldsa_test_vector.privkey[(mldsa_dword*2)][15:8], mldsa_test_vector.privkey[(mldsa_dword*2)][23:16], mldsa_test_vector.privkey[(mldsa_dword*2)][31:24]};
                    force `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.privatekey_reg.enc.K[mldsa_dword] = {mldsa_test_vector.privkey[((mldsa_dword*2)+1+8)][7:0], mldsa_test_vector.privkey[((mldsa_dword*2)+1+8)][15:8], mldsa_test_vector.privkey[((mldsa_dword*2)+1+8)][23:16], mldsa_test_vector.privkey[((mldsa_dword*2)+1+8)][31:24],
                                                                                                      mldsa_test_vector.privkey[((mldsa_dword*2)+8)][7:0], mldsa_test_vector.privkey[((mldsa_dword*2)+8)][15:8], mldsa_test_vector.privkey[((mldsa_dword*2)+8)][23:16], mldsa_test_vector.privkey[((mldsa_dword*2)+8)][31:24]};
                end
                else begin
                    release `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.privatekey_reg.enc.rho[mldsa_dword];
                    release `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.privatekey_reg.enc.K[mldsa_dword];
                end
            end
        end

        for (mldsa_dword = 0; mldsa_dword < 8; mldsa_dword++) begin
            always @(negedge clk) begin
                if (mldsa_signing) begin
                    force `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.privatekey_reg.enc.tr[mldsa_dword] = {mldsa_test_vector.privkey[((mldsa_dword*2)+1+16)][7:0], mldsa_test_vector.privkey[((mldsa_dword*2)+1+16)][15:8], mldsa_test_vector.privkey[((mldsa_dword*2)+1+16)][23:16], mldsa_test_vector.privkey[((mldsa_dword*2)+1+16)][31:24],
                                                                                                       mldsa_test_vector.privkey[((mldsa_dword*2)+16)][7:0], mldsa_test_vector.privkey[((mldsa_dword*2)+16)][15:8], mldsa_test_vector.privkey[((mldsa_dword*2)+16)][23:16], mldsa_test_vector.privkey[((mldsa_dword*2)+16)][31:24]};
                end
                else begin
                    release `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.privatekey_reg.enc.tr[mldsa_dword];
                end
            end
        end

        for (mldsa_dword = PRIVKEY_REG_NUM_DWORDS; mldsa_dword < PRIVKEY_NUM_DWORDS; mldsa_dword++) begin
            always @(negedge clk) begin
                if (mldsa_signing) begin
                    if ((mldsa_dword % 2) == 0) begin
                        force mldsa_mem_top_inst.mldsa_sk_mem_bank0_inst.ram[(mldsa_dword-32)/2] = {mldsa_test_vector.privkey[mldsa_dword][7:0], mldsa_test_vector.privkey[mldsa_dword][15:8], mldsa_test_vector.privkey[mldsa_dword][23:16], mldsa_test_vector.privkey[mldsa_dword][31:24]};
                    end
                    else begin
                        force mldsa_mem_top_inst.mldsa_sk_mem_bank1_inst.ram[(mldsa_dword-33)/2] = {mldsa_test_vector.privkey[mldsa_dword][7:0], mldsa_test_vector.privkey[mldsa_dword][15:8], mldsa_test_vector.privkey[mldsa_dword][23:16], mldsa_test_vector.privkey[mldsa_dword][31:24]};
                    end
                end
                else begin
                    release mldsa_mem_top_inst.mldsa_sk_mem_bank0_inst.ram[(mldsa_dword-32)/2];
                    release mldsa_mem_top_inst.mldsa_sk_mem_bank1_inst.ram[(mldsa_dword-33)/2];
                end
            end
        end

        //MLDSA verify - inject pk
        for (mldsa_dword = 0; mldsa_dword < 8; mldsa_dword++) begin
            always @(negedge clk) begin
                if (mldsa_verify) begin
                    force `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.publickey_reg.enc.rho[mldsa_dword] = {mldsa_test_vector.pubkey[mldsa_dword][7:0], mldsa_test_vector.pubkey[mldsa_dword][15:8], mldsa_test_vector.pubkey[mldsa_dword][23:16], mldsa_test_vector.pubkey[mldsa_dword][31:24]};
                end
                else begin
                    release `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.publickey_reg.enc.rho[mldsa_dword];
                end
            end
        end
        for (genvar a = 0; a < 64; a++) begin
            for (genvar b = 0; b < 10; b++) begin
                always @(negedge clk) begin
                    if (mldsa_verify) begin
                        force mldsa_mem_top_inst.mldsa_pk_mem_inst.ram[a][b*4+3:b*4] = {mldsa_test_vector.pubkey[a*10+8+b][7:0], mldsa_test_vector.pubkey[a*10+8+b][15:8], mldsa_test_vector.pubkey[a*10+8+b][23:16], mldsa_test_vector.pubkey[a*10+8+b][31:24]};
                    end
                    else begin
                        release mldsa_mem_top_inst.mldsa_pk_mem_inst.ram[a][b*4+3:b*4];
                    end
                end
            end
        end

        //MLDSA verify - inject signature
        for (mldsa_dword = 0; mldsa_dword < VERIFY_RES_NUM_DWORDS; mldsa_dword++) begin
            always @(negedge clk) begin
                if (mldsa_verify) begin
                    force `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.signature_reg.enc.c[mldsa_dword] = {mldsa_test_vector.signature[mldsa_dword][7:0], mldsa_test_vector.signature[mldsa_dword][15:8], mldsa_test_vector.signature[mldsa_dword][23:16], mldsa_test_vector.signature[mldsa_dword][31:24]};
                end
                else begin
                    release `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.signature_reg.enc.c[mldsa_dword];
                end
            end
        end
        for (mldsa_dword = 0; mldsa_dword < SIGNATURE_H_NUM_DWORDS; mldsa_dword++) begin
            always @(negedge clk) begin
                if (mldsa_verify) begin
                    force `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.signature_reg.enc.h[mldsa_dword] = {mldsa_test_vector.signature[1136+mldsa_dword][7:0], mldsa_test_vector.signature[1136+mldsa_dword][15:8], mldsa_test_vector.signature[1136+mldsa_dword][23:16], mldsa_test_vector.signature[1136+mldsa_dword][31:24]};
                end
                else begin
                    release `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.signature_reg.enc.h[mldsa_dword];
                end
            end
        end
        for (genvar a = 0; a < 224; a++) begin
            for (genvar b = 0; b < 5; b++) begin
                always @(negedge clk) begin
                    if (mldsa_verify) begin
                        force mldsa_mem_top_inst.mldsa_sig_z_mem_inst.ram[a][b*4+3:b*4] = {mldsa_test_vector.signature[a*5+16+b][7:0], mldsa_test_vector.signature[a*5+16+b][15:8], mldsa_test_vector.signature[a*5+16+b][23:16], mldsa_test_vector.signature[a*5+16+b][31:24]};
                    end
                    else begin
                        release mldsa_mem_top_inst.mldsa_sig_z_mem_inst.ram[a][b*4+3:b*4];
                    end
                end
            end
        end
    endgenerate
    `endif

    //Randomized wntz
    generate
        for (genvar dword = 15; dword >= 0; dword--) begin
            always@(negedge clk) begin
                if ((WriteData[7:0] == 8'hdd) && mailbox_write) begin
                    force `CPTRA_TOP_PATH.sha256.sha256_inst.hwif_out.SHA256_BLOCK[dword].BLOCK.value = sha256_wntz_test_vector.sha256_wntz_block_tb[15-dword];
                    force `CPTRA_TOP_PATH.sha256.sha256_inst.wntz_mode = 1'b1; //single pulse
                    force `CPTRA_TOP_PATH.sha256.sha256_inst.wntz_n_mode = sha256_wntz_test_vector.wntz_n;
                    force `CPTRA_TOP_PATH.sha256.sha256_inst.wntz_w = sha256_wntz_test_vector.wntz_w;
                    force `CPTRA_TOP_PATH.sha256.sha256_inst.init_reg = 1'b1;
                    force `CPTRA_TOP_PATH.sha256.sha256_inst.mode_reg = 1'b1;
                end //if 'hdd
                else if (`CPTRA_TOP_PATH.sha256.sha256_inst.hwif_out.SHA256_CTRL.ZEROIZE.value) begin
                    release `CPTRA_TOP_PATH.sha256.sha256_inst.hwif_out.SHA256_BLOCK[dword].BLOCK.value;
                end
                else begin
                    // release `CPTRA_TOP_PATH.sha256.sha256_inst.hwif_out.SHA256_BLOCK[dword].BLOCK.value;
                    release `CPTRA_TOP_PATH.sha256.sha256_inst.wntz_mode;
                    release `CPTRA_TOP_PATH.sha256.sha256_inst.init_reg;
                end //else
            end //always
        end //for
    endgenerate

    generate
        for(genvar dword = 0; dword < IV_NO; dword++) begin
    always@(negedge clk) begin
        if ((WriteData[7:0] == 8'hec) && mailbox_write) begin
            force `CPTRA_TOP_PATH.doe.doe_inst.hwif_out.DOE_IV[dword].IV.swmod = 'b1;
            force `CPTRA_TOP_PATH.doe.doe_inst.i_doe_reg.field_storage.DOE_IV[dword].IV.value = doe_test_vector.iv_uds[dword];
        end
        else if ((WriteData[7:0] == 8'hed) && mailbox_write) begin
            force `CPTRA_TOP_PATH.doe.doe_inst.hwif_out.DOE_IV[dword].IV.swmod = 'b1;
            force `CPTRA_TOP_PATH.doe.doe_inst.i_doe_reg.field_storage.DOE_IV[dword].IV.value = doe_test_vector.iv_fe[dword];
        end
        else begin
            release `CPTRA_TOP_PATH.doe.doe_inst.hwif_out.DOE_IV[dword].IV.swmod;
            release `CPTRA_TOP_PATH.doe.doe_inst.i_doe_reg.field_storage.DOE_IV[dword].IV.value;
        end
    end
end //for
endgenerate //IV_NO

    logic assert_scan_mode;
    logic assert_scan_mode_doe_done;
    always @(negedge clk) begin
        //Enable scan mode
        if ((WriteData[7:0] == 8'hef) && mailbox_write) begin
            cycleCnt_ff <= cycleCnt;
            assert_scan_mode <= 'b1;
            //scan_mode <= 1'b1;
        end
        else if ((WriteData[7:0] == 8'he8) && mailbox_write) begin
            cycleCnt_ff <= cycleCnt;
            assert_scan_mode_doe_done <= 'b1;
        end
        else if(assert_scan_mode && (cycleCnt == cycleCnt_ff + 'd100)) begin
            scan_mode <= 1'b1;
            assert_scan_mode <= 'b0;
        end
        else if (assert_scan_mode_doe_done && (`CPTRA_TOP_PATH.doe.doe_inst.doe_fsm1.kv_doe_fsm_ps == 'h5)) begin
            scan_mode <= 1'b1;
            assert_scan_mode <= 'b0;
        end
        //Disable scan mode
        else if ((WriteData[7:0] == 8'hf0) && mailbox_write) begin
            scan_mode <= 1'b0;
        end
    end
    
    
    always@(negedge clk) begin
        if((WriteData[7:0] == 8'hf2) && mailbox_write) begin
            force `CPTRA_TOP_PATH.soc_ifc_top1.clk_gating_en = 1;
        end
    end

    always@(negedge clk) begin
        if ((WriteData[7:0] == 8'he9) && mailbox_write) begin
            cycleCnt_ff <= cycleCnt;
            en_jtag_access <= 'b1;
        end
        else if(en_jtag_access && (cycleCnt == (cycleCnt_ff + 'd100))) begin
            force `CPTRA_TOP_PATH.cptra_dmi_reg_en_preQ = 1;
        end
        else if(en_jtag_access && (cycleCnt == (cycleCnt_ff + 'd150))) begin
            release `CPTRA_TOP_PATH.cptra_dmi_reg_en_preQ;
            en_jtag_access <= 'b0;
        end
    end
    
    logic inject_zeroize_to_hmac;
    logic inject_zeroize_to_hmac_cmd;
    logic [3 : 0] inject_zeroize_to_hmac_cnt;
    always@(posedge clk or negedge cptra_rst_b) begin
        if (~cptra_rst_b) begin
            inject_zeroize_to_hmac_cmd <= 1'b0;
            inject_zeroize_to_hmac <= 1'b0;
            inject_zeroize_to_hmac_cnt <= '0;
        end
        else if((WriteData[7:0] == 8'h99) && mailbox_write) begin
            inject_zeroize_to_hmac_cmd <= 1'b1;
        end
        else if (inject_zeroize_to_hmac_cmd) begin
            if (`CPTRA_TOP_PATH.hmac.hmac_inst.core_tag_we) begin
                inject_zeroize_to_hmac <= 1'b1;
            end
            if (inject_zeroize_to_hmac) begin
                if (inject_zeroize_to_hmac_cnt < 4'hf) begin
                    inject_zeroize_to_hmac_cnt <= inject_zeroize_to_hmac_cnt + 1'b1;
                end
            end
        end
    end
    always@(negedge clk) begin
        if (inject_zeroize_to_hmac) begin
            if (inject_zeroize_to_hmac_cnt == 4'h5) begin
                force `CPTRA_TOP_PATH.hmac.hmac_inst.i_hmac_reg.field_storage.HMAC512_CTRL.ZEROIZE.value = 1'b1;
            end
            else begin
                release `CPTRA_TOP_PATH.hmac.hmac_inst.i_hmac_reg.field_storage.HMAC512_CTRL.ZEROIZE.value;
            end
        end
    end

    logic inject_zeroize_kv_read;
    logic inject_zeroize_to_mldsa;
    always@(posedge clk or negedge cptra_rst_b) begin
        if (~cptra_rst_b) begin
            inject_zeroize_kv_read <= 1'b0;
            inject_zeroize_to_mldsa <= 1'b0;
        end
        else if((WriteData[7:0] == 8'h9b) && mailbox_write) begin
            inject_zeroize_kv_read <= 1'b1;
        end
        else if (inject_zeroize_kv_read) begin
            if (`CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.kv_seed_write_en & 
                (`CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.kv_seed_write_offset == 3)) begin
                inject_zeroize_to_mldsa <= 1'b1;
            end
            if (inject_zeroize_to_mldsa) begin
                inject_zeroize_to_mldsa <= 1'b0;
                inject_zeroize_kv_read <= 1'b0;
            end
        end
    end
    always@(negedge clk) begin
        if (inject_zeroize_to_mldsa) begin
            force `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.mldsa_reg_hwif_out.MLDSA_CTRL.ZEROIZE.value = 1'b1;
        end else begin
            release `CPTRA_TOP_PATH.mldsa.mldsa_ctrl_inst.mldsa_reg_hwif_out.MLDSA_CTRL.ZEROIZE.value;
        end
    end

    //Inject fatal error after a delay
    logic inject_fatal_error;
    always@(negedge clk) begin
        if((WriteData[7:0] == 8'heb) && mailbox_write) begin
            cycleCnt_ff <= cycleCnt;
            inject_fatal_error <= 'b1;
        end
        else if(inject_fatal_error && (cycleCnt == cycleCnt_ff + 'd100)) begin
            force `CPTRA_TOP_PATH.cptra_error_fatal = 'b1;
        end
        else if(inject_fatal_error && (cycleCnt == cycleCnt_ff + 'd200)) begin
            release `CPTRA_TOP_PATH.cptra_error_fatal;
            inject_fatal_error <= 'b0;
        end
    end

    logic [0:11][31:0] pv_hash_value = {32'h11143121,
    32'hbeb365e6,
    32'h3826e7de,
    32'h89f9c76a,
    32'he1100411,
    32'hfb9643d1,
    32'h98e730b7,
    32'h603a83a4,
    32'h977c76ee,
    32'he6ddf74f,
    32'ha0b43fbf,
    32'h49897978};

    logic pcr_vault_needs_release;

    generate 
        for (genvar dword = 0; dword < 12; dword++) begin
            always@(posedge clk or negedge cptra_rst_b) begin
                if (~cptra_rst_b) begin
                    pcr_vault_needs_release <= 1'b0;
                end
                else if((WriteData[7:0] == 8'hf3) && mailbox_write) begin
                    pcr_vault_needs_release <= 1'b1;
                    force `CPTRA_TOP_PATH.pcr_vault1.pv_reg_hwif_in.PCR_ENTRY[31][dword].data.we = 1'b1;
                    force `CPTRA_TOP_PATH.pcr_vault1.pv_reg_hwif_in.PCR_ENTRY[31][dword].data.next = pv_hash_value[dword];
                end
                else if (pcr_vault_needs_release) begin
                    pcr_vault_needs_release <= 1'b0;
                    release `CPTRA_TOP_PATH.pcr_vault1.pv_reg_hwif_in.PCR_ENTRY[31][dword].data.we;
                    release `CPTRA_TOP_PATH.pcr_vault1.pv_reg_hwif_in.PCR_ENTRY[31][dword].data.next;
                end
            end
        end
    endgenerate

    task sha256_wntz_testvector_generator();
        string file_name;
        int fd_r;
        string line_read;
        int w_ln, w, n;

        w_ln = $urandom_range(3, 0);
        w = 2**w_ln;
        n = $urandom_range(0, 1);

        $system($sformatf("python sha256_wntz_test_gen.py %d %d", w, n));
        file_name = "sha256_wntz_test_vector.txt";

        if (!UVM_TB) begin
            fd_r = $fopen(file_name, "r");
            if (fd_r == 0) $error("Cannot open file %s for reading", file_name);
           
            //Get values from file
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", sha256_wntz_test_vector.sha256_wntz_block_tb));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", sha256_wntz_test_vector.sha256_wntz_digest));
            sha256_wntz_test_vector.wntz_n = n;
            sha256_wntz_test_vector.wntz_w = w;
            $fclose(fd_r);
        end
    endtask

    task doe_testvector_generator();
        string file_name;
        int fd_r;
        string line_read;

        $system("python doe_test_gen.py");
        file_name = "doe_test_vector.txt";
        if(!UVM_TB) begin
            fd_r = $fopen(file_name, "r");
            if(fd_r == 0) $error("Cannot open file %s for reading", file_name);

            //Get values from file
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", doe_test_vector.obf_key_uds));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", doe_test_vector.iv_uds));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", doe_test_vector.uds_plaintext));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", doe_test_vector.uds_ciphertext));

            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", doe_test_vector.obf_key_fe));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", doe_test_vector.iv_fe));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", doe_test_vector.fe_plaintext));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", doe_test_vector.fe_ciphertext));

            $fclose(fd_r);
        end

    endtask

    task mldsa_input_hex_gen(); //mode = CTRL.value-1
        int fd_r;
        logic [7:0][31:0] seed;
        logic [15:0][31:0] msg;
        string keygen_outfile, sign_outfile, verify_outfile;
        string keygen_infile, sign_infile, verify_infile;
        string line_read;
        keygen_outfile = "keygen_input.hex";
        keygen_infile = "keygen_output.hex";
        sign_outfile = "sign_input.hex";
        sign_infile = "sign_output.hex";
        verify_outfile = "verify_input.hex";
        verify_infile = "verify_output.hex";
        
        //---------------------------
        //Keygen
        //---------------------------
        fd_r = $fopen(keygen_outfile, "w");
        for (int i = 0; i < 8; i++) begin
            seed[i] = $urandom();
        end
        mldsa_test_vector.seed = seed;
        $fwrite(fd_r, "%02X\n", 0); //write cmd (keygen) as a 2 digit number
        $fwrite(fd_r, "%h", seed); //write random seed 8*4 bytes
        $fclose(fd_r);
        $system("./test_dilithium5 keygen_input.hex keygen_output.hex");

        fd_r = $fopen(keygen_infile, "r");
        if (fd_r == 0)
            $error("Can't open file %s", keygen_infile);

        void'($fgets(line_read, fd_r)); //skip cmd
        void'($fgets(line_read, fd_r));
        void'($sscanf(line_read, "%h", mldsa_test_vector.pubkey));
        void'($fgets(line_read, fd_r));
        void'($sscanf(line_read, "%h", mldsa_test_vector.privkey));

        //---------------------------
        //Sign
        //---------------------------
        fd_r = $fopen(sign_outfile, "w");
        for (int i = 0; i < 16; i++) begin
            msg[i] = $urandom();
        end
        mldsa_test_vector.msg = msg;
        $fwrite(fd_r, "%02X\n", 1);
        $fwrite(fd_r, "%h\n", msg);
        $fwrite(fd_r, "%h", mldsa_test_vector.privkey);
        $fclose(fd_r);
        $system("./test_dilithium5 sign_input.hex sign_output.hex");

        fd_r = $fopen(sign_infile, "r");
        if (fd_r == 0)
            $error("Can't open file %s", sign_infile);

        void'($fgets(line_read, fd_r)); //skip cmd
        void'($fgets(line_read, fd_r)); //skip sig length
        void'($fgets(line_read, fd_r));
        void'($sscanf(line_read, "%h", mldsa_test_vector.signature));
        mldsa_test_vector.signature = {mldsa_test_vector.signature[0:1156], 8'h00};

        mldsa_test_vector.sign_rnd = 'h0;
        
        //---------------------------
        //Verify
        //---------------------------
        fd_r = $fopen(verify_outfile, "w");
        $fwrite(fd_r, "%02X\n", 2);
        $fwrite(fd_r, "%h\n", {mldsa_test_vector.signature[0:1155], mldsa_test_vector.signature[1156][31:8]}); //[0:1156][31:0] signature
        $fwrite(fd_r, "%h\n", mldsa_test_vector.msg);
        $fwrite(fd_r, "%h", mldsa_test_vector.pubkey);
        $fclose(fd_r);
        $system("./test_dilithium5 verify_input.hex verify_output.hex");
        
        fd_r = $fopen(verify_infile, "r");
        if (fd_r == 0)
            $error("Can't open file %s", verify_infile);

        void'($fgets(line_read, fd_r)); //skip cmd
        void'($fgets(line_read, fd_r)); //skip 2nd line
        void'($fgets(line_read, fd_r));
        void'($sscanf(line_read, "%h", mldsa_test_vector.verify_res));
    endtask

    task ecc_testvector_generator ();
        string    file_name;
        begin

        $system("./ecc_secp384r1.exe");

        file_name = "secp384_testvector.hex";
        if (!UVM_TB) ecc_read_test_vectors(file_name);
        end
    endtask // ecc_test

    task static ecc_read_test_vectors (input string fname);
        integer values_per_test_vector;
        int fd_r;
        string line_read;
        begin

            // ATTN: Must match the number of fields generated by gen_mm_test_vectors.py script
            values_per_test_vector = 11;

            fd_r = $fopen(fname, "r");
            if (fd_r == 0)
                $error("Can't open file %s", fname);


            // Get hashed message, private key, public key x, public key y, k and R
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", ecc_test_vector.hashed_msg));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", ecc_test_vector.privkey));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", ecc_test_vector.pubkey.x));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", ecc_test_vector.pubkey.y));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", ecc_test_vector.seed));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", ecc_test_vector.nonce));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", ecc_test_vector.R));
            void'($fgets(line_read, fd_r)); 
            void'($sscanf(line_read, "%h", ecc_test_vector.S));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", ecc_test_vector.IV));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", ecc_test_vector.privkeyB));
            void'($fgets(line_read, fd_r));
            void'($sscanf(line_read, "%h", ecc_test_vector.dh_sharedkey));

            $fclose(fd_r);

        end
    endtask

    logic [0:15][31:0]   pcr_to_be_signed = 512'h_C8F518D4F3AA1BD46ED56C1C3C9E16FB800AF504DB98843548C5F623EE115F73D4C62ABC06D303B5D90D9A175087290D_16e6009644e2a5f2c41fed22e703fb78;
    logic [0:15][31:0]   ecc_random_msg;
    logic [0:15][31:0]   mldsa_random_msg;
    always_comb ecc_random_msg = {ecc_test_vector.hashed_msg, 128'h00000000000000000000000000000000};
    always_comb mldsa_random_msg = change_endian(mldsa_test_vector.msg);  //swap the endian

    generate 
        for (genvar dword = 0; dword < 16; dword++) begin
            always@(posedge clk) begin
                if((WriteData[7:0] == 8'h90) && mailbox_write) begin
                    force `CPTRA_TOP_PATH.sha512.sha512_inst.pcr_sign_we = 1'b1;
                    force `CPTRA_TOP_PATH.sha512.sha512_inst.pcr_sign[dword] = pcr_to_be_signed[15-dword][31 : 0];
                end
                else if((WriteData[7:0] == 8'h91) && mailbox_write) begin
                    force `CPTRA_TOP_PATH.sha512.sha512_inst.pcr_sign_we = 1'b1;
                    force `CPTRA_TOP_PATH.sha512.sha512_inst.pcr_sign[dword] = ecc_random_msg[15-dword][31 : 0];
                end
                else if((WriteData[7:0] == 8'h93) && mailbox_write && !inject_single_msg_for_ecc_mldsa) begin //TODO: what if mldsa is trig'd first and then ecc?
                    force `CPTRA_TOP_PATH.sha512.sha512_inst.pcr_sign_we = 1'b1;
                    force `CPTRA_TOP_PATH.sha512.sha512_inst.pcr_sign[dword] = mldsa_random_msg[15-dword][31 : 0];
                end
                else begin
                    release `CPTRA_TOP_PATH.sha512.sha512_inst.pcr_sign_we;
                    release `CPTRA_TOP_PATH.sha512.sha512_inst.pcr_sign[dword];
                end
            end
        end
    endgenerate

    always @(negedge clk) begin
        if((WriteData[7:0] == 8'h92) && mailbox_write)
            check_pcr_ecc_signing <= 1'b1;
        else if((WriteData[7:0] == 8'h94) && mailbox_write)
            check_pcr_mldsa_signing <= 1'b1;
        else begin
            check_pcr_ecc_signing <= 1'b0;
            check_pcr_mldsa_signing <= 1'b0;
        end
    end


    always@(negedge clk) begin

        if((WriteData[7:0] == 8'hf5) && mailbox_write) begin 
            cold_rst <= 'b1;
            rst_cyclecnt <= cycleCnt;
        end
        else if((WriteData[7:0] == 8'hf6) && mailbox_write) begin
            warm_rst <= 'b1;
            rst_cyclecnt <= cycleCnt;
        end
        else if((WriteData[7:0] == 8'hf7) && mailbox_write) begin
            timed_warm_rst <= 'b1;
        end
        else if((WriteData[7:0] == 8'hee) && mailbox_write) begin
            `ifndef VERILATOR
                std::randomize(wait_time_to_rst) with {wait_time_to_rst dist {[5:24] :/ 3, [25:99] :/ 5, [100:255] :/ 8, [256:511] :/ 5, [512:1023] :/ 1};};
            `else
                wait_time_to_rst = $urandom_range(5,150);
            `endif
            prandom_warm_rst <= 'b1;
            rst_cyclecnt <= cycleCnt;
        end


        if (cold_rst) begin
            assert_hard_rst_flag <= cold_rst_done ? 'b0 : 'b1;
            deassert_hard_rst_flag <= 'b0;
            deassert_rst_flag <= 'b0;
            

            if(cycleCnt == rst_cyclecnt + 'd10) begin
                assert_hard_rst_flag <= 'b0;
                deassert_hard_rst_flag <= 'b1;
                cold_rst_done <= 'b1;
            end
            else if(cycleCnt == rst_cyclecnt + 'd20) begin
                deassert_rst_flag <= 'b1;
                cold_rst <= 'b0;
                cold_rst_done <= 'b0;
            end
            else begin
                deassert_hard_rst_flag <= 'b0;
                deassert_rst_flag <= 'b0;
            end
        end
        else if(warm_rst) begin
            assert_rst_flag <= 'b1;
            deassert_rst_flag <= 'b0;
            

            if(cycleCnt == rst_cyclecnt + 'd10) begin
                assert_rst_flag <= 'b0;
                deassert_rst_flag <= 'b1;
                warm_rst <= 'b0;
            end
        end
        else if(timed_warm_rst) begin
            if((`CPTRA_TOP_PATH.doe.doe_inst.doe_fsm1.kv_doe_fsm_ns == 'h5)) begin
                assert_rst_flag <= 'b1;
                deassert_rst_flag <= 'b0;
                rst_cyclecnt <= cycleCnt;
            end
            else if(assert_rst_flag && (cycleCnt == rst_cyclecnt + 'd5)) begin
                assert_rst_flag <= 0;
                deassert_rst_flag <= 1;
                timed_warm_rst <= 'b0;
            end
        end
        else if(prandom_warm_rst) begin
            if(cycleCnt == rst_cyclecnt + wait_time_to_rst) begin
                assert_rst_flag <= 'b1;
                deassert_rst_flag <= 'b0;
            end
            else if(assert_rst_flag && (cycleCnt >= (rst_cyclecnt + wait_time_to_rst + 10))) begin //prandom rst was already issued, so deassert rst now
                assert_rst_flag <= 'b0;
                deassert_rst_flag <= 'b1;
                prandom_warm_rst <= 'b0;
            end
        end
        else begin
            deassert_hard_rst_flag <= 'b0;
            deassert_rst_flag <= 'b0;
        end
    end

    always @(negedge clk or negedge cptra_rst_b) begin
        if (!cptra_rst_b) begin
            int_flag <= 'b0;
            cycleCnt_smpl_en <= 'b0;
        end
        else if((WriteData[7:0] == 8'hf8) && mailbox_write) begin
            int_flag <= 1'b1;
            cycleCnt_smpl_en <= 'b1;
        end
        else cycleCnt_smpl_en <= 'b0;
    end

    //WDT assist logic
    always @(negedge clk or negedge cptra_rst_b) begin
        if (!cptra_rst_b) begin
            reset_wdt_timer_period <= 'b0;
        end
        else if((WriteData[7:0] == 8'hf1) && mailbox_write) begin
            reset_wdt_timer_period <= 'b1;
        end
    end

    always @(negedge clk or negedge cptra_rst_b) begin
        if(!cptra_rst_b) begin
            set_wdt_timer1_period <= 'b0;
            set_wdt_timer2_period <= 'b0;
        end
        else begin
            if (!UVM_TB) begin
                if(`CPTRA_TOP_PATH.soc_ifc_top1.i_wdt.wdt_timer1_timeout_serviced_qual) begin
                    set_wdt_timer1_period <= 'b1;
                end
                if(`CPTRA_TOP_PATH.soc_ifc_top1.i_wdt.wdt_timer2_timeout_serviced_qual) begin
                    set_wdt_timer2_period <= 'b1;
                end
            end
            if(reset_wdt_timer_period) begin
                set_wdt_timer1_period <= 'b0;
                set_wdt_timer2_period <= 'b0;
            end
        end
    end

    always @(negedge clk) begin
        if(set_wdt_timer1_period) begin
            force `CPTRA_TOP_PATH.soc_ifc_top1.timer1_timeout_period = 64'hFFFFFFFF_FFFFFFFF;
        end
        else if(reset_wdt_timer_period) begin
            release `CPTRA_TOP_PATH.soc_ifc_top1.timer1_timeout_period;
        end

        if(set_wdt_timer2_period) begin
            force `CPTRA_TOP_PATH.soc_ifc_top1.timer2_timeout_period = 64'hFFFFFFFF_FFFFFFFF;
        end
        else if(reset_wdt_timer_period) begin
            release `CPTRA_TOP_PATH.soc_ifc_top1.timer2_timeout_period;
        end

    end

    always @(negedge clk) begin
        if((WriteData[7:0] == 8'hea) && mailbox_write) begin
            force `CPTRA_TOP_PATH.soc_ifc_top1.timer1_timeout_period = {32'h0000_0000, $urandom_range(32'h0000_0001,32'h0000_0FFF)};
            force `CPTRA_TOP_PATH.soc_ifc_top1.timer2_timeout_period = {32'h0000_0000, $urandom_range(32'h0000_0001,32'h0000_0FFF)};
        end
        //Use 'hF1 code to reset these values in the test
    end


    `ifndef VERILATOR
        initial begin
            automatic bitflip_mask_generator #(CPTRA_MBOX_DATA_AND_ECC_W) bitflip_gen = new();
            forever begin
                @(posedge clk)
                if (~|inject_mbox_sram_error) begin
                    mbox_sram_wdata_bitflip <= '0;
                end
                else if (mbox_sram_cs & mbox_sram_we) begin
                    // Corrupt 10% of the writes
                    flip_bit = $urandom_range(0,99) < 10;
                    mbox_sram_wdata_bitflip <= flip_bit ? bitflip_gen.get_mask(inject_mbox_sram_error[1]) : '0;
//                    if (flip_bit) $display("%t Injecting bit flips", $realtime);
//                    else          $display("%t No bit flips injected", $realtime);
                end
            end
        end
    `else
        always @(posedge clk) begin
            if (~|inject_mbox_sram_error) begin
                flip_bit <= 0;
                mbox_sram_wdata_bitflip <= '0;
            end
            else if (mbox_sram_cs & mbox_sram_we) begin
                // Corrupt 10% of the writes
                flip_bit <= ($urandom % 100) < 10;
                mbox_sram_wdata_bitflip <= flip_bit ? get_bitflip_mask(inject_mbox_sram_error[1]) : '0;
            end
        end
    `endif

    initial cycleCnt = 0;
    initial cycleCntKillReq = 0;
    always @(negedge clk) begin
        cycleCnt <= cycleCnt+1;
        // Test timeout monitor
        if(cycleCnt == MAX_CYCLES && !UVM_TB) begin
            $error("Hit max cycle count (%0d) .. stopping",cycleCnt);
            dump_memory_contents(MEMTYPE_LMEM, 32'h8000_0110, 32'h8000_0180);
            dump_memory_contents(MEMTYPE_DCCM, `RV_DCCM_SADR, `RV_DCCM_EADR);
            dump_memory_contents(MEMTYPE_ICCM, `RV_ICCM_SADR, `RV_ICCM_EADR);
            $finish;
        end
        // console Monitor
        if( mailbox_data_val & mailbox_write) begin
            $fwrite(fd,"%c", WriteData[7:0]);
            // Prints get lost in sim.log amidst a flurry of UVM_INFO
            // messages....  best to just omit and send to console.log
            if (!UVM_TB) begin
                $write("%c", WriteData[7:0]);
            end
            if (WriteData[7:0] inside {8'h0A,8'h0D}) begin // CR/LF
                $fflush(fd);
            end
        end
        // Disable this for UVM simulations since control is delegated to
        // uvm tests/sequences
        // End Of test monitor
        if(mailbox_write && WriteData[7:0] == 8'hff) begin
            if (UVM_TB) $info("INFO: Detected FW write to manually end the test with SUCCESS; ignoring since the UVM environment will handle this.");
            else if (|cycleCntKillReq) begin
                $error("ERROR! FW attempted to end the simulation with SUCCESS after previously requesting to end the sim with FAILURE!");
            end
            else begin
                $display("* TESTCASE PASSED");
                $display("\nFinished : minstret = %0d, mcycle = %0d", `DEC.tlu.minstretl[31:0],`DEC.tlu.mcyclel[31:0]);
                $display("See \"exec.log\" for execution trace with register updates..\n");
                dump_memory_contents(MEMTYPE_LMEM, MBOX_DIR_START_ADDR, MBOX_DIR_END_ADDR);
                dump_memory_contents(MEMTYPE_DCCM, `RV_DCCM_SADR, `RV_DCCM_EADR);
                dump_memory_contents(MEMTYPE_ICCM, `RV_ICCM_SADR, `RV_ICCM_EADR);
                $finish;
            end
        end
        else if(mailbox_write && WriteData[7:0] == 8'h1) begin
            if (UVM_TB) $info("INFO: Detected FW write to manually end the test with FAIL; ignoring since the UVM environment will handle this.");
            else begin
                cycleCntKillReq <= cycleCnt;
                $error("* TESTCASE FAILED");
                $display(" -- Extending simulation for 100 clock cycles to capture ending waveform");
            end
        end
        if (|cycleCntKillReq && (cycleCnt == (cycleCntKillReq + 100))) begin
                $error("Dumping memory contents at simulation end due to FAILURE");
                dump_memory_contents(MEMTYPE_LMEM, MBOX_DIR_START_ADDR, MBOX_DIR_END_ADDR);
                dump_memory_contents(MEMTYPE_DCCM, `RV_DCCM_SADR, `RV_DCCM_EADR);
                dump_memory_contents(MEMTYPE_ICCM, `RV_ICCM_SADR, `RV_ICCM_EADR);
                $finish;
        end
    end


    // trace monitor
    always @(posedge clk) begin
        wb_valid  <= `DEC.dec_i0_wen_r;
        wb_dest   <= `DEC.dec_i0_waddr_r;
        wb_data   <= `DEC.dec_i0_wdata_r;
        if (`CPTRA_TOP_PATH.trace_rv_i_valid_ip && $test$plusargs("CLP_BUS_LOGS")) begin

           $fwrite(tp,"%b,%h,%h,%0h,%0h,3,%b,%h,%h,%b\n", `CPTRA_TOP_PATH.trace_rv_i_valid_ip, 0, `CPTRA_TOP_PATH.trace_rv_i_address_ip,
                  0, `CPTRA_TOP_PATH.trace_rv_i_insn_ip,`CPTRA_TOP_PATH.trace_rv_i_exception_ip,`CPTRA_TOP_PATH.trace_rv_i_ecause_ip,
                  `CPTRA_TOP_PATH.trace_rv_i_tval_ip,`CPTRA_TOP_PATH.trace_rv_i_interrupt_ip);
           // Basic trace - no exception register updates
           // #1 0 ee000000 b0201073 c 0b02       00000000
           commit_count++;
           $fwrite (el, "%10d : %8s 0 %h %h%13s ; %s\n", cycleCnt, $sformatf("#%0d",commit_count),
                        `CPTRA_TOP_PATH.trace_rv_i_address_ip, `CPTRA_TOP_PATH.trace_rv_i_insn_ip,
                        (wb_dest !=0 && wb_valid)?  $sformatf("%s=%h", abi_reg[wb_dest], wb_data) : "             ",
                        dasm(`CPTRA_TOP_PATH.trace_rv_i_insn_ip, `CPTRA_TOP_PATH.trace_rv_i_address_ip, wb_dest & {5{wb_valid}}, wb_data)
                   );
        end
        if(`DEC.dec_nonblock_load_wen) begin
            if ($test$plusargs("CLP_BUS_LOGS")) $fwrite (el, "%10d : %32s=%h ; nbL\n", cycleCnt, abi_reg[`DEC.dec_nonblock_load_waddr], `DEC.lsu_nonblock_load_data);
            caliptra_top_tb_services.gpr[0][`DEC.dec_nonblock_load_waddr] = `DEC.lsu_nonblock_load_data;
        end
        if(`DEC.exu_div_wren) begin
            if ($test$plusargs("CLP_BUS_LOGS")) $fwrite (el, "%10d : %32s=%h ; nbD\n", cycleCnt, abi_reg[`DEC.div_waddr_wb], `DEC.exu_div_result);
            caliptra_top_tb_services.gpr[0][`DEC.div_waddr_wb] = `DEC.exu_div_result;
        end
    end

    // IFU Initiator monitor
    always @(posedge clk) begin
        if ($test$plusargs("CLP_BUS_LOGS"))
        $fstrobe(ifu_p, "%10d : 0x%0h %h %b %h %h %h %b 0x%08h_%08h %b %b\n", cycleCnt, 
                        `CPTRA_TOP_PATH.ic_haddr, `CPTRA_TOP_PATH.ic_hburst, `CPTRA_TOP_PATH.ic_hmastlock, 
                        `CPTRA_TOP_PATH.ic_hprot, `CPTRA_TOP_PATH.ic_hsize, `CPTRA_TOP_PATH.ic_htrans, 
                        `CPTRA_TOP_PATH.ic_hwrite, `CPTRA_TOP_PATH.ic_hrdata[63:32], `CPTRA_TOP_PATH.ic_hrdata[31:0], 
                        `CPTRA_TOP_PATH.ic_hready, `CPTRA_TOP_PATH.ic_hresp);
    end

    // LSU Initiator monitor
    always @(posedge clk) begin
        if ($test$plusargs("CLP_BUS_LOGS"))
        $fstrobe(lsu_p, "%10d : 0x%0h %h %h %b 0x%08h_%08h 0x%08h_%08h %b %b\n", cycleCnt, 
                        `CPTRA_TOP_PATH.initiator_inst.haddr, `CPTRA_TOP_PATH.initiator_inst.hsize, `CPTRA_TOP_PATH.initiator_inst.htrans, 
                        `CPTRA_TOP_PATH.initiator_inst.hwrite, `CPTRA_TOP_PATH.initiator_inst.hrdata[63:32], `CPTRA_TOP_PATH.initiator_inst.hrdata[31:0], 
                        `CPTRA_TOP_PATH.initiator_inst.hwdata[63:32], `CPTRA_TOP_PATH.initiator_inst.hwdata[31:0], 
                        `CPTRA_TOP_PATH.initiator_inst.hready, `CPTRA_TOP_PATH.initiator_inst.hresp);
    end

    // AHB responder interfaces monitor
    genvar sl_i;
    generate
        for (sl_i = 0; sl_i < `CALIPTRA_AHB_SLAVES_NUM; sl_i = sl_i + 1) begin: gen_responder_inf_monitor
            always @(posedge clk) begin
                if ($test$plusargs("CLP_BUS_LOGS"))
                $fstrobe(sl_p[sl_i], "%10d : 0x%0h %h %h %b 0x%08h_%08h 0x%08h_%08h %b %b %b %b\n", cycleCnt, 
                        `CPTRA_TOP_PATH.responder_inst[sl_i].haddr, `CPTRA_TOP_PATH.responder_inst[sl_i].hsize, `CPTRA_TOP_PATH.responder_inst[sl_i].htrans, 
                        `CPTRA_TOP_PATH.responder_inst[sl_i].hwrite, `CPTRA_TOP_PATH.responder_inst[sl_i].hrdata[63:32], `CPTRA_TOP_PATH.responder_inst[sl_i].hrdata[31:0], 
                        `CPTRA_TOP_PATH.responder_inst[sl_i].hwdata[63:32], `CPTRA_TOP_PATH.responder_inst[sl_i].hwdata[31:0], 
                        `CPTRA_TOP_PATH.responder_inst[sl_i].hready, `CPTRA_TOP_PATH.responder_inst[sl_i].hreadyout, `CPTRA_TOP_PATH.responder_inst[sl_i].hresp, `CPTRA_TOP_PATH.responder_inst[sl_i].hsel);
            end
        end
    endgenerate

    logic preload_dccm_done;

    initial begin
        abi_reg[0] = "zero";
        abi_reg[1] = "ra";
        abi_reg[2] = "sp";
        abi_reg[3] = "gp";
        abi_reg[4] = "tp";
        abi_reg[5] = "t0";
        abi_reg[6] = "t1";
        abi_reg[7] = "t2";
        abi_reg[8] = "s0";
        abi_reg[9] = "s1";
        abi_reg[10] = "a0";
        abi_reg[11] = "a1";
        abi_reg[12] = "a2";
        abi_reg[13] = "a3";
        abi_reg[14] = "a4";
        abi_reg[15] = "a5";
        abi_reg[16] = "a6";
        abi_reg[17] = "a7";
        abi_reg[18] = "s2";
        abi_reg[19] = "s3";
        abi_reg[20] = "s4";
        abi_reg[21] = "s5";
        abi_reg[22] = "s6";
        abi_reg[23] = "s7";
        abi_reg[24] = "s8";
        abi_reg[25] = "s9";
        abi_reg[26] = "s10";
        abi_reg[27] = "s11";
        abi_reg[28] = "t3";
        abi_reg[29] = "t4";
        abi_reg[30] = "t5";
        abi_reg[31] = "t6";

        //generate_memory_hex_file(AXI_SRAM_BASE_ADDR, 65536, getenv("PLAYBOOK_RANDOM_SEED"));

        `ifndef VERILATOR
        imem_inst1.ram           = '{default:8'h0};
        dummy_mbox_preloader.ram = '{default:8'h0};
        dummy_iccm_preloader.ram = '{default:8'h0};
        dummy_dccm_preloader.ram = '{default:8'h0};
        `endif
        hex_file_is_empty = $system("test -s program.hex");
        if (!hex_file_is_empty) $readmemh("program.hex",  imem_inst1.ram,0,`CALIPTRA_IMEM_BYTE_SIZE-1);
        hex_file_is_empty = $system("test -s mailbox.hex");
        if (!hex_file_is_empty) $readmemh("mailbox.hex",  dummy_mbox_preloader.ram,0,MBOX_DIR_MEM_SIZE-1);
        hex_file_is_empty = $system("test -s dccm.hex");
        if (!hex_file_is_empty) $readmemh("dccm.hex",     dummy_dccm_preloader.ram,0,`RV_DCCM_EADR - `RV_DCCM_SADR);
        hex_file_is_empty = $system("test -s iccm.hex");
        if (!hex_file_is_empty) $readmemh("iccm.hex",     dummy_iccm_preloader.ram,0,`RV_ICCM_EADR - `RV_ICCM_SADR);
       
        `ifdef CALIPTRA_TOP_TB
        $display("Initializing AXI SRAM with random data");
        if ($test$plusargs("CPTRA_RAND_TEST_DMA")) begin
            initialize_caliptra_axi_sram();
        end
        `endif
        
        if ($test$plusargs("CLP_BUS_LOGS")) begin
            tp = $fopen("trace_port.csv","w");
            el = $fopen("exec.log","w");
            ifu_p = $fopen("ifu_master_ahb_trace.log", "w");
            lsu_p = $fopen("lsu_master_ahb_trace.log", "w");
        end
        if ($test$plusargs("CLP_BUS_LOGS")) begin
            $fwrite (el, "//   Cycle : #inst    0    pc    opcode    reg=value   ; mnemonic\n");
            $fwrite(ifu_p, "//   Cycle: ic_haddr     ic_hburst     ic_hmastlock     ic_hprot     ic_hsize     ic_htrans     ic_hwrite     ic_hrdata     ic_hwdata     ic_hready     ic_hresp\n");
            $fwrite(lsu_p, "//   Cycle: lsu_haddr     lsu_hsize     lsu_htrans     lsu_hwrite     lsu_hrdata     lsu_hwdata     lsu_hready     lsu_hresp\n");

            for (j = 0; j < `CALIPTRA_AHB_SLAVES_NUM; j = j + 1) begin
                slaveLog_fileName[j] = {$sformatf("slave%0d_ahb_trace.log", j)};
                sl_p[j] = $fopen(slaveLog_fileName[j], "w");
                $fwrite(sl_p[j], "//   Cycle: haddr     hsize     htrans     hwrite     hrdata     hwdata     hready     hreadyout     hresp\n");
            end
        end

        fd = $fopen("console.log","w");
        commit_count = 0;
        preload_dccm();
        preload_iccm();
        preload_mbox();

        assert_hard_rst_flag = 0;
        deassert_hard_rst_flag = 0;
        assert_rst_flag = 0;
        deassert_rst_flag = 0;

        cold_rst = 0;
        warm_rst = 0;
        timed_warm_rst = 0;
        cold_rst_done = 0;
        prandom_warm_rst = 0;

        scan_mode = 0;
        wait_time_to_rst = 0;

        set_wdt_timer1_period = 0;
        assert_ss_tran = 0;
        en_jtag_access = 0;

        `ifndef VERILATOR
        if (!UVM_TB) begin
            ecc_testvector_generator();
            doe_testvector_generator();
            sha256_wntz_testvector_generator();
            mldsa_input_hex_gen();

            //Note: Both obf_key_uds and obf_key_fe are the same
            //for(int dword = 0; dword < `CLP_OBF_KEY_DWORDS; dword++) begin
            //    cptra_obf_key_tb[dword] = doe_test_vector.obf_key_uds[(`CLP_OBF_KEY_DWORDS-1)-dword];
            //end
            cptra_obf_key_tb = doe_test_vector.obf_key_uds;
            for(int dword = 0; dword < `CLP_OBF_UDS_DWORDS; dword++) begin
                cptra_uds_tb[dword] = doe_test_vector.uds_ciphertext[dword];
            end
            for(int dword = 0; dword < `CLP_OBF_FE_DWORDS; dword++) begin
                cptra_fe_tb[dword] = doe_test_vector.fe_ciphertext[dword];
            end
        end
        `endif
    end

   //=========================================================================-
   // SRAM instances
   //=========================================================================-
  // SRAM module
mldsa_mem_top mldsa_mem_top_inst (
    .clk_i(clk),
    .mldsa_memory_export
);

caliptra_veer_sram_export veer_sram_export_inst (
    .sram_error_injection_mode(sram_error_injection_mode),
    .el2_mem_export(el2_mem_export)
);

//SRAM for mbox (preload raw data here)
caliptra_sram 
#(
    .DATA_WIDTH(CPTRA_MBOX_DATA_W),
    .DEPTH     (CPTRA_MBOX_DEPTH )
)
dummy_mbox_preloader
(
    .clk_i(clk),

    .cs_i   (),
    .we_i   (),
    .addr_i (),
    .wdata_i(),
    .rdata_o()
);
// Actual Mailbox RAM -- preloaded with data from
// dummy_mbox_preloader with ECC bits appended
caliptra_sram 
#(
    .DATA_WIDTH(CPTRA_MBOX_DATA_AND_ECC_W),
    .DEPTH     (CPTRA_MBOX_DEPTH         )
)
mbox_ram1
(
    .clk_i(clk),

    .cs_i(mbox_sram_cs),
    .we_i(mbox_sram_we),
    .addr_i(mbox_sram_addr),
    .wdata_i(mbox_sram_wdata ^ mbox_sram_wdata_bitflip),

    .rdata_o(mbox_sram_rdata)
);

//SRAM for imem
caliptra_sram #(
    .DEPTH     (`CALIPTRA_IMEM_DEPTH     ), // Depth in WORDS
    .DATA_WIDTH(`CALIPTRA_IMEM_DATA_WIDTH),
    .ADDR_WIDTH(`CALIPTRA_IMEM_ADDR_WIDTH)
) imem_inst1 (
    .clk_i   (clk   ),

    .cs_i    (imem_cs),
    .we_i    (1'b0/*sram_write && sram_dv*/      ),
    .addr_i  (imem_addr                          ),
    .wdata_i (`CALIPTRA_IMEM_DATA_WIDTH'(0)/*sram_wdata   */),
    .rdata_o (imem_rdata                         )
);

// This is used to load the generated ICCM hexfile prior to
// running slam_iccm_ram
caliptra_sram #(
     .DEPTH     (ICCM_PRELOADER_DEPTH     ),
     .DATA_WIDTH(ICCM_PRELOADER_WIDTH     ),
     .ADDR_WIDTH(ICCM_PRELOADER_ADDR_WIDTH)

) dummy_iccm_preloader (
    .clk_i   (clk),

    .cs_i    (        ),
    .we_i    (        ),
    .addr_i  (        ),
    .wdata_i (        ),
    .rdata_o (        )
);


// This is used to load the generated DCCM hexfile prior to
// running slam_dccm_ram
caliptra_sram #(
     .DEPTH     (DCCM_PRELOADER_DEPTH     ),
     .DATA_WIDTH(DCCM_PRELOADER_WIDTH     ),
     .ADDR_WIDTH(DCCM_PRELOADER_ADDR_WIDTH)

) dummy_dccm_preloader (
    .clk_i   (clk),

    .cs_i    (        ),
    .we_i    (        ),
    .addr_i  (        ),
    .wdata_i (        ),
    .rdata_o (        )
);

// DMA Test case generator
// Interface instance
//dma_transfer_if dma_xfer_if;

`ifndef VERILATOR
// Testcase generator instance 
dma_transfer_randomizer dma_xfers[];

dma_testcase_generator i_dma_gen (
    .preload_dccm_done (preload_dccm_done                  ),
    .dma_gen_done      (axi_complex_ctrl.dma_gen_done      ),
    .dma_gen_block_size(axi_complex_ctrl.dma_gen_block_size)
    );
/*
initial begin
    // Wait for the test cases to be generated
    wait (dma_gen_done);

    // Retrieve the generated test cases
    i_dma_gen.get_dma_xfers(dma_xfers);
end
*/
`else
    always@(posedge clk) axi_complex_ctrl.dma_gen_done       <= 1'b0;
    always@(posedge clk) axi_complex_ctrl.dma_gen_block_size <= '0;
`endif

   //=========================================================================-
   // SRAM preload services
   //=========================================================================-
task static preload_mbox;
    // Variables
    cptra_mbox_sram_data_t         ecc_data;
    bit [CPTRA_MBOX_ADDR_W:0] addr;
    int                      byt;
    localparam NUM_BYTES = CPTRA_MBOX_DATA_AND_ECC_W / 8 + ((CPTRA_MBOX_DATA_AND_ECC_W%8) ? 1 : 0);

    // Init
    `ifndef VERILATOR
    mbox_ram1.ram = '{default:8'h0};
    `endif

    // Slam
    $display("MBOX pre-load from %h to %h", 0, CPTRA_MBOX_DEPTH);
    
    for (addr = 0; addr < CPTRA_MBOX_DEPTH; addr++) begin
        ecc_data.data = {dummy_mbox_preloader.ram[addr][3],
                         dummy_mbox_preloader.ram[addr][2],
                         dummy_mbox_preloader.ram[addr][1],
                         dummy_mbox_preloader.ram[addr][0]};
        ecc_data.ecc  = |ecc_data.data ? riscv_ecc32(ecc_data.data) : 0;
        for (byt = 0; byt < NUM_BYTES; byt++) begin
            mbox_ram1.ram[addr][byt] = ecc_data[byt*8+:8];
        end
    end
    $display("MBOX pre-load completed");
endtask

task static preload_iccm;
    bit[31:0] data;
    bit[31:0] addr, eaddr, saddr;

    `ifndef VERILATOR
    init_iccm();
    `endif
    saddr = `RV_ICCM_SADR;
    if ( (saddr < `RV_ICCM_SADR) || (saddr > `RV_ICCM_EADR)) return;
    `ifndef RV_ICCM_ENABLE
        $display("********************************************************");
        $display("ICCM preload: there is no ICCM in VeeR, terminating !!!");
        $display("********************************************************");
        $finish;
    `endif
    eaddr = `RV_ICCM_EADR;
    $display("ICCM pre-load from %h to %h", saddr, eaddr);

    for(addr= saddr; addr <= eaddr; addr+=4) begin
        // FIXME hardcoded address indices?
        data = {dummy_iccm_preloader.ram [addr[`RV_ICCM_BITS-1:3]] [{addr[2],2'h3}],
                dummy_iccm_preloader.ram [addr[`RV_ICCM_BITS-1:3]] [{addr[2],2'h2}],
                dummy_iccm_preloader.ram [addr[`RV_ICCM_BITS-1:3]] [{addr[2],2'h1}],
                dummy_iccm_preloader.ram [addr[`RV_ICCM_BITS-1:3]] [{addr[2],2'h0}]};
        //data = {`CPTRA_TOP_PATH.imem.mem[addr+3],`CPTRA_TOP_PATH.imem.mem[addr+2],`CPTRA_TOP_PATH.imem.mem[addr+1],`CPTRA_TOP_PATH.imem.mem[addr]};
        slam_iccm_ram(addr, data == 0 ? 0 : {riscv_ecc32(data),data});
    end
    $display("ICCM pre-load completed");

endtask


task static preload_dccm ();
    bit[31:0] data;
    bit[31:0] addr, saddr, eaddr;

    `ifndef VERILATOR
    init_dccm();
    `endif
    saddr = `RV_DCCM_SADR;
    if (saddr < `RV_DCCM_SADR || saddr > `RV_DCCM_EADR) return;
    `ifndef RV_DCCM_ENABLE
        $display("********************************************************");
        $display("DCCM preload: there is no DCCM in VeeR, terminating !!!");
        $display("********************************************************");
        $finish;
    `endif
    eaddr = `RV_DCCM_EADR;
    $display("DCCM pre-load from %h to %h", saddr, eaddr);

    for(addr=saddr; addr <= eaddr; addr+=4) begin
        // FIXME hardcoded address indices?
        data = {dummy_dccm_preloader.ram [addr[`RV_DCCM_BITS:3]] [{addr[2],2'h3}],
                dummy_dccm_preloader.ram [addr[`RV_DCCM_BITS:3]] [{addr[2],2'h2}],
                dummy_dccm_preloader.ram [addr[`RV_DCCM_BITS:3]] [{addr[2],2'h1}],
                dummy_dccm_preloader.ram [addr[`RV_DCCM_BITS:3]] [{addr[2],2'h0}]};
        slam_dccm_ram(addr, data == 0 ? 0 : {riscv_ecc32(data),data});
    end
    $display("DCCM pre-load completed");
    preload_dccm_done = 1;

endtask



`define ICCM_PATH veer_sram_export_inst.Gen_iccm_enable
`ifdef VERILATOR
`define DRAM(bk) veer_sram_export_inst.Gen_dccm_enable.dccm_loop[bk].ram.ram_core
`define IRAM(bk) `ICCM_PATH.iccm_loop[bk].iccm_bank.ram_core
`else
`define DRAM(bk) veer_sram_export_inst.Gen_dccm_enable.dccm_loop[bk].dccm.dccm_bank.ram_core
`define IRAM(bk) `ICCM_PATH.iccm_loop[bk].iccm.iccm_bank.ram_core
`endif


task static slam_dccm_ram(input [31:0] addr, input[38:0] data);
    int bank, indx;
    bank = get_dccm_bank(addr, indx);
    `ifdef RV_DCCM_ENABLE
    case(bank)
    0: `DRAM(0)[indx] = data;
    1: `DRAM(1)[indx] = data;
    `ifdef RV_DCCM_NUM_BANKS_4
    2: `DRAM(2)[indx] = data;
    3: `DRAM(3)[indx] = data;
    `endif
    `ifdef RV_DCCM_NUM_BANKS_8
    2: `DRAM(2)[indx] = data;
    3: `DRAM(3)[indx] = data;
    4: `DRAM(4)[indx] = data;
    5: `DRAM(5)[indx] = data;
    6: `DRAM(6)[indx] = data;
    7: `DRAM(7)[indx] = data;
    `endif
    endcase
    `endif
    //$display("Writing bank %0d indx=%0d A=%h, D=%h",bank, indx, addr, data);
endtask


task static slam_iccm_ram( input[31:0] addr, input[38:0] data);
    int bank, idx;

    bank = get_iccm_bank(addr, idx);
    `ifdef RV_ICCM_ENABLE
    case(bank) // {
      0: `IRAM(0)[idx] = data;
      1: `IRAM(1)[idx] = data;
     `ifdef RV_ICCM_NUM_BANKS_4
      2: `IRAM(2)[idx] = data;
      3: `IRAM(3)[idx] = data;
     `endif
     `ifdef RV_ICCM_NUM_BANKS_8
      2: `IRAM(2)[idx] = data;
      3: `IRAM(3)[idx] = data;
      4: `IRAM(4)[idx] = data;
      5: `IRAM(5)[idx] = data;
      6: `IRAM(6)[idx] = data;
      7: `IRAM(7)[idx] = data;
     `endif

     `ifdef RV_ICCM_NUM_BANKS_16
      2: `IRAM(2)[idx] = data;
      3: `IRAM(3)[idx] = data;
      4: `IRAM(4)[idx] = data;
      5: `IRAM(5)[idx] = data;
      6: `IRAM(6)[idx] = data;
      7: `IRAM(7)[idx] = data;
      8: `IRAM(8)[idx] = data;
      9: `IRAM(9)[idx] = data;
      10: `IRAM(10)[idx] = data;
      11: `IRAM(11)[idx] = data;
      12: `IRAM(12)[idx] = data;
      13: `IRAM(13)[idx] = data;
      14: `IRAM(14)[idx] = data;
      15: `IRAM(15)[idx] = data;
     `endif
    endcase // }
    `endif
endtask

task static init_iccm;
    `ifdef RV_ICCM_ENABLE
        `IRAM(0) = '{default:39'h0};
        `IRAM(1) = '{default:39'h0};
    `ifdef RV_ICCM_NUM_BANKS_4
        `IRAM(2) = '{default:39'h0};
        `IRAM(3) = '{default:39'h0};
    `endif
    `ifdef RV_ICCM_NUM_BANKS_8
        `IRAM(4) = '{default:39'h0};
        `IRAM(5) = '{default:39'h0};
        `IRAM(6) = '{default:39'h0};
        `IRAM(7) = '{default:39'h0};
    `endif

    `ifdef RV_ICCM_NUM_BANKS_16
        `IRAM(4) = '{default:39'h0};
        `IRAM(5) = '{default:39'h0};
        `IRAM(6) = '{default:39'h0};
        `IRAM(7) = '{default:39'h0};
        `IRAM(8) = '{default:39'h0};
        `IRAM(9) = '{default:39'h0};
        `IRAM(10) = '{default:39'h0};
        `IRAM(11) = '{default:39'h0};
        `IRAM(12) = '{default:39'h0};
        `IRAM(13) = '{default:39'h0};
        `IRAM(14) = '{default:39'h0};
        `IRAM(15) = '{default:39'h0};
     `endif
    `endif
endtask

task static init_dccm;
    `ifdef RV_DCCM_ENABLE
        `DRAM(0) = '{default:39'h0};
        `DRAM(1) = '{default:39'h0};
    `ifdef RV_DCCM_NUM_BANKS_4
        `DRAM(2) = '{default:39'h0};
        `DRAM(3) = '{default:39'h0};
    `endif
    `ifdef RV_DCCM_NUM_BANKS_8
        `DRAM(4) = '{default:39'h0};
        `DRAM(5) = '{default:39'h0};
        `DRAM(6) = '{default:39'h0};
        `DRAM(7) = '{default:39'h0};
    `endif
    `endif
endtask

task static dump_memory_contents;
    input [2:0] mem_type;
    input [31:0] start_addr;
    input [31:0] end_addr;

    bit [31:0] addr;
    bit [38:0] ecc_data;
    bit [7:0] data;
    string outfile;

    int bank, indx; 

    int of;

    //$display(`DRAM);

    case (mem_type)
        MEMTYPE_LMEM:  outfile = "lmem_data_dump.hex";
        MEMTYPE_DCCM:  outfile = "dccm_data_dump.hex";
        MEMTYPE_ICCM:  outfile = "iccm_data_dump.hex";
        default:       outfile = "";
    endcase

    of = $fopen(outfile, "w");
    for (addr = start_addr; addr <= start_addr + 112; addr = addr + 1) begin
        case (mem_type)
            MEMTYPE_LMEM: data = `LMEM[addr[31:2]][addr[1:0]];
            MEMTYPE_DCCM: begin
                            bank = get_dccm_bank(addr, indx);
                            `ifdef RV_DCCM_ENABLE
                            case(bank)
                                0: ecc_data = `DRAM(0)[indx];
                                1: ecc_data = `DRAM(1)[indx];
                                `ifdef RV_DCCM_NUM_BANKS_4
                                2: ecc_data = `DRAM(2)[indx];
                                3: ecc_data = `DRAM(3)[indx];
                                `endif
                                `ifdef RV_DCCM_NUM_BANKS_8
                                2: ecc_data = `DRAM(2)[indx];
                                3: ecc_data = `DRAM(3)[indx];
                                4: ecc_data = `DRAM(4)[indx];
                                5: ecc_data = `DRAM(5)[indx];
                                6: ecc_data = `DRAM(6)[indx];
                                7: ecc_data = `DRAM(7)[indx];
                                `endif
                            endcase
                            `endif
            end
            MEMTYPE_ICCM: begin
                            bank = get_iccm_bank(addr, indx);
                            `ifdef RV_ICCM_ENABLE
                            case(bank) // {
                                0: ecc_data =  `IRAM(0)[indx];
                                1: ecc_data = `IRAM(1)[indx];
                                `ifdef RV_ICCM_NUM_BANKS_4
                                2: ecc_data = `IRAM(2)[indx];
                                3: ecc_data = `IRAM(3)[indx];
                                `endif
                                `ifdef RV_ICCM_NUM_BANKS_8
                                2: ecc_data = `IRAM(2)[indx];
                                3: ecc_data = `IRAM(3)[indx];
                                4: ecc_data = `IRAM(4)[indx];
                                5: ecc_data = `IRAM(5)[indx];
                                6: ecc_data = `IRAM(6)[indx];
                                7: ecc_data = `IRAM(7)[indx];
                                `endif
                                `ifdef RV_ICCM_NUM_BANKS_16
                                2: ecc_data = `IRAM(2)[indx];
                                3: ecc_data = `IRAM(3)[indx];
                                4: ecc_data = `IRAM(4)[indx];
                                5: ecc_data = `IRAM(5)[indx];
                                6: ecc_data = `IRAM(6)[indx];
                                7: ecc_data = `IRAM(7)[indx];
                                8: ecc_data = `IRAM(8)[indx];
                                9: ecc_data = `IRAM(9)[indx];
                                10: ecc_data = `IRAM(10)[indx];
                                11: ecc_data = `IRAM(11)[indx];
                                12: ecc_data = `IRAM(12)[indx];
                                13: ecc_data = `IRAM(13)[indx];
                                14: ecc_data = `IRAM(14)[indx];
                                15: ecc_data = `IRAM(15)[indx];
                                `endif
                            endcase // }
                            `endif
            end
            default: begin
                data = 0;
                bank = 0;
                ecc_data = 0;
            end
        endcase

        case (mem_type)
            MEMTYPE_LMEM: begin 
                            if ((addr & 'hF) == 0) begin
                                $fwrite(of, "%0x:\t%x ", addr, data);
                            end
                            else if ((addr & 'hF) == 'hF) begin
                                $fwrite(of, "%x\n", data);
                            end
                            else begin
                                $fwrite(of, "%x ", data);
                            end
            end
            MEMTYPE_DCCM,
            MEMTYPE_ICCM: begin
                            if ((addr & 'hF) == 0) begin
                                $fwrite(of, "%0x:\t%x ", addr, ecc_data);
                            end
                            else if ((addr & 'hF) == 'hC) begin
                                $fwrite(of, "%x\n", ecc_data);
                            end
                            else if (((addr & 'hF) == 'h4)|| ((addr & 'hF) == 'h8)) begin
                                $fwrite(of, "%x ", ecc_data);
                            end
            end
            default: begin end
        endcase
    end
endtask

`ifdef CALIPTRA_TOP_TB
// Initialize AXI SRAM with random data 
task initialize_caliptra_axi_sram;
    
    integer addr, byte_idx;
    reg [7:0] random_byte;
    
    begin

        if (!UVM_TB) begin
        
            $display("Starting Caliptra SRAM initialization with random data (64K addresses, 4 bytes per address)...");
            
            // Loop through all addresses (64K) and all bytes per address (4 for 32-bit data)
            for (addr = 0; addr < AXI_SRAM_DEPTH; addr = addr + 1) begin
                // For each address, initialize all bytes
                for (byte_idx = 0; byte_idx < 4; byte_idx = byte_idx + 1) begin
                    random_byte = $random & 8'hFF;  // Generate random byte (8 bits)
                    
                    // Direct assignment
                    `CALIPTRA_TOP.tb_axi_complex_i.i_axi_sram.i_sram.ram[addr][byte_idx] = random_byte;
                end
                
                // Progress reporting every 12.5% (8192 addresses)
                if (addr % (AXI_SRAM_DEPTH/8) == 0) begin
                    $display("  SRAM initialization progress: %0d%% (addr: 0x%x)", (addr * 100) / AXI_SRAM_DEPTH, addr);
                end
            end
            
            $display("Caliptra SRAM initialization complete!");
        end
    end
endtask
`endif


function[6:0] riscv_ecc32(input[31:0] data);
    reg[6:0] synd;
    synd[0] = ^(data & 32'h56aa_ad5b);
    synd[1] = ^(data & 32'h9b33_366d);
    synd[2] = ^(data & 32'he3c3_c78e);
    synd[3] = ^(data & 32'h03fc_07f0);
    synd[3] = ^(data & 32'h03fc_07f0);
    synd[4] = ^(data & 32'h03ff_f800);
    synd[5] = ^(data & 32'hfc00_0000);
    synd[6] = ^{data, synd[5:0]};
    return synd;
endfunction

function int get_dccm_bank(input[31:0] addr,  output int bank_idx);
    `ifdef RV_DCCM_NUM_BANKS_2
        bank_idx = int'(addr[`RV_DCCM_BITS-1:3]);
        return int'( addr[2]);
    `elsif RV_DCCM_NUM_BANKS_4
        bank_idx = int'(addr[`RV_DCCM_BITS-1:4]);
        return int'(addr[3:2]);
    `elsif RV_DCCM_NUM_BANKS_8
        bank_idx = int'(addr[`RV_DCCM_BITS-1:5]);
        return int'( addr[4:2]);
    `endif
endfunction

function int get_iccm_bank(input[31:0] addr,  output int bank_idx);
    `ifdef RV_DCCM_NUM_BANKS_2
        bank_idx = int'(addr[`RV_DCCM_BITS-1:3]);
        return int'( addr[2]);
    `elsif RV_ICCM_NUM_BANKS_4
        bank_idx = int'(addr[`RV_ICCM_BITS-1:4]);
        return int'(addr[3:2]);
    `elsif RV_ICCM_NUM_BANKS_8
        bank_idx = int'(addr[`RV_ICCM_BITS-1:5]);
        return int'( addr[4:2]);
    `elsif RV_ICCM_NUM_BANKS_16
        bank_idx = int'(addr[`RV_ICCM_BITS-1:6]);
        return int'( addr[5:2]);
    `endif
endfunction

`ifndef VERILATOR
soc_ifc_cov_bind i_soc_ifc_cov_bind();
caliptra_top_cov_bind i_caliptra_top_cov_bind();
sha512_ctrl_cov_bind i_sha512_ctrl_cov_bind();
sha256_ctrl_cov_bind i_sha256_ctrl_cov_bind();
hmac_ctrl_cov_bind i_hmac_ctrl_cov_bind();
hmac_drbg_cov_bind i_hmac_drbg_cov_bind();
ecc_top_cov_bind i_ecc_top_cov_bind();
mldsa_top_cov_bind i_mldsa_top_cov_bind();
keyvault_cov_bind i_keyvault_cov_bind();
pcrvault_cov_bind i_pcrvault_cov_bind();
axi_dma_top_cov_bind i_axi_dma_top_cov_bind();
`endif

/* verilator lint_off CASEINCOMPLETE */
`include "dasm.svi"
/* verilator lint_on CASEINCOMPLETE */


endmodule
