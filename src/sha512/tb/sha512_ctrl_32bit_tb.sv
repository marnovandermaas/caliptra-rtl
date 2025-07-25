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
//======================================================================
//
// sha512_ctrl_32bit_tb.sv
// --------
// SHA512 testbench for the SHA512 AHb_lite interface controller.
//
//
//======================================================================

`include "caliptra_reg_defines.svh"
`include "caliptra_reg_field_defines.svh"

module sha512_ctrl_32bit_tb 
  import kv_defines_pkg::*;
  import pv_defines_pkg::*;
  ();

//----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter DEBUG = 0;

  parameter CLK_HALF_PERIOD = 1;
  parameter CLK_PERIOD      = 2 * CLK_HALF_PERIOD;

  parameter MODE_SHA_512_224     = 2'h0;
  parameter MODE_SHA_512_256     = 2'h1;
  parameter MODE_SHA_384         = 2'h2;
  parameter MODE_SHA_512         = 2'h3;

  parameter INIT_CMD             = (1 << `SHA512_REG_SHA512_CTRL_INIT_LOW) & (`SHA512_REG_SHA512_CTRL_INIT_MASK);
  parameter NEXT_CMD             = (1 << `SHA512_REG_SHA512_CTRL_NEXT_LOW) & (`SHA512_REG_SHA512_CTRL_NEXT_MASK);
  parameter RESTORE_CMD          = (1 << `SHA512_REG_SHA512_CTRL_RESTORE_LOW) & (`SHA512_REG_SHA512_CTRL_RESTORE_MASK);
  parameter ZEROIZE_CMD          = (1 << `SHA512_REG_SHA512_CTRL_ZEROIZE_LOW) & (`SHA512_REG_SHA512_CTRL_ZEROIZE_MASK);

  parameter AHB_HTRANS_IDLE      = 0;
  parameter AHB_HTRANS_BUSY      = 1;
  parameter AHB_HTRANS_NONSEQ    = 2;
  parameter AHB_HTRANS_SEQ       = 3;

  parameter AHB_ADDR_WIDTH       = 32;
  parameter AHB_DATA_WIDTH       = 32;

  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  reg [31 : 0]  cycle_ctr;
  reg [31 : 0]  error_ctr;
  reg [31 : 0]  tc_ctr;

  reg           clk_tb;
  reg           reset_n_tb;
  reg           cptra_pwrgood_tb;

  reg [AHB_ADDR_WIDTH-1:0]  haddr_i_tb;
  reg [AHB_DATA_WIDTH-1:0]  hwdata_i_tb;
  reg           hsel_i_tb;
  reg           hwrite_i_tb; 
  reg           hready_i_tb;
  reg [1:0]     htrans_i_tb;
  reg [2:0]     hsize_i_tb;

  wire          hresp_o_tb;
  wire          hreadyout_o_tb;
  wire [AHB_DATA_WIDTH-1:0] hrdata_o_tb;

  pv_read_t pv_read_tb;
  pv_write_t pv_write_tb;
  pv_rd_resp_t pv_rd_resp_tb;
  pv_wr_resp_t pv_wr_resp_tb;
  logic [KV_NUM_DWORDS-1:0][31:0] pcr_signing_hash_tb;

  wire error_intr_tb;
  wire notif_intr_tb;

  reg [31 : 0]  read_data;
  reg [511 : 0] digest_data;

  //bind coverage file
  sha512_ctrl_cov_bind i_sha512_ctrl_cov_bind();

  //----------------------------------------------------------------
  // Device Under Test.
  //----------------------------------------------------------------
  sha512_ctrl #(
             .AHB_DATA_WIDTH(32),
             .AHB_ADDR_WIDTH(32)
            )
            dut (
             .clk(clk_tb),
             .reset_n(reset_n_tb),
             .cptra_pwrgood(cptra_pwrgood_tb),

             .haddr_i(haddr_i_tb),
             .hwdata_i(hwdata_i_tb),
             .hsel_i(hsel_i_tb),
             .hwrite_i(hwrite_i_tb),
             .hready_i(hready_i_tb),
             .htrans_i(htrans_i_tb),
             .hsize_i(hsize_i_tb),

             .hresp_o(hresp_o_tb),
             .hreadyout_o(hreadyout_o_tb),
             .hrdata_o(hrdata_o_tb),

             .pcr_signing_hash(pcr_signing_hash_tb),
             .pv_read(pv_read_tb),
             .pv_rd_resp(pv_rd_resp_tb),
             .pv_write(pv_write_tb),
             .pv_wr_resp(pv_wr_resp_tb),

             .error_intr(error_intr_tb),
             .notif_intr(notif_intr_tb),
             .debugUnlock_or_scan_mode_switch('0)
            );

  //----------------------------------------------------------------
  // clk_gen
  //
  // Clock generator process.
  //----------------------------------------------------------------
  always
    begin : clk_gen
      #CLK_HALF_PERIOD clk_tb = !clk_tb;
    end // clk_gen

  //----------------------------------------------------------------
  // sys_monitor
  //
  // Generates a cycle counter and displays information about
  // the dut as needed.
  //----------------------------------------------------------------
  always
    begin : sys_monitor
      #(CLK_PERIOD);
      cycle_ctr = cycle_ctr + 1;
    end

  //----------------------------------------------------------------
  // reset_dut()
  //
  // Toggles reset to force the DUT into a well defined state.
  //----------------------------------------------------------------
  task reset_dut;
    begin
      $display("*** Toggle reset.");
      reset_n_tb = 0;
      cptra_pwrgood_tb = 0;

      #(4 * CLK_HALF_PERIOD);

      reset_n_tb = 1;
      cptra_pwrgood_tb = 1;
    end
  endtask // reset_dut


  //----------------------------------------------------------------
  // init_sim()
  //
  // Initialize all counters and testbed functionality as well
  // as setting the DUT inputs to defined values.
  //----------------------------------------------------------------
  task init_sim;
    begin
      cycle_ctr = 32'h00000000;
      error_ctr = 32'h00000000;
      tc_ctr    = 32'h00000000;

      clk_tb        = 0;
      reset_n_tb    = 0;
      cptra_pwrgood_tb = 0;

      haddr_i_tb      = 0;
      hwdata_i_tb     = 0;
      hsel_i_tb       = 0;
      hwrite_i_tb     = 0;
      hready_i_tb     = 0;
      htrans_i_tb     = AHB_HTRANS_IDLE;
      hsize_i_tb      = 3'b011;

      pv_wr_resp_tb   = '0;
      pv_rd_resp_tb   = '0;
    end
  endtask // init_dut

  //----------------------------------------------------------------
  // display_test_result()
  //
  // Display the accumulated test results.
  //----------------------------------------------------------------
  task display_test_result;
    begin
      if (error_ctr == 0)
        begin
          $display("*** All %02d test cases completed successfully.", tc_ctr);
          $display("* TESTCASE PASSED");
        end
      else
        begin
          $display("*** %02d test cases completed.", tc_ctr);
          $display("*** %02d errors detected during testing.", error_ctr);
          $display("* TESTCASE FAILED");
        end
    end
  endtask // display_test_result

  //----------------------------------------------------------------
  // wait_ready()
  //
  // Wait for the ready flag in the dut to be set.
  // (Actually we wait for either ready or valid to be set.)
  //
  // Note: It is the callers responsibility to call the function
  // when the dut is actively processing and will in fact at some
  // point set the flag.
  //----------------------------------------------------------------
  task wait_ready;
    begin
      read_data = 0;
      #(CLK_PERIOD);

      while (read_data == 0)
        begin
          read_single_word(`SHA512_REG_SHA512_STATUS);
        end
    end
  endtask // wait_ready

  //----------------------------------------------------------------
  // read_word()
  //
  // Read a data word from the given address in the DUT.
  // the word read will be available in the global variable
  // read_data.
  //----------------------------------------------------------------
  task read_single_word(input [31 : 0]  address);
    begin
      hsel_i_tb       = 1;
      haddr_i_tb      = address;
      hwrite_i_tb     = 0;
      hready_i_tb     = 1;
      htrans_i_tb     = AHB_HTRANS_NONSEQ;
      hsize_i_tb      = 3'b010;
      #(CLK_PERIOD);
      
      hwdata_i_tb     = 0;
      haddr_i_tb     = 'Z;
      htrans_i_tb     = AHB_HTRANS_IDLE;

      read_data = hrdata_o_tb;

    end
  endtask // read_word


  //----------------------------------------------------------------
  // write_single_word()
  //
  // Write the given word to the DUT using the DUT interface.
  //----------------------------------------------------------------
  task write_single_word(input [31 : 0]  address,
                  input [31 : 0] word);
    begin
      hsel_i_tb       = 1;
      haddr_i_tb      = address;
      hwrite_i_tb     = 1;
      hready_i_tb     = 1;
      htrans_i_tb     = AHB_HTRANS_NONSEQ;
      hsize_i_tb      = 3'b010;
      #(CLK_PERIOD);

      haddr_i_tb      = 'Z;
      hwdata_i_tb     = word;
      hwrite_i_tb     = 0;
      htrans_i_tb     = AHB_HTRANS_IDLE;
    end
  endtask // write_single_word


  //----------------------------------------------------------------
  // write_block()
  //
  // Write the given block to the dut.
  //----------------------------------------------------------------
  task write_block(input [1023 : 0] block);
    begin
      write_single_word(`SHA512_REG_SHA512_BLOCK_0,  block[1023 : 992]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_1,  block[991  : 960]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_2,  block[959  : 928]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_3,  block[927  : 896]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_4,  block[895  : 864]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_5,  block[863  : 832]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_6,  block[831  : 800]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_7,  block[799  : 768]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_8,  block[767  : 736]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_9,  block[735  : 704]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_10, block[703  : 672]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_11, block[671  : 640]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_12, block[639  : 608]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_13, block[607  : 576]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_14, block[575  : 544]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_15, block[543  : 512]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_16, block[511  : 480]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_17, block[479  : 448]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_18, block[447  : 416]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_19, block[415  : 384]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_20, block[383  : 352]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_21, block[351  : 320]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_22, block[319  : 288]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_23, block[287  : 256]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_24, block[255  : 224]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_25, block[223  : 192]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_26, block[191  : 160]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_27, block[159  : 128]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_28, block[127  :  96]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_29, block[95   :  64]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_30, block[63   :  32]);
      write_single_word(`SHA512_REG_SHA512_BLOCK_31, block[31   :   0]);
    end
  endtask // write_block

  //----------------------------------------------------------------
  // mode_cmd()
  //
  // Create the mode_cmd needed for a given mode.
  //----------------------------------------------------------------
  function [31 : 0] mode_cmd(input [1:0] mode);
    begin
      mode_cmd = (mode << `SHA512_REG_SHA512_CTRL_MODE_LOW) & `SHA512_REG_SHA512_CTRL_MODE_MASK;
    end
  endfunction

  //----------------------------------------------------------------
  // get_mask()
  //
  // Create the mask needed for a given mode.
  //----------------------------------------------------------------
  function [511 : 0] get_mask(input [1 : 0] mode);
    begin
      case (mode)
        MODE_SHA_512_224:
          begin
            if (DEBUG)
              begin
                $display("Mode MODE_SHA_512_224");
              end
            get_mask = {{7{32'hffffffff}}, {9{32'h00000000}}};
          end

        MODE_SHA_512_256:
          begin
            if (DEBUG)
              begin
                $display("Mode MODE_SHA_512_256");
              end
            get_mask = {{8{32'hffffffff}}, {8{32'h00000000}}};
          end

        MODE_SHA_384:
          begin
            if (DEBUG)
              begin
                $display("Mode MODE_SHA_512_384");
              end
            get_mask = {{12{32'hffffffff}}, {4{32'h00000000}}};
          end

        MODE_SHA_512:
          begin
            if (DEBUG)
              begin
                $display("Mode MODE_SHA_512");
              end
            get_mask = {16{32'hffffffff}};
          end
      endcase // case (mode)
    end
  endfunction // get_mask

  //----------------------------------------------------------------
  // read_digest()
  //
  // Read the digest in the dut. The resulting digest will be
  // available in the global variable digest_data.
  //----------------------------------------------------------------
  task read_digest;
    begin
      read_single_word(`SHA512_REG_SHA512_DIGEST_0);
      digest_data[511 : 480] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_1);
      digest_data[479 : 448] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_2);
      digest_data[447 : 416] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_3);
      digest_data[415 : 384] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_4);
      digest_data[383 : 352] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_5);
      digest_data[351 : 320] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_6);
      digest_data[319 : 288] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_7);
      digest_data[287 : 256] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_8);
      digest_data[255 : 224] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_9);
      digest_data[223 : 192] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_10);
      digest_data[191 : 160] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_11);
      digest_data[159 : 128] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_12);
      digest_data[127 :  96] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_13);
      digest_data[95  :  64] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_14);
      digest_data[63  :  32] = read_data;
      read_single_word(`SHA512_REG_SHA512_DIGEST_15);
      digest_data[31  :   0] = read_data;
    end
  endtask // read_digest


  //----------------------------------------------------------------
  // write_digest()
  //
  // Write the given digest to the dut.
  //----------------------------------------------------------------
  task write_digest(input [511 : 0] digest);
    begin
      write_single_word(`SHA512_REG_SHA512_DIGEST_0,  digest[511  : 480]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_1,  digest[479  : 448]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_2,  digest[447  : 416]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_3,  digest[415  : 384]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_4,  digest[383  : 352]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_5,  digest[351  : 320]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_6,  digest[319  : 288]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_7,  digest[287  : 256]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_8,  digest[255  : 224]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_9,  digest[223  : 192]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_10, digest[191  : 160]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_11, digest[159  : 128]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_12, digest[127  :  96]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_13, digest[95   :  64]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_14, digest[63   :  32]);
      write_single_word(`SHA512_REG_SHA512_DIGEST_15, digest[31   :   0]);
    end
  endtask // write_digest

  //----------------------------------------------------------------
  // check_name_version()
  //
  // Read the name and version from the DUT.
  //----------------------------------------------------------------
  task check_name_version;
    reg [31 : 0] name0;
    reg [31 : 0] name1;
    reg [31 : 0] version0;
    reg [31 : 0] version1;
    begin

      read_single_word(`SHA512_REG_SHA512_NAME_0);
      name0 = read_data;
      read_single_word(`SHA512_REG_SHA512_NAME_1);
      name1 = read_data;
      read_single_word(`SHA512_REG_SHA512_VERSION_0);
      version0 = read_data;
      read_single_word(`SHA512_REG_SHA512_VERSION_1);
      version1 = read_data;

      $display("DUT name: %c%c%c%c%c%c%c%c",
               name0[15 :  8], name0[7  :  0],
               name0[31 : 24], name0[23 : 16], 
               name1[15 :  8], name1[7  :  0],
               name1[31 : 24], name1[23 : 16]);
      $display("DUT version: %c%c%c%c%c%c%c%c",
               version0[15 :  8], version0[7  :  0],
               version0[31 : 24], version0[23 : 16],
               version1[15 :  8], version1[7  :  0],
               version1[31 : 24], version1[23 : 16]);
    end
  endtask // check_name_version

  //----------------------------------------------------------------
  // single_block_test()
  //
  //
  // Perform test of a single block digest.
  //----------------------------------------------------------------
  task single_block_test(input [7 : 0]    tc_number,
                         input [1 : 0]    mode,
                         input [1023 : 0] block,
                         input [511 : 0]  expected);

    reg [511 : 0] mask;
    reg [31  : 0] start_time;
    reg [31 : 0] end_time;
    begin
      $display("*** TC%01d - Single block test started.", tc_ctr);

      start_time = cycle_ctr;
      write_block(block);
      write_single_word(`SHA512_REG_SHA512_CTRL, INIT_CMD | mode_cmd(mode));
      

      #CLK_PERIOD;
      hsel_i_tb       = 0;

      #(CLK_PERIOD);
      wait_ready();
      read_digest();
      end_time = cycle_ctr - start_time;
      $display("*** Single block test processing time = %01d cycles", end_time);

      write_single_word(`SHA512_REG_SHA512_CTRL, ZEROIZE_CMD); //zeroize

      mask = get_mask(mode);

      if ((digest_data & mask) == (expected & mask))
        begin
          $display("TC%01d: OK.", tc_ctr);
        end
      else
        begin
          $display("TC%01d: ERROR.", tc_ctr);
          $display("TC%01d: Expected: 0x%0128x", tc_ctr, expected);
          $display("TC%01d: Got:      0x%0128x", tc_ctr, digest_data);
          error_ctr = error_ctr + 1;
        end
      $display("*** TC%01d - Single block test done.", tc_ctr);
      tc_ctr = tc_ctr + 1;
    end
  endtask // single_block_test


  //----------------------------------------------------------------
  // double_block_test()
  //
  //
  // Perform test of a double block digest. Note that we check
  // the digests for both the first and final block.
  //----------------------------------------------------------------
  task double_block_test(input [7 : 0]    tc_number,
                         input [1 : 0]    mode,
                         input [1023 : 0] block0,
                         input [1023 : 0] block1,
                         input [511 : 0]  expected0,
                         input [511 : 0]  expected1
                        );
    reg [511 : 0] mask;
    reg [31 : 0] start_time;
    reg [31 : 0] end_time;

    begin
      $display("*** TC%01d - Double block test started.", tc_ctr);

      // First block
      write_block(block0);
      write_single_word(`SHA512_REG_SHA512_CTRL, INIT_CMD | mode_cmd(mode));
      start_time = cycle_ctr;
      #CLK_PERIOD;
      hsel_i_tb       = 0;

      #(CLK_PERIOD);
      wait_ready();
      read_digest();

      mask = get_mask(mode);

      if ((digest_data & mask) == (expected0 & mask))
        begin
          $display("TC%01d first block: OK.", tc_ctr);
        end
      else
        begin
          $display("TC%01d: ERROR in first digest", tc_ctr);
          $display("TC%01d: Expected: 0x%064x", tc_ctr, expected0);
          $display("TC%01d: Got:      0x%064x", tc_ctr, digest_data);
          error_ctr = error_ctr + 1;
        end
      

      // Final block
      write_block(block1);
      write_single_word(`SHA512_REG_SHA512_CTRL, NEXT_CMD | mode_cmd(mode));
      #CLK_PERIOD;
      hsel_i_tb       = 0;

      #(CLK_PERIOD);
      wait_ready();
      end_time = cycle_ctr - start_time;
      $display("*** Double block test processing time = %01d cycles", end_time);
      read_digest();

      write_single_word(`SHA512_REG_SHA512_CTRL, ZEROIZE_CMD); //zeroize

      if ((digest_data & mask) == (expected1 & mask))
        begin
          $display("TC%01d final block: OK.", tc_ctr);
        end
      else
        begin
          $display("TC%01d: ERROR in final digest", tc_ctr);
          $display("TC%01d: Expected: 0x%0128x", tc_ctr, expected1);
          $display("TC%01d: Got:      0x%0128x", tc_ctr, digest_data);
          error_ctr = error_ctr + 1;
        end

      $display("*** TC%01d - Double block test done.", tc_ctr);
      tc_ctr = tc_ctr + 1;
    end
  endtask // double_block_test


  //----------------------------------------------------------------
  // double_block_test()
  //
  //
  // Perform test of a double block digest. Note that we check
  // the digests for both the first and final block.
  //----------------------------------------------------------------
  task double_block_test_pipelined(input [7 : 0]    tc_number,
                         input [1 : 0]    mode,
                         input [1023 : 0] block0,
                         input [1023 : 0] block1,
                         input [511 : 0]  expected
                        );
    reg [511 : 0] mask;
    reg [31 : 0] start_time;
    reg [31 : 0] end_time;

    begin
      $display("*** TC%01d - Double block test pipelined started.", tc_ctr);

      // First block
      write_block(block0);
      write_single_word(`SHA512_REG_SHA512_CTRL, INIT_CMD | mode_cmd(mode));
      start_time = cycle_ctr;
      #CLK_PERIOD;
      hsel_i_tb       = 0;

      #(CLK_PERIOD);
      write_block(block1);
      wait_ready();

      // Final block
      write_single_word(`SHA512_REG_SHA512_CTRL, NEXT_CMD | mode_cmd(mode));
      #CLK_PERIOD;
      hsel_i_tb       = 0;

      #(CLK_PERIOD);
      wait_ready();
      end_time = cycle_ctr - start_time;
      $display("*** Double block test pipelined processing time = %01d cycles", end_time);
      read_digest();

      mask = get_mask(mode);

      if ((digest_data & mask) == (expected & mask))
        begin
          $display("TC%01d final block: OK.", tc_ctr);
        end
      else
        begin
          $display("TC%01d: ERROR in final digest", tc_ctr);
          $display("TC%01d: Expected: 0x%0128x", tc_ctr, expected);
          $display("TC%01d: Got:      0x%0128x", tc_ctr, digest_data);
          error_ctr = error_ctr + 1;
        end

      $display("*** TC%01d - Double block test done.", tc_ctr);
      tc_ctr = tc_ctr + 1;
    end
  endtask // double_block_test

  //----------------------------------------------------------------
  // restore_test()
  //
  //
  // Perform test of a double block digest with restore feature. 
  //----------------------------------------------------------------
  task restore_test(input [7 : 0]    tc_number,
                         input [1 : 0]    mode,
                         input [1023 : 0] block0,
                         input [1023 : 0] block1,
                         input [511 : 0]  expected0,
                         input [511 : 0]  expected1
                        );
    reg [511 : 0] mask;

    begin
      $display("*** TC%01d - Restore block test started.", tc_ctr);

      // First block
      write_block(block0);
      write_single_word(`SHA512_REG_SHA512_CTRL, INIT_CMD | mode_cmd(mode));
      #CLK_PERIOD;
      hsel_i_tb       = 0;

      #(CLK_PERIOD);
      wait_ready();
      read_digest();

      mask = get_mask(mode);

      if ((digest_data & mask) == (expected0 & mask))
        begin
          $display("TC%01d first block: OK.", tc_ctr);
        end
      else
        begin
          $display("TC%01d: ERROR in first digest", tc_ctr);
          $display("TC%01d: Expected: 0x%064x", tc_ctr, expected0);
          $display("TC%01d: Got:      0x%064x", tc_ctr, digest_data);
          error_ctr = error_ctr + 1;
        end
      

      //zeroize core to test restore
      write_single_word(`SHA512_REG_SHA512_CTRL, ZEROIZE_CMD);


      // Final block
      write_block(block1);
      write_digest(digest_data);
      write_single_word(`SHA512_REG_SHA512_CTRL, RESTORE_CMD | NEXT_CMD | mode_cmd(mode));
      #CLK_PERIOD;
      hsel_i_tb       = 0;

      #(CLK_PERIOD);
      wait_ready();

      read_digest();

      write_single_word(`SHA512_REG_SHA512_CTRL, ZEROIZE_CMD); //zeroize

      if ((digest_data & mask) == (expected1 & mask))
        begin
          $display("TC%01d final block: OK.", tc_ctr);
        end
      else
        begin
          $display("TC%01d: ERROR in final digest", tc_ctr);
          $display("TC%01d: Expected: 0x%0128x", tc_ctr, expected1);
          $display("TC%01d: Got:      0x%0128x", tc_ctr, digest_data);
          error_ctr = error_ctr + 1;
        end

      $display("*** TC%01d - Double block test done.", tc_ctr);
      tc_ctr = tc_ctr + 1;
    end
  endtask // double_block_test
  
  //----------------------------------------------------------------
  // continuous_cmd_test()
  //
  //
  // Perform test of a double block digest.
  //----------------------------------------------------------------
  task continuous_cmd_test(input [7 : 0]    tc_number,
                         input [1 : 0]    mode,
                         input [1023 : 0] block0,
                         input [1023 : 0] block1,
                         input [511 : 0]  expected
                        );
    reg [511 : 0] mask;
    reg [31 : 0] start_time;
    reg [31 : 0] end_time;

    begin
      $display("*** TC%01d - continuous command test started.", tc_ctr);

      // First block
      write_block(block0);
      write_single_word(`SHA512_REG_SHA512_CTRL, INIT_CMD | mode_cmd(mode));
      start_time = cycle_ctr;
      #CLK_PERIOD;
      hsel_i_tb       = 0;

      #(CLK_PERIOD);

      for (int i=0; i<10; i++)
        begin
          write_single_word(`SHA512_REG_SHA512_CTRL, INIT_CMD | mode_cmd(mode));
          #CLK_PERIOD;
          hsel_i_tb       = 0;
          #CLK_PERIOD;
          write_single_word(`SHA512_REG_SHA512_CTRL, NEXT_CMD | mode_cmd(mode));
          #CLK_PERIOD;
          hsel_i_tb       = 0;
          #CLK_PERIOD;
          write_single_word(`CLP_SHA512_REG_SHA512_GEN_PCR_HASH_CTRL, `SHA512_REG_SHA512_GEN_PCR_HASH_CTRL_START_MASK);
          #CLK_PERIOD;
          hsel_i_tb       = 0;
          #CLK_PERIOD;
        end

      wait_ready();

      write_block(block1);

      // Final block
      write_single_word(`SHA512_REG_SHA512_CTRL, NEXT_CMD | mode_cmd(mode));
      #CLK_PERIOD;
      hsel_i_tb       = 0;

      #(CLK_PERIOD);

      for (int i=0; i<10; i++)
        begin
          write_single_word(`SHA512_REG_SHA512_CTRL, INIT_CMD | mode_cmd(mode));
          #CLK_PERIOD;
          hsel_i_tb       = 0;
          #CLK_PERIOD;
          write_single_word(`SHA512_REG_SHA512_CTRL, NEXT_CMD | mode_cmd(mode));
          #CLK_PERIOD;
          hsel_i_tb       = 0;
          #CLK_PERIOD;
        end

      wait_ready();

      end_time = cycle_ctr - start_time;
      $display("*** Continuous command test processing time = %01d cycles", end_time);
      read_digest();

      mask = get_mask(mode);

      if ((digest_data & mask) == (expected & mask))
        begin
          $display("TC%01d final block: OK.", tc_ctr);
        end
      else
        begin
          $display("TC%01d: ERROR in final digest", tc_ctr);
          $display("TC%01d: Expected: 0x%0128x", tc_ctr, expected);
          $display("TC%01d: Got:      0x%0128x", tc_ctr, digest_data);
          error_ctr = error_ctr + 1;
        end

      $display("*** TC%01d - Continuous command test done.", tc_ctr);
      tc_ctr = tc_ctr + 1;
    end
  endtask // continuous_cmd_test


  //----------------------------------------------------------------
  // zeroize_test()
  //
  //----------------------------------------------------------------
  task zeroize_test(input [7 : 0]    tc_number,
                    input [1 : 0]    mode,
                    input [1023 : 0] block0,
                    input [1023 : 0] block1,
                    input [511 : 0]  expected
                  );
    begin

      $display("*** TC%01d - zeroize test started.", tc_ctr);

      // First test: assert zeroize when engine is working 
      write_block(block0);

      write_single_word(`SHA512_REG_SHA512_CTRL, INIT_CMD | mode_cmd(mode));
      #(10 * CLK_PERIOD);

      write_single_word(`SHA512_REG_SHA512_CTRL, ZEROIZE_CMD); //zeroize
      #CLK_PERIOD;
      hsel_i_tb       = 0;

      wait_ready();
      read_digest();
      if (digest_data == 0)
        begin
          $display("TC%01d final block: OK.", tc_ctr);
        end
      else
        begin
          $display("TC%01d: ERROR in final digest", tc_ctr);
          $display("TC%01d: Expected: 0x%128x", tc_ctr, 0);
          $display("TC%01d: Got:      0x%128x", tc_ctr, digest_data);
          error_ctr = error_ctr + 1;
        end
      tc_ctr = tc_ctr + 1;

      // Second test: assert zeroize with INIT
      write_block(block0);

      write_single_word(`SHA512_REG_SHA512_CTRL, INIT_CMD | mode_cmd(mode) | ZEROIZE_CMD); //zeroize
      #CLK_PERIOD;
      hsel_i_tb       = 0;
      #(CLK_PERIOD);

      wait_ready();
      read_digest();
      if (digest_data == 0)
        begin
          $display("TC%01d final block: OK.", tc_ctr);
        end
      else
        begin
          $display("TC%01d: ERROR in final digest", tc_ctr);
          $display("TC%01d: Expected: 0x%128x", tc_ctr, 0);
          $display("TC%01d: Got:      0x%128x", tc_ctr, digest_data);
          error_ctr = error_ctr + 1;
        end
      tc_ctr = tc_ctr + 1;

      // Third test: assert zeroize with NEXT      
      write_block(block0);

      write_single_word(`SHA512_REG_SHA512_CTRL, NEXT_CMD | mode_cmd(mode) | ZEROIZE_CMD); //zeroize
      #CLK_PERIOD;
      hsel_i_tb       = 0;
      #(CLK_PERIOD);

      wait_ready();
      read_digest();
      if (digest_data == 0)
        begin
          $display("TC%01d final block: OK.", tc_ctr);
        end
      else
        begin
          $display("TC%01d: ERROR in final digest", tc_ctr);
          $display("TC%01d: Expected: 0x%128x", tc_ctr, 0);
          $display("TC%01d: Got:      0x%128x", tc_ctr, digest_data);
          error_ctr = error_ctr + 1;
        end
      tc_ctr = tc_ctr + 1;

      // Forth test: assert zeroize after NEXT      
      write_block(block0);

      write_single_word(`SHA512_REG_SHA512_CTRL, NEXT_CMD | mode_cmd(mode));
      #(10 * CLK_PERIOD);

      write_single_word(`SHA512_REG_SHA512_CTRL, ZEROIZE_CMD); //zeroize
      #CLK_PERIOD;
      hsel_i_tb       = 0;

      wait_ready();
      read_digest();
      if (digest_data == 0)
        begin
          $display("TC%01d final block: OK.", tc_ctr);
        end
      else
        begin
          $display("TC%01d: ERROR in final digest", tc_ctr);
          $display("TC%01d: Expected: 0x%128x", tc_ctr, 0);
          $display("TC%01d: Got:      0x%128x", tc_ctr, digest_data);
          error_ctr = error_ctr + 1;
        end

      $display("*** TC%01d - zeroize test done.", tc_ctr);
      tc_ctr = tc_ctr + 1;

      // Fifth test: assert zeroize after PCR      
      write_block(block0);

      write_single_word(`CLP_SHA512_REG_SHA512_GEN_PCR_HASH_CTRL, `SHA512_REG_SHA512_GEN_PCR_HASH_CTRL_START_MASK);
      #(10 * CLK_PERIOD);

      write_single_word(`SHA512_REG_SHA512_CTRL, ZEROIZE_CMD); //zeroize
      #CLK_PERIOD;
      hsel_i_tb       = 0;

      wait_ready();
      read_digest();
      if (digest_data == 0)
        begin
          $display("TC%01d final block: OK.", tc_ctr);
        end
      else
        begin
          $display("TC%01d: ERROR in final digest", tc_ctr);
          $display("TC%01d: Expected: 0x%128x", tc_ctr, 0);
          $display("TC%01d: Got:      0x%128x", tc_ctr, digest_data);
          error_ctr = error_ctr + 1;
        end

      $display("*** TC%01d - zeroize test done.", tc_ctr);
      tc_ctr = tc_ctr + 1;
    end
  endtask // zeroize_test

  //----------------------------------------------------------------
  // sha512_test
  // The main test functionality.
  //
  // Test cases taken from:
  // http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
  //----------------------------------------------------------------
  initial
    begin : sha512_test
      reg [1024 : 0] single_block;
      reg [511 : 0]  tc1_expected;
      reg [511 : 0]  tc2_expected;
      reg [511 : 0]  tc3_expected;
      reg [511 : 0]  tc4_expected;

      reg [1024 : 0] double_block_one;
      reg [1024 : 0] double_block_two;
      reg [511 : 0]  tc5_expected;
      reg [511 : 0]  tc6_expected;
      reg [511 : 0]  tc7_expected;
      reg [511 : 0]  tc8_expected;
      reg [511 : 0]  tc9_expected;
      reg [511 : 0]  tc10_expected;
      reg [511 : 0]  tc11_expected;
      reg [511 : 0]  tc12_expected;

      $display("   -- Testbench for sha512 started --");

      init_sim();
      reset_dut();
      check_name_version();


      // Single block test mesage.
      single_block = 1024'h6162638000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018;

      // SHA-512 single block digest and test.
      tc1_expected = 512'hDDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F;
      single_block_test(8'h01, MODE_SHA_512, single_block, tc1_expected);

      // SHA-512_224 single block digest and test.
      tc2_expected = {224'h4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA, {9{32'h00000000}}};
      single_block_test(8'h02, MODE_SHA_512_224, single_block, tc2_expected);

      // SHA-512_256 single block digest and test.
      tc3_expected = {256'h53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23, {8{32'h00000000}}};
      single_block_test(8'h03, MODE_SHA_512_256, single_block, tc3_expected);

      // SHA-384 single block digest and test.
      tc4_expected = {384'hCB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7, {4{32'h00000000}}};
      single_block_test(8'h04, MODE_SHA_384, single_block, tc4_expected);


      // Two block test message.
      double_block_one = 1024'h61626364656667686263646566676869636465666768696A6465666768696A6B65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F707172736D6E6F70717273746E6F70717273747580000000000000000000000000000000;
      double_block_two = 1024'h0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000380;

      // SHA-512 two block digests and test.
      tc5_expected = 512'h4319017A2B706E69CD4B05938BAE5E890186BF199F30AA956EF8B71D2F810585D787D6764B20BDA2A26014470973692000EC057F37D14B8E06ADD5B50E671C72;
      tc6_expected = 512'h8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909;
      double_block_test(8'h05, MODE_SHA_512, double_block_one, double_block_two, tc5_expected, tc6_expected);

      // SHA-512_224 two block digests and test.
      tc7_expected = 512'h9606CB2DB7823CE75FE35E2674A8F9EF1417ED9E89C412BB54EA29664586108625852563EED495096DEBAAE2F4737FD75319224B135486F8E6C0F55E700C35B3;
      tc8_expected = {224'h23FEC5BB94D60B23308192640B0C453335D664734FE40E7268674AF9, {9{32'h00000000}}};
      double_block_test(8'h06, MODE_SHA_512_224, double_block_one, double_block_two, tc7_expected, tc8_expected);

      // SHA-512_256 two block digests and test.
      tc9_expected = 512'h8DD99EB081311F8BCBBBC42CC7AFB288E8E9408730419D1E953FF7A2B194048DAE24175483C44C7C809B348E8E88E3ECBF2EA614CEED9C5B51807937F11867E1;
      tc10_expected = {256'h3928E184FB8690F840DA3988121D31BE65CB9D3EF83EE6146FEAC861E19B563A, {8{32'h00000000}}};
      double_block_test(8'h07, MODE_SHA_512_256, double_block_one, double_block_two, tc9_expected, tc10_expected);

      // SHA-384 two block digests and test.
      tc11_expected = 512'h2A7F1D895FD58E0BEAAE96D1A673C741015A2173796C1A88F6352CA156ACAFF7C662113E9EBB4D6417B61A85E2CCF0A937EB9A6660FEB5198F2EBE9A81E6A2C5;
      tc12_expected = {384'h09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039, {4{32'h00000000}}};
      double_block_test(8'h08, MODE_SHA_384, double_block_one, double_block_two, tc11_expected, tc12_expected);

      double_block_test_pipelined(8'h09, MODE_SHA_512, double_block_one, double_block_two, tc6_expected);

      continuous_cmd_test(8'h0a, MODE_SHA_384, double_block_one, double_block_two, tc12_expected);

      zeroize_test(8'h0b, MODE_SHA_384, double_block_one, double_block_two, tc12_expected);

      // SHA-512 restore test.
      restore_test(8'h0c, MODE_SHA_512, double_block_one, double_block_two, tc5_expected, tc6_expected);
      
      restore_test(8'h0d, MODE_SHA_512_224, double_block_one, double_block_two, tc7_expected, tc8_expected);

      restore_test(8'h0e, MODE_SHA_512_256, double_block_one, double_block_two, tc9_expected, tc10_expected);

      restore_test(8'h0f, MODE_SHA_384, double_block_one, double_block_two, tc11_expected, tc12_expected);
      
      display_test_result();
      
      $display("   -- Testbench for sha512 done. --");
      $finish;
  end //sha512_test

endmodule
