/* CMSIS-DAP Interface Firmware
 * Copyright (c) 2009-2013 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "target_flash.h"

const uint32_t K22F_FLM[] = {
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0xb5104830, 0x5120f24c, 0xf64d81c1, 0x81c11128, 0xf0218801, 0x80010101, 0x4448482b, 0xf88cf000, 
    0xd0002800, 0xbd102001, 0x47702000, 0xb5104826, 0xf0004448, 0xb920f877, 0x21004823, 0xf0004448, 
    0x4922f90b, 0xf442684a, 0x604a0270, 0xd0002800, 0xbd102001, 0x4604b510, 0x481b4601, 0x44482201, 
    0xf836f000, 0x4818b930, 0x22012300, 0x44484621, 0xf8bcf000, 0x684a4915, 0x0270f442, 0x2800604a, 
    0x2001d000, 0xb5febd10, 0x460b460c, 0x46014606, 0x4615480d, 0xf0004448, 0xb950f881, 0x90002000, 
    0x90029001, 0x462b4808, 0x46314622, 0xf0004448, 0x4906f8df, 0xf442684a, 0x604a0270, 0xd0002800, 
    0xbdfe2001, 0x40052000, 0x00000004, 0x4001f000, 0x41f0e92d, 0x460c4615, 0xf846f000, 0xd11b2800, 
    0x1e6d4425, 0xd0050569, 0xeb012101, 0x1e4221d5, 0x25c1eb02, 0x447e4e09, 0x8024f8df, 0x42ac2709, 
    0x6830d80a, 0xf8886004, 0xf0007007, 0x2800f8e9, 0xf504d102, 0xe7f26400, 0x81f0e8bd, 0x00000236, 
    0x40020000, 0x4903b120, 0x71c82044, 0xb8d8f000, 0x47702004, 0x40020000, 0x4916b190, 0x4a166cc9, 
    0x6103f3c1, 0xf832447a, 0x03091011, 0x2200d00a, 0x2100e9c0, 0x60812102, 0x60c10289, 0x47704610, 
    0x47702004, 0x47702064, 0xea41b128, 0x079b0302, 0x2065d003, 0x20044770, 0x68034770, 0xd804428b, 
    0x44116840, 0x42884418, 0x2066d201, 0x20004770, 0x00004770, 0x40048000, 0x000001c8, 0x47f0e92d, 
    0x0014461d, 0xd01a460e, 0xf7ff461a, 0x2800ffdd, 0x4f0cd116, 0xf8df447f, 0xf04fa030, 0x2d000806, 
    0x6838d00e, 0x68396006, 0x6048cc01, 0x8007f88a, 0xf886f000, 0xd1032800, 0x1f2d1d36, 0x2004e7ef, 
    0x87f0e8bd, 0x00000178, 0x40020000, 0x47f0e92d, 0x4615469a, 0x4604460f, 0xffb6f7ff, 0xd1252800, 
    0x0101e9d4, 0xf8f1fbb0, 0xf1c84279, 0x40010000, 0x42be424e, 0x4446d100, 0x1bf4b1bd, 0xd90042ac, 
    0x490b462c, 0x447908a0, 0x600f6809, 0x22014909, 0x0a0271ca, 0x728872ca, 0xa009f881, 0xf850f000, 
    0xd1032800, 0x44271b2d, 0x2000e7e5, 0x87f0e8bd, 0x00000106, 0x40020000, 0x4804b128, 0x71c22240, 
    0xf0007181, 0x2004b83d, 0x00004770, 0x40020000, 0x4df0e92d, 0xe9dd001c, 0xf8dd8709, 0x4616a020, 
    0xd022460d, 0xff70f7ff, 0xd11c2800, 0xb048f8df, 0x2e0044fb, 0xf8dbd017, 0x60050000, 0x2102480f, 
    0xf88071c1, 0xf8dba00b, 0x68201000, 0xf0006088, 0xb160f817, 0x0f00f1b8, 0xf8c8d001, 0x2f005000, 
    0x2100d001, 0xe8bd6039, 0x20048df0, 0x1f36e7fb, 0x1d2d1d24, 0x0000e7dd, 0x0000009c, 0x40020000, 
    0x2170480a, 0x21807001, 0x78017001, 0xd5fc0609, 0x06817800, 0x2067d501, 0x06c14770, 0x2068d501, 
    0x07c04770, 0x2069d0fc, 0x00004770, 0x40020000, 0x00000000, 0x00080000, 0x00100000, 0x00200000, 
    0x00400000, 0x00800000, 0x01000000, 0x01000000, 0x40020004, 0x00000000, 
};

static const TARGET_FLASH flash = {
    0x20000021, // Init
    0x20000049, // UnInit
    0x2000004D, // EraseChip
    0x20000075, // EraseSector
    0x200000A7, // ProgramPage

    // breakpoint = RAM start + 1
    // RSB : base address is address of Execution Region PrgData in map file
    //       to access global/static data
    // RSP : Initial stack pointer
	{
	    0x20000001, // breakpoint instruction address
	    0x20000000 + 0x20 + 0x334,  // static base register value (image start + header + static base offset)
	    0x20000800  // initial stack pointer
	},

	0x20001000, // program_buffer, any valid RAM location with +512 bytes of headroom
	0x20000000, // algo_start, start of RAM
	sizeof(K22F_FLM), // algo_size, size of array above
	K22F_FLM,  // image, flash algo instruction array
    512        // ram_to_flash_bytes_to_be_written
};




