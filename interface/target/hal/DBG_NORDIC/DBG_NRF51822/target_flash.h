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
#ifndef TARGET_FLASH_H
#define TARGET_FLASH_H

#include "target_struct.h"
#include "swd_host.h"
#include <stdint.h>

#define FLASH_SECTOR_SIZE           (1024)

#define TARGET_AUTO_INCREMENT_PAGE_SIZE    0x1000

static uint8_t target_flash_init(uint32_t clk);
static uint8_t target_flash_uninit(void);
static uint8_t target_flash_erase_chip(void);
static uint8_t target_flash_erase_sector(uint32_t adr);
static uint8_t target_flash_program_page(uint32_t adr, uint8_t * buf, uint32_t size);


static const uint32_t flash_algo_blob[] = {
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,

    /*0x020*/ 0x4770ba40, 0x4770bac0, 0x48884987, 0xd0052a01L, 0xd0092a02L, 0xd00d2a03L, 0x47702001, 0x604a2202, 
    /*0x040*/ 0x29006801, 0xe00ad0fcL, 0x604a2201, 0x29006801, 0xe004d0fcL, 0x604a2200, 0x29006801, 0x2000d0fc, 
    /*0x060*/ 0x49794770, 0x60482000, 0x68014878, 0xd0fc2900L, 0x47702000, 0x4876b570, 0x4096841, 0xd00c0e09L, 
    /*0x080*/ 0x6ae10404, 0xb2ca2501L, 0x49704b6f, 0xd0062a00L, 0x1c526802, 0x6800d021, 0x2001e019, 0x6aa0bd70, 
    /*0x0A0*/ 0x6098e005, 0x2a00680a, 0x6922d0fc, 0x69221810, 0x43726966, 0xd8f44282L, 0x6808615d, 0xd0fc2800L, 
    /*0x0C0*/ 0x6098e00f, 0x2a00680a, 0x6922d0fc, 0x69221810, 0x436a6965, 0xd8f44282L, 0x60dde003, 0x28006808, 
    /*0x0E0*/ 0x2000d0fc, 0x581bd70, 0x2101d120, 0x690a0709, 0x435a694b, 0xd9174282L, 0x6126aca, 0xd1020e12L, 
    /*0x100*/ 0x42816a89, 0x4952d810, 0x1c52680a, 0x680ad002, 0xd8094282L, 0x4096849, 0xd0070e09L, 0x6088494a, 
    /*0x120*/ 0x6801484a, 0xd0fc2900L, 0x47702000, 0x47702001, 0x783b570, 0x78bd122, 0x2301d120, 0x691c071b, 
    /*0x140*/ 0x436c695d, 0xd9194284L, 0x6246adc, 0xd1020e24L, 0x42846a9c, 0x4b3ed812, 0x1c64681c, 0x681dd002, 
    /*0x160*/ 0xd80b4285L, 0x41b685b, 0xd0070e1bL, 0x4c372300, 0xe00b088dL, 0x58460099, 0xd0011c76L, 0xbd702001L, 
    /*0x180*/ 0x50465856, 0x29006821, 0x1c5bd0fc, 0xd8f1429dL, 0xbd702000L, 0x783b570, 0x78bd125, 0x2501d123, 
    /*0x1A0*/ 0x692b072d, 0x4363696c, 0xd91c4283L, 0x61b6aeb, 0xd1020e1bL, 0x42846aac, 0x4b25d815, 0x624685c, 
    /*0x1C0*/ 0xd1020e24L, 0x4284681c, 0x685bd80d, 0xe1b041b, 0x2300d009, 0xe008088eL, 0x5905009c, 0x42a55914, 
    /*0x1E0*/ 0x99d002, 0xbd701808L, 0x429e1c5b, 0x1840d8f4, 0xb530bd70L, 0xd1200783L, 0xd11e078bL, 0x71b2301, 
    /*0x200*/ 0x695d691c, 0x4284436c, 0x6adcd91c, 0xe240624, 0x6a9cd102, 0xd8154284L, 0x685c4b0d, 0xe240624, 
    /*0x220*/ 0x681dd102, 0xd80d4285L, 0x41b685b, 0xd0090e1bL, 0xe0052300L, 0x42945cc4, 0x2001d001, 0x1c5bbd30, 
    /*0x240*/ 0xd3f7428bL, 0xbd302000L, 0x4001e500, 0x4001e400, 0x10001000, 0x0, 
};

static const TARGET_FLASH flash = {
    0x20000029, // Init
    0x20000063, // UnInit
    0x20000075, // EraseChip
    0x200000E7, // EraseSector
    0x20000131, // ProgramPage

// RSB : base adreess is address of Execution Region PrgData in map file
//       to access global/static data
// RSP : Initial stack pointer

    {0x20000001, 0x20000000+0x20+0x0234, 0x20000000 + 0x1000}, // {breakpoint, RSB, RSP}

    0x20000400, // program_buffer
    0x20000000, // algo_start
    0x00000300, // algo_size
    flash_algo_blob,// image
    1024         // ram_to_flash_bytes_to_be_written
};

static uint8_t target_flash_init(uint32_t clk) {
#if 0
    // Download flash programming algorithm to target and initialise.
    if (!swd_write_memory(flash.algo_start, (uint8_t *)flash.image, flash.algo_size)) {
        return 0;
    }

    if (!swd_flash_syscall_exec(&flash.sys_call_param, flash.init, 0, 0 /* clk value is not used */, 1, 0)) {
        return 0;
    }
#endif
    return 1;
}

static uint8_t target_flash_init_ex(uint32_t func) {
    // Download flash programming algorithm to target and initialise.
    if (!swd_write_memory(flash.algo_start, (uint8_t *)flash.image, flash.algo_size)) {
        return 0;
    }

    if (!swd_flash_syscall_exec(&flash.sys_call_param, flash.init, 0, 0, func, 0)) {
        return 0;
    }

    return 1;
}

static uint8_t target_flash_erase_sector(unsigned int sector) {
#if 0
    if (!swd_flash_syscall_exec(&flash.sys_call_param, flash.erase_sector, sector*0x1000, 0, 0, 0)) {
        return 0;
    }
#endif
    return 1;
}

static uint8_t target_flash_erase_sector_ex(uint32_t addr) {
    if (!swd_flash_syscall_exec(&flash.sys_call_param, flash.erase_sector, addr, 0, 0, 0)) {
        return 0;
    }

    return 1;
}

static uint8_t target_flash_erase_chip(void) {
#if 0
    if (!swd_flash_syscall_exec(&flash.sys_call_param, flash.erase_chip, 0, 0, 0, 0)) {
        return 0;
    }
#endif
    return 1;
}

static uint16_t GetSecNum (unsigned long adr) {
    uint16_t n = (adr >> 10); 
    return (n);
}

static uint8_t target_flash_program_page(uint32_t addr, uint8_t * buf, uint32_t size)
{ 
    static uint16_t lastSecNum = 0xFFFF;
    uint32_t bytes_written = 0;
    
    addr += 0x00014000;
    
    // Download flash programming algorithm to target and initialise.
    if (!swd_write_memory(flash.algo_start, (uint8_t *)flash.image, flash.algo_size)) {
        return 0;
    }
    
    // Program a page in target flash.
    if (!swd_write_memory(flash.program_buffer, buf, size)) {
        return 0;
    }

    while(bytes_written < size) {
        uint16_t currentSecNum = GetSecNum(addr);
        uint32_t bytes;
      
        if (currentSecNum != lastSecNum) {
            if (!swd_flash_syscall_exec(&flash.sys_call_param, flash.init, 0, 0, 1, 0)) {
                return 0;
            }
            
            if (!swd_flash_syscall_exec(&flash.sys_call_param, flash.erase_sector, addr, 0, 0, 0)) {
                return 0;
            }
            lastSecNum = currentSecNum;
            
            if (!swd_flash_syscall_exec(&flash.sys_call_param, flash.init, 0, 0, 2, 0)) {
                return 0;
            }
        }
        
        if (size < flash.ram_to_flash_bytes_to_be_written) {
            bytes = size;
        } else {
            bytes = flash.ram_to_flash_bytes_to_be_written;
        }
   
        if (!swd_flash_syscall_exec(&flash.sys_call_param,
                                    flash.program_page,
                                    addr,
                                    bytes,
                                    flash.program_buffer + bytes_written, 0)) {
            return 0;
        }

        bytes_written += flash.ram_to_flash_bytes_to_be_written;
        addr += flash.ram_to_flash_bytes_to_be_written;
    }
    
    if (!swd_flash_syscall_exec(&flash.sys_call_param, flash.init, 0, 0, 2, 0)) {
        return 0;
    }

    return 1;
}


#endif
