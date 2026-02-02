#include "platform.h"
#include "debugger.h"

// Simplified disassembler for common instructions
size_t disasm_instruction(byte* code, size_t max_size, uintptr_t address, Instruction* instr) {
    if (max_size == 0 || !code || !instr) return 0;
    
    memset(instr, 0, sizeof(Instruction));
    
    // Handle common prefixes
    size_t offset = 0;
    bool rex_w = false;
    
    // REX prefix (x64 only)
    #if TARGET_X64
    if ((code[offset] & 0xF0) == 0x40 && offset + 1 < max_size) {
        rex_w = (code[offset] & 0x08) != 0;
        offset++;
    }
    #endif
    
    // Now decode opcode
    if (offset >= max_size) return 0;
    byte opcode = code[offset];
    offset++;
    
    if (offset > max_size) return 0;
    
    // Handle common instructions
    if (opcode == 0xCC) { // INT3
        strcpy(instr->mnemonic, "int3");
        instr->size = offset;
        return instr->size;
    }
    else if (opcode == 0xC3) { // RET
        strcpy(instr->mnemonic, "ret");
        instr->is_ret = true;
        instr->size = offset;
        return instr->size;
    }
    else if (opcode == 0xE9) { // JMP rel32
        if (offset + 4 > max_size) return 0;
        int32_t rel = *(int32_t*)&code[offset];
        uintptr_t target = address + 5 + rel; // 5 = opcode + 4 bytes
        snprintf(instr->mnemonic, sizeof(instr->mnemonic), "jmp");
        snprintf(instr->operands, sizeof(instr->operands), "0x%llx", (unsigned long long)target);
        instr->is_jump = true;
        instr->size = offset + 4;
        return instr->size;
    }
    else if (opcode == 0xE8) { // CALL rel32
        if (offset + 4 > max_size) return 0;
        int32_t rel = *(int32_t*)&code[offset];
        uintptr_t target = address + 5 + rel; // 5 = opcode + 4 bytes
        snprintf(instr->mnemonic, sizeof(instr->mnemonic), "call");
        snprintf(instr->operands, sizeof(instr->operands), "0x%llx", (unsigned long long)target);
        instr->is_call = true;
        instr->size = offset + 4;
        return instr->size;
    }
    else if ((opcode & 0xF0) == 0x70) { // Jcc rel8
        if (offset + 1 > max_size) return 0;
        int8_t rel = (int8_t)code[offset];
        uintptr_t target = address + 2 + rel; // 2 = opcode + 1 byte
        static const char* cc_mnemonics[16] = {
            "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
            "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
        };
        snprintf(instr->mnemonic, sizeof(instr->mnemonic), "%s", cc_mnemonics[opcode & 0x0F]);
        snprintf(instr->operands, sizeof(instr->operands), "0x%llx", (unsigned long long)target);
        instr->is_jump = true;
        instr->size = offset + 1;
        return instr->size;
    }
    else if (opcode == 0x0F && offset < max_size) {
        // Two-byte opcode
        byte opcode2 = code[offset];
        offset++;
        
        if ((opcode2 & 0xF0) == 0x80 && offset + 4 <= max_size) { // Jcc rel32
            int32_t rel = *(int32_t*)&code[offset];
            uintptr_t target = address + 6 + rel; // 6 = 0F + opcode + 4 bytes
            static const char* cc_mnemonics[16] = {
                "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
            };
            snprintf(instr->mnemonic, sizeof(instr->mnemonic), "%s", cc_mnemonics[opcode2 & 0x0F]);
            snprintf(instr->operands, sizeof(instr->operands), "0x%llx", (unsigned long long)target);
            instr->is_jump = true;
            instr->size = offset + 4;
            return instr->size;
        }
    }
    
    // MOV r8, imm8 (0xB0-0xB7)
    if (opcode >= 0xB0 && opcode <= 0xB7) {
        if (offset + 1 > max_size) return 0;
        byte imm = code[offset];
        int reg = opcode & 0x07;
        const char* reg_name = get_register_name(reg, false);
        snprintf(instr->mnemonic, sizeof(instr->mnemonic), "mov");
        snprintf(instr->operands, sizeof(instr->operands), "%s, 0x%02X", reg_name, imm);
        instr->size = offset + 1;
        return instr->size;
    }
    // MOV r16/r32/r64, imm16/32/64 (0xB8-0xBF)
    else if (opcode >= 0xB8 && opcode <= 0xBF) {
        int width = 4; // default 32-bit
        #if TARGET_X64
        if (rex_w) width = 8;
        #endif
        
        if (offset + width > max_size) return 0;
        
        int reg = opcode & 0x07;
        const char* reg_name = get_register_name(reg, TARGET_X64 && rex_w);
        
        if (width == 8) {
            uint64_t immediate = *(uint64_t*)&code[offset];
            snprintf(instr->mnemonic, sizeof(instr->mnemonic), "mov");
            snprintf(instr->operands, sizeof(instr->operands), "%s, 0x%lx", reg_name, (unsigned long)immediate);
        } else {
            uint32_t immediate = *(uint32_t*)&code[offset];
            snprintf(instr->mnemonic, sizeof(instr->mnemonic), "mov");
            snprintf(instr->operands, sizeof(instr->operands), "%s, 0x%X", reg_name, immediate);
        }
        
        instr->size = offset + width;
        return instr->size;
    }
    // ADD r/m32, imm32 (0x81 /0)
    else if (opcode == 0x81 && offset + 6 <= max_size) {
        byte modrm = code[offset];
        int reg = (modrm >> 3) & 0x07;
        if (reg == 0) { // ADD
            snprintf(instr->mnemonic, sizeof(instr->mnemonic), "add");
            uint32_t immediate = *(uint32_t*)&code[offset + 1];
            snprintf(instr->operands, sizeof(instr->operands), "[reg], 0x%X", immediate);
            instr->size = offset + 6;
            return instr->size;
        }
    }
    // PUSH reg (0x50-0x57)
    else if (opcode >= 0x50 && opcode <= 0x57) {
        int reg = opcode & 0x07;
        const char* reg_name = get_register_name(reg, TARGET_X64);
        snprintf(instr->mnemonic, sizeof(instr->mnemonic), "push");
        snprintf(instr->operands, sizeof(instr->operands), "%s", reg_name);
        instr->size = offset;
        return instr->size;
    }
    // POP reg (0x58-0x5F)
    else if (opcode >= 0x58 && opcode <= 0x5F) {
        int reg = opcode & 0x07;
        const char* reg_name = get_register_name(reg, TARGET_X64);
        snprintf(instr->mnemonic, sizeof(instr->mnemonic), "pop");
        snprintf(instr->operands, sizeof(instr->operands), "%s", reg_name);
        instr->size = offset;
        return instr->size;
    }
    
    // Default handler for unknown instructions
    snprintf(instr->mnemonic, sizeof(instr->mnemonic), "db");
    snprintf(instr->operands, sizeof(instr->operands), "0x%02X", opcode);
    instr->size = 1;
    return instr->size;
}

const char* get_register_name(int reg_index, bool is_64bit) {
    static const char* reg64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"};
    static const char* reg32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    static const char* reg8[] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"}; // simplified
    
    if (reg_index < 0 || reg_index >= 8) return "???";
    return is_64bit ? reg64[reg_index] : reg32[reg_index];
}