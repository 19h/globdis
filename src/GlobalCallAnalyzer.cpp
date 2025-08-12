#include "GlobalCallAnalyzer.hpp"
#include <windows.h>
#include <psapi.h>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <iomanip>

namespace BinA {
// PE parsing (NO win32 at runtime  we already received a view!)

void GlobalCallAnalyzer::ParsePE() {
    if (m_view.size() < sizeof(IMAGE_DOS_HEADER))
        throw std::runtime_error("DOS hdr too small");

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_view.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) throw std::runtime_error("Bad MZ");

    const auto nt_off = dos->e_lfanew;
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(m_view.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) throw std::runtime_error("Bad PE");

    const auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!std::strncmp(reinterpret_cast<const char*>(sec[i].Name), ".text", 5)) {
            m_text_va  = nt->OptionalHeader.ImageBase + sec[i].VirtualAddress;
            m_text     = m_view.subspan(sec[i].VirtualAddress, sec[i].Misc.VirtualSize);
            return;
        }
    }
    throw std::runtime_error(".text not found");
}

// ------------------------------------------------------------------
// ctor

GlobalCallAnalyzer::GlobalCallAnalyzer(std::span<const uint8_t> mv) : m_view(mv) {
    ParsePE();
}

// ------------------------------------------------------------------
// tiny helpers

bool GlobalCallAnalyzer::IsRIPRelativeMovOrLEA(const ZydisDecodedInstruction& insn,
                                               const ZydisDecodedOperand& op) {
    if (op.type != ZYDIS_OPERAND_TYPE_MEMORY)       return false;
    if (op.mem.base != ZYDIS_REGISTER_RIP)          return false;
    
    // For MOV and LEA instructions that load from RIP-relative addresses
    // We'll accept any MOV/LEA with RIP-relative addressing and filter later
    return (insn.mnemonic == ZYDIS_MNEMONIC_MOV || insn.mnemonic == ZYDIS_MNEMONIC_LEA);
}

bool GlobalCallAnalyzer::OperandReads(const ZydisDecodedOperand& op)  {
    return op.actions & ZYDIS_OPERAND_ACTION_READ;
}
bool GlobalCallAnalyzer::OperandWrites(const ZydisDecodedOperand& op) {
    return op.actions & ZYDIS_OPERAND_ACTION_WRITE;
}

// Get the full 64-bit register for any sub-register
ZydisRegister GlobalCallAnalyzer::GetFullRegister(ZydisRegister reg) {
    // Handle sub-registers by mapping to their full 64-bit version
    switch (reg) {
        // RAX family
        case ZYDIS_REGISTER_AL:
        case ZYDIS_REGISTER_AH:
        case ZYDIS_REGISTER_AX:
        case ZYDIS_REGISTER_EAX:
        case ZYDIS_REGISTER_RAX:
            return ZYDIS_REGISTER_RAX;
        
        // RBX family
        case ZYDIS_REGISTER_BL:
        case ZYDIS_REGISTER_BH:
        case ZYDIS_REGISTER_BX:
        case ZYDIS_REGISTER_EBX:
        case ZYDIS_REGISTER_RBX:
            return ZYDIS_REGISTER_RBX;
        
        // RCX family
        case ZYDIS_REGISTER_CL:
        case ZYDIS_REGISTER_CH:
        case ZYDIS_REGISTER_CX:
        case ZYDIS_REGISTER_ECX:
        case ZYDIS_REGISTER_RCX:
            return ZYDIS_REGISTER_RCX;
        
        // RDX family
        case ZYDIS_REGISTER_DL:
        case ZYDIS_REGISTER_DH:
        case ZYDIS_REGISTER_DX:
        case ZYDIS_REGISTER_EDX:
        case ZYDIS_REGISTER_RDX:
            return ZYDIS_REGISTER_RDX;
        
        // RSI family
        case ZYDIS_REGISTER_SIL:
        case ZYDIS_REGISTER_SI:
        case ZYDIS_REGISTER_ESI:
        case ZYDIS_REGISTER_RSI:
            return ZYDIS_REGISTER_RSI;
        
        // RDI family
        case ZYDIS_REGISTER_DIL:
        case ZYDIS_REGISTER_DI:
        case ZYDIS_REGISTER_EDI:
        case ZYDIS_REGISTER_RDI:
            return ZYDIS_REGISTER_RDI;
        
        // RBP family
        case ZYDIS_REGISTER_BPL:
        case ZYDIS_REGISTER_BP:
        case ZYDIS_REGISTER_EBP:
        case ZYDIS_REGISTER_RBP:
            return ZYDIS_REGISTER_RBP;
        
        // RSP family
        case ZYDIS_REGISTER_SPL:
        case ZYDIS_REGISTER_SP:
        case ZYDIS_REGISTER_ESP:
        case ZYDIS_REGISTER_RSP:
            return ZYDIS_REGISTER_RSP;
        
        // R8-R15 families
        case ZYDIS_REGISTER_R8B:
        case ZYDIS_REGISTER_R8W:
        case ZYDIS_REGISTER_R8D:
        case ZYDIS_REGISTER_R8:
            return ZYDIS_REGISTER_R8;
            
        case ZYDIS_REGISTER_R9B:
        case ZYDIS_REGISTER_R9W:
        case ZYDIS_REGISTER_R9D:
        case ZYDIS_REGISTER_R9:
            return ZYDIS_REGISTER_R9;
            
        case ZYDIS_REGISTER_R10B:
        case ZYDIS_REGISTER_R10W:
        case ZYDIS_REGISTER_R10D:
        case ZYDIS_REGISTER_R10:
            return ZYDIS_REGISTER_R10;
            
        case ZYDIS_REGISTER_R11B:
        case ZYDIS_REGISTER_R11W:
        case ZYDIS_REGISTER_R11D:
        case ZYDIS_REGISTER_R11:
            return ZYDIS_REGISTER_R11;
            
        case ZYDIS_REGISTER_R12B:
        case ZYDIS_REGISTER_R12W:
        case ZYDIS_REGISTER_R12D:
        case ZYDIS_REGISTER_R12:
            return ZYDIS_REGISTER_R12;
            
        case ZYDIS_REGISTER_R13B:
        case ZYDIS_REGISTER_R13W:
        case ZYDIS_REGISTER_R13D:
        case ZYDIS_REGISTER_R13:
            return ZYDIS_REGISTER_R13;
            
        case ZYDIS_REGISTER_R14B:
        case ZYDIS_REGISTER_R14W:
        case ZYDIS_REGISTER_R14D:
        case ZYDIS_REGISTER_R14:
            return ZYDIS_REGISTER_R14;
            
        case ZYDIS_REGISTER_R15B:
        case ZYDIS_REGISTER_R15W:
        case ZYDIS_REGISTER_R15D:
        case ZYDIS_REGISTER_R15:
            return ZYDIS_REGISTER_R15;
        
        default:
            return reg;
    }
}

// Check if two registers overlap (e.g., RAX and EAX)
bool GlobalCallAnalyzer::RegistersOverlap(ZydisRegister reg1, ZydisRegister reg2) {
    return GetFullRegister(reg1) == GetFullRegister(reg2);
}

// ------------------------------------------------------------------
// main loop

void GlobalCallAnalyzer::ProcessInstruction(size_t idx,
                                            uint64_t ip,
                                            const ZydisDecodedInstruction& insn,
                                            const ZydisDecodedOperand* operands,
                                            std::vector<GlobalAccessReport>& reports,
                                            std::unordered_map<ZydisRegister, DereferencedPointer>& register_pointer_map) const
{
    // Step 1: Handle register-to-register moves (aliasing)
    if (insn.mnemonic == ZYDIS_MNEMONIC_MOV && insn.operand_count >= 2) {
        const auto& src = operands[1];
        const auto& dst = operands[0];
        
        if (src.type == ZYDIS_OPERAND_TYPE_REGISTER && dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            ZydisRegister src_full = GetFullRegister(src.reg.value);
            ZydisRegister dst_full = GetFullRegister(dst.reg.value);
            
            // Check if source register contains a tracked pointer
            auto it = register_pointer_map.find(src_full);
            if (it != register_pointer_map.end()) {
                // Copy the pointer tracking to the destination register
                DereferencedPointer alias = it->second;
                alias.loaded_register = dst_full;
                register_pointer_map[dst_full] = alias;
                
                // Debug: print alias and nesting levels
                std::cerr << "Debug: Alias assignment: " << ZydisRegisterGetString(dst_full) 
                          << " now holds alias of " << ZydisRegisterGetString(src_full) 
                          << " with nesting level " << alias.nesting_level 
                          << " and offset " << alias.accumulated_offset << '\n';
            } else if (OperandWrites(dst)) {
                // Destination is being overwritten with non-pointer value
                register_pointer_map.erase(dst_full);
            }
        }
    }
    
    // Step 2: Handle pointer arithmetic (add/sub with immediate)
    if ((insn.mnemonic == ZYDIS_MNEMONIC_ADD || insn.mnemonic == ZYDIS_MNEMONIC_SUB || 
         insn.mnemonic == ZYDIS_MNEMONIC_LEA) && insn.operand_count >= 2) {
        const auto& dst = operands[0];
        
        if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            ZydisRegister dst_full = GetFullRegister(dst.reg.value);
            auto it = register_pointer_map.find(dst_full);
            
            if (it != register_pointer_map.end()) {
                // Handle LEA special case
                if (insn.mnemonic == ZYDIS_MNEMONIC_LEA && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    const auto& mem = operands[1].mem;
                    if (RegistersOverlap(mem.base, dst_full)) {
                        // LEA modifies the offset
                        it->second.accumulated_offset += mem.disp.value;
                    }
                }
                // Handle ADD/SUB with immediate
                else if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    int64_t offset = operands[1].imm.value.s;
                    if (insn.mnemonic == ZYDIS_MNEMONIC_SUB) {
                        offset = -offset;
                    }
                    it->second.accumulated_offset += offset;
                    
                    // Debug: print pointer arithmetic adjustment
                    std::cerr << "Debug: Adjusted pointer in register " << ZydisRegisterGetString(dst_full)
                              << " by immediate " << offset
                              << ", resulting offset is " << it->second.accumulated_offset << '\n';
                }
            }
        }
    }

    // Step 3: Clear tracking for registers that are overwritten with non-pointer values
    for (uint8_t i = 0; i < insn.operand_count; ++i) {
        const auto& op = operands[i];
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER && OperandWrites(op)) {
            ZydisRegister reg_full = GetFullRegister(op.reg.value);
            
            // Skip if this is already handled by mov or arithmetic instructions
            if (insn.mnemonic != ZYDIS_MNEMONIC_MOV && 
                insn.mnemonic != ZYDIS_MNEMONIC_ADD && 
                insn.mnemonic != ZYDIS_MNEMONIC_SUB &&
                insn.mnemonic != ZYDIS_MNEMONIC_LEA) {
                // Register is being overwritten with unknown value
                register_pointer_map.erase(reg_full);
            }
        }
    }
    // Step A: detect root global handle ---------------------------------
    for (uint8_t oi = 0; oi < insn.operand_count; ++oi) {
        const auto& op = operands[oi];
        
        // Debug: Check all RIP-relative accesses
        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base == ZYDIS_REGISTER_RIP) {
            static int debug_count = 0;
            if (debug_count < 10) {  // Only print first 10 to avoid spam
                std::cerr << "Debug: RIP-relative at 0x" << std::hex << ip 
                          << " mnemonic=" << insn.mnemonic 
                          << " (" << (insn.mnemonic == ZYDIS_MNEMONIC_MOV ? "MOV" : 
                               insn.mnemonic == ZYDIS_MNEMONIC_LEA ? "LEA" : "OTHER") << ")"
                          << " operand_idx=" << (int)oi
                          << " operand_count=" << (int)insn.operand_count
                          << " actions=0x" << std::hex << (int)op.actions << std::dec
                          << " IsMovOrLea=" << IsRIPRelativeMovOrLEA(insn, op) << "\n";
                debug_count++;
            }
        }
        
        if (!IsRIPRelativeMovOrLEA(insn, op)) continue;

        // absolute address of [RIP+disp]
        uint64_t glob;
        ZyanStatus status = ZydisCalcAbsoluteAddress(&insn, &op, ip, &glob);
        if (ZYAN_FAILED(status)) {
            static int calc_debug_count = 0;
            if (calc_debug_count < 5) {
                std::cerr << "Debug: ZydisCalcAbsoluteAddress failed with status: 0x" 
                          << std::hex << status << std::dec << "\n";
                calc_debug_count++;
            }
            continue;
        }

        // Debug: Show calculated address
        static int addr_debug_count = 0;
        if (addr_debug_count < 5) {
            std::cerr << "Debug: Calculated global address: 0x" << std::hex << glob 
                      << " from RIP=0x" << ip << " text_range=[0x" << m_text_va 
                      << ", 0x" << (m_text_va + m_text.size()) << ")" << std::dec << "\n";
            addr_debug_count++;
        }

        // .text self‑references are ignored
        if (glob >= m_text_va && glob < m_text_va + m_text.size()) continue;
        
        // Filter out suspicious addresses that are likely base addresses rather than globals
        // These are typically addresses below the image base that are used with large offsets
        // Also check if this is likely the image base minus some offset
        const uint64_t image_base = m_text_va & 0xFFFFFFFF00000000ULL;  // Typical image base alignment
        if (glob < image_base || (glob < m_text_va && (m_text_va - glob) > 0x1000)) {
            // This looks like a base address used for relative addressing
            // Skip it to avoid false positives
            static int filter_debug_count = 0;
            if (filter_debug_count < 5) {
                std::cerr << "Debug: Filtering out suspicious base address 0x" << std::hex << glob 
                          << " (image_base=0x" << image_base << ", text_va=0x" << m_text_va << ")" << std::dec << "\n";
                filter_debug_count++;
            }
            continue;
        }

        // Track the source of derived pointers when loading from globals
        for (uint8_t j = 0; j < insn.operand_count; ++j) {
            const auto& dest_op = operands[j];
            if (dest_op.type == ZYDIS_OPERAND_TYPE_REGISTER && OperandWrites(dest_op)) {
                // Mark the register as containing a pointer from this global
                DereferencedPointer derivedPointer = {
                    glob,                                    // source_global_va
                    static_cast<int64_t>(op.mem.disp.value), // source_offset (signed)
                    GetFullRegister(dest_op.reg.value),      // loaded_register (full register)
                    idx,                                     // instruction_index
                    1,                                       // nesting_level
                    0                                        // accumulated_offset
                };
                register_pointer_map[GetFullRegister(dest_op.reg.value)] = derivedPointer;
            }
        }
        // alias set starts with the mov destination
        ZydisRegister aliases[4]{};
        uint8_t       alias_cnt = 0;
        for (uint8_t j = 0; j < insn.operand_count; ++j)
            if (operands[j].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                OperandWrites(operands[j]))
                aliases[alias_cnt++] = operands[j].reg.value;

        constexpr size_t kWindow = 8;
        GlobalAccessReport* rep   = nullptr;
        for (auto& r : reports) if (r.global_va == glob) { rep = &r; break; }
        if (!rep) { reports.push_back({glob,{}}); rep = &reports.back(); }

        size_t walk_idx = idx + 1;
        for (size_t w = 0; w < kWindow && walk_idx < m_text.size(); ++w) {
            ZydisDecodedInstruction nxt{};
            ZydisDecodedOperand nxt_operands[ZYDIS_MAX_OPERAND_COUNT];
            ZydisDecoder dec;
            ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
            if (ZYAN_FAILED(ZydisDecoderDecodeFull(&dec,
                            m_text.data() + walk_idx, m_text.size() - walk_idx,
                            &nxt, nxt_operands)))
                break;

            uint64_t nxt_ip = m_text_va + walk_idx;

            // Scan operands for accesses using alias registers ------------
            for (uint8_t oi2 = 0; oi2 < nxt.operand_count; ++oi2) {
                const auto& op2 = nxt_operands[oi2];
                if (op2.type != ZYDIS_OPERAND_TYPE_MEMORY) continue;

                for (uint8_t a = 0; a < alias_cnt; ++a) {
                    if (op2.mem.base != aliases[a]) continue;

                    // compute [alias + disp]
                    // The displacement is signed, we need to handle it correctly
                    int64_t signed_disp = op2.mem.disp.value;
                    
                    // Debug problematic offsets
                    static int offset_debug_count = 0;
                    if (offset_debug_count < 10 && (signed_disp < -100 || signed_disp > 10000)) {
                        std::cerr << "Debug: Large/negative offset " << signed_disp 
                                  << " (0x" << std::hex << signed_disp << ") at instruction 0x" 
                                  << nxt_ip << " mnemonic=" << nxt.mnemonic << std::dec << "\n";
                        offset_debug_count++;
                    }
                    
                    // Store the offset as a signed value to preserve negative offsets
                    auto& st = rep->per_offset[signed_disp];
                    st.relative = signed_disp;

                    // Type inference based on instruction and operand info
                    size_t operand_size = op2.size / 8;  // Convert bits to bytes
                    st.type_info.size_histogram[operand_size]++;
                    
                    // Check for floating-point operations
                    bool is_float_op = false;
                    switch (nxt.mnemonic) {
                        case ZYDIS_MNEMONIC_MOVSS:
                        case ZYDIS_MNEMONIC_MOVAPS:
                        case ZYDIS_MNEMONIC_MOVUPS:
                        case ZYDIS_MNEMONIC_ADDSS:
                        case ZYDIS_MNEMONIC_SUBSS:
                        case ZYDIS_MNEMONIC_MULSS:
                        case ZYDIS_MNEMONIC_DIVSS:
                        case ZYDIS_MNEMONIC_COMISS:
                        case ZYDIS_MNEMONIC_UCOMISS:
                            st.type_info.has_float_ops = true;
                            is_float_op = true;
                            break;
                        case ZYDIS_MNEMONIC_MOVSD:
                        case ZYDIS_MNEMONIC_MOVAPD:
                        case ZYDIS_MNEMONIC_MOVUPD:
                        case ZYDIS_MNEMONIC_ADDSD:
                        case ZYDIS_MNEMONIC_SUBSD:
                        case ZYDIS_MNEMONIC_MULSD:
                        case ZYDIS_MNEMONIC_DIVSD:
                        case ZYDIS_MNEMONIC_COMISD:
                        case ZYDIS_MNEMONIC_UCOMISD:
                            st.type_info.has_float_ops = true;
                            is_float_op = true;
                            break;
                    }

                    if (nxt.mnemonic == ZYDIS_MNEMONIC_CALL) {
                        ++st.call_hits;
                        st.type_info.has_calls = true;
                    }
                    else if (OperandReads(op2) && OperandWrites(op2))
                        ; // ignore RMW – classify separately if needed
                    else if (OperandReads(op2))
                        ++st.load_hits;
                    else if (OperandWrites(op2))
                        ++st.store_hits;
                }
            }

            // alias propagation + kill ------------------------------------
            for (uint8_t oi2 = 0; oi2 < nxt.operand_count; ++oi2) {
                const auto& op2 = nxt_operands[oi2];
                if (op2.type != ZYDIS_OPERAND_TYPE_REGISTER) continue;

                // transfer rX  rY
                if (OperandReads(op2) && op2.reg.value == aliases[0]) {
                    for (uint8_t oi3 = 0; oi3 < nxt.operand_count; ++oi3) {
                        const auto& dst = nxt_operands[oi3];
                        if (OperandWrites(dst) && dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                            alias_cnt < std::size(aliases))
                            aliases[alias_cnt++] = dst.reg.value;
                    }
                }
                // kill
                if (OperandWrites(op2)) {
                    for (uint8_t a = 0; a < alias_cnt; ++a)
                        if (aliases[a] == op2.reg.value) { aliases[a] = ZYDIS_REGISTER_NONE; }
                }
            }

            // stop if alias set empty
            bool empty = true;
            for (uint8_t a = 0; a < alias_cnt; ++a) if (aliases[a] != ZYDIS_REGISTER_NONE) { empty = false; break; }
            if (empty) break;

            // stop on flow break that we are not going to simulate
            if (nxt.mnemonic == ZYDIS_MNEMONIC_CALL || nxt.mnemonic == ZYDIS_MNEMONIC_RET)
                break;

            walk_idx += nxt.length;
        }
    }
}

// ------------------------------------------------------------------

std::vector<GlobalAccessReport> GlobalCallAnalyzer::Analyze() const {
    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    std::vector<GlobalAccessReport> reports;
    std::unordered_map<ZydisRegister, DereferencedPointer> register_pointer_map;
    size_t off = 0;
    size_t instruction_count = 0;
    size_t rip_relative_count = 0;
    
    while (off < m_text.size()) {
        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        if (ZYAN_FAILED(ZydisDecoderDecodeFull(&dec,
                 m_text.data() + off, m_text.size() - off, &insn, operands)))
            { ++off; continue; }  // undecodable byte – advance

        const uint64_t ip = m_text_va + off;
        instruction_count++;
        
        // Count RIP-relative instructions for debugging
        for (uint8_t i = 0; i < insn.operand_count; ++i) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && 
                operands[i].mem.base == ZYDIS_REGISTER_RIP) {
                rip_relative_count++;
                break;
            }
        }
        
        ProcessInstruction(off, ip, insn, operands, reports, register_pointer_map);
        off += insn.length;
    }
    
    std::cerr << "Debug: Analyzed " << instruction_count << " instructions\n";
    std::cerr << "Debug: Found " << rip_relative_count << " RIP-relative instructions\n";
    std::cerr << "Debug: .text section VA: 0x" << std::hex << m_text_va 
              << ", size: 0x" << m_text.size() << std::dec << "\n";
    
    return reports;
}

// Infer the type based on collected stats
InferredType GlobalCallAnalyzer::InferTypeFromStats(const OffsetStats& stats) {
    if (stats.type_info.has_calls) {
        return InferredType::FUNCTION_POINTER;
    }
    if (stats.type_info.has_float_ops) {
        if (stats.type_info.size_histogram.count(4)) {
            return InferredType::FLOAT;
        }
        if (stats.type_info.size_histogram.count(8)) {
            return InferredType::DOUBLE;
        }
    }
    if (stats.type_info.size_histogram.size() == 1) {
        const auto size = stats.type_info.size_histogram.begin()->first;
        switch (size) {
            case 1: return InferredType::BYTE;
            case 2: return InferredType::WORD;
            case 4: return InferredType::DWORD;
            case 8: return InferredType::QWORD;
        }
    }
    if (stats.type_info.size_histogram.count(8)) {
        return InferredType::POINTER;
    }
    return InferredType::STRUCT;  // Default to complex type
}

// Overload for NestedAccess - uses the same logic since it has the same relevant fields
InferredType GlobalCallAnalyzer::InferTypeFromStats(const NestedAccess& nested) {
    if (nested.type_info.has_calls) {
        return InferredType::FUNCTION_POINTER;
    }
    if (nested.type_info.has_float_ops) {
        if (nested.type_info.size_histogram.count(4)) {
            return InferredType::FLOAT;
        }
        if (nested.type_info.size_histogram.count(8)) {
            return InferredType::DOUBLE;
        }
    }
    if (nested.type_info.size_histogram.size() == 1) {
        const auto size = nested.type_info.size_histogram.begin()->first;
        switch (size) {
            case 1: return InferredType::BYTE;
            case 2: return InferredType::WORD;
            case 4: return InferredType::DWORD;
            case 8: return InferredType::QWORD;
        }
    }
    if (nested.type_info.size_histogram.count(8)) {
        return InferredType::POINTER;
    }
    return InferredType::STRUCT;  // Default to complex type
}

const char* GlobalCallAnalyzer::TypeToString(InferredType type) {
    switch (type) {
        case InferredType::UNKNOWN: return "Unknown";
        case InferredType::BYTE: return "Byte";
        case InferredType::WORD: return "Word";
        case InferredType::DWORD: return "DWord";
        case InferredType::QWORD: return "QWord";
        case InferredType::POINTER: return "Pointer";
        case InferredType::FLOAT: return "Float";
        case InferredType::DOUBLE: return "Double";
        case InferredType::FUNCTION_POINTER: return "Function Pointer";
        case InferredType::STRUCT: return "Struct";
    }
    return "Unknown";
}

} // namespace BinA

