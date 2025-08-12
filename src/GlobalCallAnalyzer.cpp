#include "GlobalCallAnalyzer.hpp"
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <functional>
#include <thread>

#if GCA_ENABLE_PAR
#include <execution>
#include <mutex>
#endif

namespace BinA {

// =================================================================================================
// Utility Functions
// =================================================================================================

namespace {

// Use the modern, non-deprecated Zydis function for getting the largest enclosing register.
ZydisRegister GetFullRegister(ZydisRegister reg) {
    return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
}

bool OperandReads(const ZydisDecodedOperand& op) {
    return (op.actions & ZYDIS_OPERAND_ACTION_READ) != 0;
}

bool OperandWrites(const ZydisDecodedOperand& op) {
    return (op.actions & ZYDIS_OPERAND_ACTION_WRITE) != 0;
}

void RecordAccess(GlobalAccessReport& report,
                  const std::vector<int64_t>& path,
                  int64_t final_offset,
                  const ZydisDecodedInstruction& instr,
                  const ZydisDecodedOperand& mem_op) {

    std::unordered_map<int64_t, OffsetStats>* current_level_offsets = &report.per_offset;
    NestedAccess* current_level_nested = nullptr;

    for (int64_t offset_in_path : path) {
        if (current_level_offsets) {
            auto& stats = (*current_level_offsets)[offset_in_path];
            stats.relative = offset_in_path;
            // The first nested access represents the pointer itself. Subsequent accesses are fields.
            current_level_nested = &stats.nested_accesses[0];
            current_level_offsets = nullptr;
        } else {
            current_level_nested = &current_level_nested->nested_accesses[offset_in_path];
        }
    }

    TypeInfo* type_info = nullptr;
    size_t* call_hits = nullptr;
    size_t* load_hits = nullptr;
    size_t* store_hits = nullptr;

    if (current_level_nested) {
        auto& nested_stats = current_level_nested->nested_accesses[final_offset];
        type_info = &nested_stats.type_info;
        call_hits = &nested_stats.call_hits;
        load_hits = &nested_stats.load_hits;
        store_hits = &nested_stats.store_hits;
    } else {
        auto& stats = report.per_offset[final_offset];
        stats.relative = final_offset;
        type_info = &stats.type_info;
        call_hits = &stats.call_hits;
        load_hits = &stats.load_hits;
        store_hits = &stats.store_hits;
    }

    if (instr.mnemonic == ZYDIS_MNEMONIC_CALL) {
        (*call_hits)++;
        type_info->has_calls = true;
    } else {
        if (OperandReads(mem_op)) (*load_hits)++;
        if (OperandWrites(mem_op)) (*store_hits)++;
    }

    if (mem_op.size > 0) {
        type_info->size_histogram[mem_op.size / 8]++;
    }

    switch (instr.meta.category) {
        case ZYDIS_CATEGORY_SSE:
        case ZYDIS_CATEGORY_AVX:
        case ZYDIS_CATEGORY_X87_ALU:
            type_info->has_float_ops = true;
            break;
        default:
            break;
    }
}

} // anonymous namespace

// =================================================================================================
// Constructor & PE Parsing
// =================================================================================================

GlobalCallAnalyzer::GlobalCallAnalyzer(std::span<const uint8_t> module_view, bool is_memory_image)
    : m_view(module_view), m_is_memory_image(is_memory_image) {
    ParsePE();
}

void GlobalCallAnalyzer::ParsePE() {
    if (m_view.size() < sizeof(IMAGE_DOS_HEADER)) throw std::runtime_error("DOS header too small");
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_view.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) throw std::runtime_error("Bad MZ signature");

    const auto nt_off = dos->e_lfanew;
    if (nt_off + sizeof(IMAGE_NT_HEADERS64) > m_view.size()) throw std::runtime_error("PE header out of bounds");
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(m_view.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) throw std::runtime_error("Bad PE signature");
    // FIX: Was IMAGE_OPTIONAL_HDR64_MAGIC
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) throw std::runtime_error("Only 64-bit PE files are supported");

    m_image_base = nt->OptionalHeader.ImageBase;

    if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT) {
        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
        if (dir.VirtualAddress && dir.Size) {
            m_iat_va = m_image_base + dir.VirtualAddress;
            m_iat_end = m_iat_va + dir.Size;
        }
    }

    const auto sections = IMAGE_FIRST_SECTION(nt);
    m_sections.reserve(nt->FileHeader.NumberOfSections);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        Section s;
        char name_buf[9]{};
        memcpy(name_buf, sections[i].Name, 8);
        s.name = name_buf;
        s.va_start = m_image_base + sections[i].VirtualAddress;
        s.va_end = s.va_start + sections[i].Misc.VirtualSize;
        s.rva_start = sections[i].VirtualAddress;
        s.rva_end = s.rva_start + sections[i].Misc.VirtualSize;
        s.raw_ptr = sections[i].PointerToRawData;
        s.raw_size = sections[i].SizeOfRawData;
        s.characteristics = sections[i].Characteristics;
        if (s.characteristics & IMAGE_SCN_CNT_CODE) s.kind = GlobalAccessReport::SectionType::TEXT;
        else if (s.name == ".rdata") s.kind = GlobalAccessReport::SectionType::RDATA;
        else if (s.name == ".data") s.kind = GlobalAccessReport::SectionType::DATA;
        else if (s.name == ".idata") s.kind = GlobalAccessReport::SectionType::IDATA;
        else if (s.name == ".pdata") s.kind = GlobalAccessReport::SectionType::PDATA;
        else if (s.name == ".xdata") s.kind = GlobalAccessReport::SectionType::XDATA;
        else if (s.name == ".rsrc") s.kind = GlobalAccessReport::SectionType::RSRC;
        else if (s.name == ".tls") s.kind = GlobalAccessReport::SectionType::TLS;
        else s.kind = GlobalAccessReport::SectionType::OTHER;
        m_sections.push_back(s);
    }

    auto text_sec_it = std::find_if(m_sections.begin(), m_sections.end(), [](const Section& s) {
        return s.kind == GlobalAccessReport::SectionType::TEXT;
    });
    if (text_sec_it == m_sections.end()) throw std::runtime_error(".text section not found");
    m_text_va = text_sec_it->va_start;
}

// =================================================================================================
// Lightweight Metadata Indexing
// =================================================================================================

std::span<const uint8_t> GlobalCallAnalyzer::GetTextBytes() const {
    const auto* text_sec = FindSectionByVA(m_text_va);
    if (!text_sec) throw std::logic_error(".text section info disappeared during analysis");

    if (m_is_memory_image) {
        size_t rva_size = text_sec->rva_end - text_sec->rva_start;
        if (text_sec->rva_start + rva_size > m_view.size())
            throw std::runtime_error(".text RVA range is out of bounds for the provided memory view");
        return m_view.subspan(text_sec->rva_start, rva_size);
    } else {
        if (text_sec->raw_ptr + text_sec->raw_size > m_view.size())
            throw std::runtime_error(".text raw file range is out of bounds for the provided file view");
        return m_view.subspan(text_sec->raw_ptr, text_sec->raw_size);
    }
}

void GlobalCallAnalyzer::BuildMetadataIndex() const {
    if (!m_metadata_index.empty()) return;

    auto text_bytes = GetTextBytes();
    m_metadata_index.reserve(text_bytes.size() / 4);

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    size_t offset = 0;

    while (offset < text_bytes.size()) {
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, text_bytes.data() + offset, text_bytes.size() - offset, &insn, ops))) {
            InstructionMetadata meta;
            meta.offset = static_cast<uint32_t>(offset);
            meta.length = insn.length;
            meta.flags = FLAG_NONE;

            if (insn.mnemonic == ZYDIS_MNEMONIC_MOV || insn.mnemonic == ZYDIS_MNEMONIC_LEA) {
                for (uint8_t i = 0; i < insn.operand_count; ++i) {
                    if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[i].mem.base == ZYDIS_REGISTER_RIP) {
                        meta.flags |= FLAG_IS_ROOT_CANDIDATE;
                        break;
                    }
                }
            }
            if (insn.meta.category == ZYDIS_CATEGORY_CALL) meta.flags |= FLAG_IS_CALL;
            if (insn.meta.category == ZYDIS_CATEGORY_RET) meta.flags |= FLAG_IS_RET;
            // FIX: Was ZYDIS_CATEGORY_JUMP
            if (insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR || insn.meta.category == ZYDIS_CATEGORY_COND_BR) {
                meta.flags |= FLAG_IS_JMP_OR_BRANCH;
            }

            m_metadata_index.push_back(meta);
            offset += insn.length;
        } else {
            ++offset;
        }
    }
}

// =================================================================================================
// Core Analysis - REWRITTEN
// =================================================================================================

std::vector<GlobalAccessReport> GlobalCallAnalyzer::Analyze() const {
    BuildMetadataIndex();

    std::vector<size_t> root_indices;
    for (size_t i = 0; i < m_metadata_index.size(); ++i) {
        if (m_metadata_index[i].flags & FLAG_IS_ROOT_CANDIDATE) {
            root_indices.push_back(i);
        }
    }

    // The parallel processing logic remains, but it now calls the new FollowPath function.
#if GCA_ENABLE_PAR
    std::mutex reports_mutex;
    std::unordered_map<uint64_t, GlobalAccessReport> final_reports_map;

    std::for_each(std::execution::par, root_indices.begin(), root_indices.end(), [&](size_t root_idx) {
        std::unordered_map<uint64_t, GlobalAccessReport> thread_local_reports;
        FollowPath(root_idx, thread_local_reports);

        std::scoped_lock lock(reports_mutex);
        for (auto& [va, report] : thread_local_reports) {
            auto& target_report = final_reports_map[va];
            if (target_report.global_va == 0) {
                target_report = std::move(report);
            } else {
                // Merge logic for per_offset stats
                for (auto& [offset, stats] : report.per_offset) {
                    auto& target_stats = target_report.per_offset[offset];
                    target_stats.load_hits += stats.load_hits;
                    target_stats.store_hits += stats.store_hits;
                    target_stats.call_hits += stats.call_hits;
                    // A more robust merge would also combine histograms and nested accesses
                }
            }
        }
    });

#else
    std::unordered_map<uint64_t, GlobalAccessReport> final_reports_map;
    for (size_t root_idx : root_indices) {
        FollowPath(root_idx, final_reports_map);
    }
#endif

    std::vector<GlobalAccessReport> final_reports;
    final_reports.reserve(final_reports_map.size());
    for (auto& [va, report] : final_reports_map) {
        EnrichReport(report);
        final_reports.push_back(std::move(report));
    }

    std::sort(final_reports.begin(), final_reports.end(),
              [](const auto& a, const auto& b) { return a.global_va < b.global_va; });

    return final_reports;
}

// ARCHITECTURE: This is the new core analysis engine, replacing ProcessRoot.
// It implements the state-tainting model described in Part 1.
void GlobalCallAnalyzer::FollowPath(size_t start_idx,
                                    std::unordered_map<uint64_t, GlobalAccessReport>& reports) const {
    auto text_bytes = GetTextBytes();
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    // 1. Identify the initial root global access
    const auto& root_meta = m_metadata_index[start_idx];
    ZydisDecodedInstruction root_insn;
    ZydisDecodedOperand root_ops[ZYDIS_MAX_OPERAND_COUNT];
    if (ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder, text_bytes.data() + root_meta.offset,
                                            text_bytes.size() - root_meta.offset, &root_insn, root_ops))) {
        return;
    }

    uint64_t global_va = 0;
    ZydisRegister root_dest_reg = ZYDIS_REGISTER_NONE;
    bool is_lea = (root_insn.mnemonic == ZYDIS_MNEMONIC_LEA);

    for (uint8_t i = 0; i < root_insn.operand_count; ++i) {
        const auto& op = root_ops[i];
        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base == ZYDIS_REGISTER_RIP) {
            uint64_t rip = m_text_va + root_meta.offset + root_insn.length;
            global_va = rip + op.mem.disp.value;

            const auto* section = FindSectionByVA(global_va);
            if (!section || section->kind == GlobalAccessReport::SectionType::TEXT) {
                return; // Not a valid data global
            }

            if (root_insn.operand_count > 0 && root_ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                root_dest_reg = GetFullRegister(root_ops[0].reg.value);
            }
            break;
        }
    }

    if (global_va == 0 || root_dest_reg == ZYDIS_REGISTER_NONE) return;

    // 2. Initialize the register state machine
    RegisterState reg_state;
    TrackedPointer initial_ptr;
    initial_ptr.source_global_va = global_va;
    // If the root instruction was LEA, the register holds the address of the global itself.
    // If it was MOV, the register holds the VALUE loaded from the global (a dereference).
    if (!is_lea) {
        initial_ptr.path.push_back(0); // Path now represents one level of dereference
    }
    reg_state[root_dest_reg] = initial_ptr;

    // 3. Follow the code path, updating state for each instruction
    // ARCHITECTURE: Replaced fixed window with control-flow-aware loop. See Part 2, Phase 1.
    for (size_t i = start_idx + 1; i < m_metadata_index.size(); ++i) {
        const auto& meta = m_metadata_index[i];
        if (i > start_idx + 128) break; // Safety break to prevent infinite loops in complex CFGs

        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder, text_bytes.data() + meta.offset,
                                                text_bytes.size() - meta.offset, &insn, ops))) {
            continue;
        }

        // Check for memory accesses using a tracked register
        for (uint8_t j = 0; j < insn.operand_count; ++j) {
            const auto& op = ops[j];
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base != ZYDIS_REGISTER_NONE) {
                auto it = reg_state.find(GetFullRegister(op.mem.base));
                if (it != reg_state.end()) {
                    const auto& ptr = it->second;
                    auto& report = reports[ptr.source_global_va];
                    if (report.global_va == 0) report.global_va = ptr.source_global_va;

                    int64_t final_offset = ptr.accumulated_offset + op.mem.disp.value;
                    RecordAccess(report, ptr.path, final_offset, insn, op);

                    // ARCHITECTURE: This is the critical dereferencing logic. See Part 1, Section 1.1.
                    // If we are loading a new pointer from a tracked memory location...
                    if (insn.mnemonic == ZYDIS_MNEMONIC_MOV && op.size == 64 && OperandReads(op)) {
                        for (uint8_t k = 0; k < insn.operand_count; ++k) {
                            if (ops[k].type == ZYDIS_OPERAND_TYPE_REGISTER && OperandWrites(ops[k])) {
                                TrackedPointer new_ptr = ptr;
                                new_ptr.path.push_back(final_offset); // ...the path gets deeper...
                                new_ptr.accumulated_offset = 0;       // ...and the offset resets.
                                reg_state[GetFullRegister(ops[k].reg.value)] = new_ptr;
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Update register state based on instruction semantics
        bool reg_written = false;
        if (insn.operand_count > 0 && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && OperandWrites(ops[0])) {
            ZydisRegister dst_reg = GetFullRegister(ops[0].reg.value);

            switch (insn.mnemonic) {
                case ZYDIS_MNEMONIC_MOV:
                    if (insn.operand_count > 1 && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                        auto it = reg_state.find(GetFullRegister(ops[1].reg.value));
                        if (it != reg_state.end()) {
                            reg_state[dst_reg] = it->second; // Propagate taint
                        } else {
                            reg_state.erase(dst_reg); // Destination is overwritten with untracked value
                        }
                        reg_written = true;
                    }
                    break;
                case ZYDIS_MNEMONIC_LEA:
                    // LEA is complex. For now, we handle simple [base + disp]
                    if (insn.operand_count > 1 && ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                        auto it = reg_state.find(GetFullRegister(ops[1].mem.base));
                        if (it != reg_state.end()) {
                            TrackedPointer new_ptr = it->second;
                            new_ptr.accumulated_offset += ops[1].mem.disp.value;
                            reg_state[dst_reg] = new_ptr;
                            reg_written = true;
                        }
                    }
                    break;
                case ZYDIS_MNEMONIC_ADD:
                case ZYDIS_MNEMONIC_SUB:
                    if (insn.operand_count > 1 && ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                        auto it = reg_state.find(dst_reg);
                        if (it != reg_state.end()) {
                            int64_t offset = ops[1].imm.value.s;
                            if (insn.mnemonic == ZYDIS_MNEMONIC_SUB) offset = -offset;
                            it->second.accumulated_offset += offset;
                            reg_written = true;
                        }
                    }
                    break;
                case ZYDIS_MNEMONIC_XOR:
                     if (insn.operand_count > 1 && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                         GetFullRegister(ops[1].reg.value) == dst_reg) {
                         reg_state.erase(dst_reg); // Register zeroed, taint removed
                         reg_written = true;
                     }
                     break;
                default:
                    break;
            }

            if (!reg_written) {
                reg_state.erase(dst_reg); // Default: any write to a register clears its tracked state
            }
        }

        // Terminate analysis at the end of a basic block
        if (meta.flags & (FLAG_IS_RET | FLAG_IS_JMP_OR_BRANCH)) break;

        // ARCHITECTURE: Model x64 calling convention. See Part 2, Phase 1.
        if (meta.flags & FLAG_IS_CALL) {
            // Clear all volatile registers
            reg_state.erase(ZYDIS_REGISTER_RAX);
            reg_state.erase(ZYDIS_REGISTER_RCX);
            reg_state.erase(ZYDIS_REGISTER_RDX);
            reg_state.erase(ZYDIS_REGISTER_R8);
            reg_state.erase(ZYDIS_REGISTER_R9);
            reg_state.erase(ZYDIS_REGISTER_R10);
            reg_state.erase(ZYDIS_REGISTER_R11);
        }
    }
}

// =================================================================================================
// Heuristics and Classification
// =================================================================================================

const GlobalCallAnalyzer::Section* GlobalCallAnalyzer::FindSectionByVA(uint64_t va) const {
    for (const auto& s : m_sections) {
        if (va >= s.va_start && va < s.va_end) return &s;
    }
    return nullptr;
}

std::span<const uint8_t> GlobalCallAnalyzer::SpanForVA(uint64_t va, size_t size) const {
    const auto* section = FindSectionByVA(va);
    if (!section) return {};

    uint64_t offset_in_section = va - section->va_start;
    uint32_t base_offset = m_is_memory_image ? section->rva_start : section->raw_ptr;
    uint32_t section_size = m_is_memory_image ? (section->rva_end - section->rva_start) : section->raw_size;

    if (offset_in_section + size > section_size) return {};
    if (base_offset + offset_in_section + size > m_view.size()) return {};

    return m_view.subspan(base_offset + offset_in_section, size);
}

void GlobalCallAnalyzer::EnrichReport(GlobalAccessReport& report) const {
    const auto* section = FindSectionByVA(report.global_va);
    if (section) {
        report.section_name = section->name;
        report.section_type = section->kind;
    }
    report.is_in_iat = (report.global_va >= m_iat_va && report.global_va < m_iat_end);

    if (report.section_type == GlobalAccessReport::SectionType::RDATA) {
        // String check is now more general
        if (LooksLikeAscii(report.global_va, report.string_preview)) {
            report.likely_string = true;
        }
        if (LooksLikeVTable(report.global_va)) {
            report.likely_vtable = true;
        }
    }
}

bool GlobalCallAnalyzer::LooksLikeVTable(uint64_t va) const {
    auto view = SpanForVA(va, 8 * sizeof(uint64_t));
    if (view.size() < sizeof(uint64_t)) return false;

    int code_pointers = 0;
    for (size_t i = 0; i < view.size() / sizeof(uint64_t); ++i) {
        uint64_t entry_va;
        memcpy(&entry_va, view.data() + i * sizeof(uint64_t), sizeof(uint64_t));
        const auto* section = FindSectionByVA(entry_va);
        if (section && section->kind == GlobalAccessReport::SectionType::TEXT) {
            ++code_pointers;
        }
    }
    return code_pointers >= 3;
}

bool GlobalCallAnalyzer::LooksLikeAscii(uint64_t va, std::string& out_preview) const {
    auto view = SpanForVA(va, 128);
    if (view.empty()) return false;

    size_t printable_chars = 0;
    size_t len = 0;
    for (uint8_t c : view) {
        if (c == 0) break;
        ++len;
        if (isprint(c) || isspace(c)) ++printable_chars;
    }

    if (len == 0 || len == view.size()) return false;
    if (static_cast<double>(printable_chars) / len < 0.85) return false;

    out_preview.assign(reinterpret_cast<const char*>(view.data()), std::min<size_t>(len, 64));
    return true;
}

bool GlobalCallAnalyzer::LooksLikeJumpTablePattern(size_t /*root_index*/, ZydisRegister /*base_reg*/) const {
    // Placeholder: true implementation requires deeper integration with the decoder.
    return false;
}

// =================================================================================================
// Public Static Helpers
// =================================================================================================

InferredType GlobalCallAnalyzer::InferTypeFromStats(const OffsetStats& stats) {
    if (stats.type_info.has_calls) return InferredType::FUNCTION_POINTER;
    if (stats.type_info.has_float_ops) {
        if (stats.type_info.size_histogram.count(8)) return InferredType::DOUBLE;
        if (stats.type_info.size_histogram.count(4)) return InferredType::FLOAT;
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
    if (stats.type_info.size_histogram.count(8)) return InferredType::POINTER;
    return InferredType::STRUCT;
}

InferredType GlobalCallAnalyzer::InferTypeFromStats(const NestedAccess& nested) {
    if (nested.type_info.has_calls) return InferredType::FUNCTION_POINTER;
    if (nested.type_info.has_float_ops) {
        if (nested.type_info.size_histogram.count(8)) return InferredType::DOUBLE;
        if (nested.type_info.size_histogram.count(4)) return InferredType::FLOAT;
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
    if (nested.type_info.size_histogram.count(8)) return InferredType::POINTER;
    return InferredType::STRUCT;
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
        case InferredType::FUNCTION_POINTER: return "Function Ptr";
        case InferredType::STRUCT: return "Struct";
    }
    return "Unknown";
}

} // namespace BinA
