#pragma once

#include <cstdint>
#include <span>
#include <vector>
#include <string>
#include <unordered_map>
#include <optional>
#include <Zydis/Zydis.h>
#include <windows.h> // For IMAGE_* types

// Define GCA_ENABLE_PAR to 0 to disable C++17 parallel algorithms for debugging or on unsupported compilers.
#ifndef GCA_ENABLE_PAR
#define GCA_ENABLE_PAR 1
#endif

namespace BinA {

// =================================================================================================
// Data Model for Analysis Reports
// These structs define the output of the analysis, compatible with the original display logic but
// extended with richer classification information.
// =================================================================================================

/**
 * @brief Contains type inference information gathered from instruction usage.
 */
struct TypeInfo {
    bool has_calls = false;      ///< True if the memory at this offset was used in a CALL instruction.
    bool has_float_ops = false;  ///< True if used with floating-point/SSE/AVX instructions.
    std::unordered_map<size_t, size_t> size_histogram; ///< Maps operand size in bytes to access frequency.
};

/**
 * @brief Represents an access to a field within a nested structure.
 *
 * This is used for accesses like `base->ptr_field->some_other_field`.
 */
struct NestedAccess {
    size_t load_hits = 0;
    size_t store_hits = 0;
    size_t call_hits = 0;
    TypeInfo type_info;
    /// @brief Further nested accesses, keyed by their relative offset.
    std::unordered_map<int64_t, NestedAccess> nested_accesses;
};

/**
 * @brief Represents all accesses to a specific offset within a global variable.
 */
struct OffsetStats {
    int64_t relative = 0; ///< The offset from the global variable's base address.
    size_t load_hits = 0;
    size_t store_hits = 0;
    size_t call_hits = 0;
    TypeInfo type_info;
    /// @brief Nested accesses originating from a pointer at this offset.
    std::unordered_map<int64_t, NestedAccess> nested_accesses;
};

/**
 * @brief The top-level report for a single global variable.
 */
struct GlobalAccessReport {
    uint64_t global_va = 0; ///< The virtual address of the global variable.
    /// @brief A map of all first-level offsets accessed within this global.
    std::unordered_map<int64_t, OffsetStats> per_offset;

    // --- Extended Intelligence Fields ---
    std::string section_name; ///< e.g., ".rdata", ".data"
    enum class SectionType { TEXT, RDATA, DATA, IDATA, PDATA, XDATA, RSRC, TLS, OTHER } section_type = SectionType::OTHER;

    bool likely_vtable = false;     ///< Heuristic: true if it looks like a C++ v-table.
    bool likely_jump_table = false; ///< Heuristic: true if used as a base for an indexed jump.
    bool likely_string = false;     ///< Heuristic: true if it points to a printable, null-terminated string.
    std::string string_preview;     ///< A short preview of the string content if likely_string is true.
    bool is_in_iat = false;         ///< True if the global VA is within the PE's Import Address Table.
};

/**
 * @brief The set of possible inferred types for a given memory location.
 */
enum class InferredType {
    UNKNOWN, BYTE, WORD, DWORD, QWORD, POINTER, FLOAT, DOUBLE, FUNCTION_POINTER, STRUCT
};


// =================================================================================================
// Core Analyzer Class
// =================================================================================================

class GlobalCallAnalyzer {
public:
    /**
     * @brief Constructs the analyzer for a given binary view.
     * @param module_view A span covering the binary data.
     * @param is_memory_image Set to `true` if the view is from a loaded module in memory (respects RVAs).
     *                        Set to `false` if the view is from a raw file on disk (respects file offsets).
     *                        This is critical for correct VA mapping.
     */
    GlobalCallAnalyzer(std::span<const uint8_t> module_view, bool is_memory_image);

    /**
     * @brief Runs the full analysis pipeline.
     * @return A vector of reports, one for each discovered global variable.
     */
    std::vector<GlobalAccessReport> Analyze() const;

    // --- Public Static Helpers ---

    static InferredType InferTypeFromStats(const OffsetStats& stats);
    static InferredType InferTypeFromStats(const NestedAccess& nested);
    static const char* TypeToString(InferredType type);

private:
    // =============================================================================================
    // Internal Structures for Analysis
    // =============================================================================================

    /**
     * @brief Represents a pointer being tracked in a register during analysis.
     *
     * This struct contains the full "provenance" of a pointer, allowing for deep analysis.
     */
    struct TrackedPointer {
        uint64_t source_global_va = 0;  ///< The root global variable this pointer originated from.
        /// @brief The sequence of offsets taken to reach this pointer. Empty for a root pointer.
        /// e.g., for `A->B->C`, the path would be `{offset_of_B, offset_of_C}`.
        std::vector<int64_t> path;
        /// @brief Pointer arithmetic (`ADD`/`SUB`/`LEA`) offset accumulated since the last dereference.
        int64_t accumulated_offset = 0;
    };

    /// @brief Maps a full 64-bit register to the pointer it's currently tracking.
    using RegisterState = std::unordered_map<ZydisRegister, TrackedPointer>;

    /**
     * @brief A compact, pre-decoded representation of a single instruction.
     */
    struct DecodedInstr {
        ZydisDecodedInstruction insn{};
        std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> ops{};
        uint64_t ip = 0;
        uint32_t length = 0;
    };

    /**
     * @brief Internal representation of a PE section.
     */
    struct Section {
        std::string name;
        uint64_t va_start = 0, va_end = 0;
        uint32_t rva_start = 0, rva_end = 0;
        uint32_t raw_ptr = 0, raw_size = 0;
        uint32_t characteristics = 0;
        GlobalAccessReport::SectionType kind = GlobalAccessReport::SectionType::OTHER;
    };

    // =============================================================================================
    // Private Methods
    // =============================================================================================

    // --- Setup & Parsing ---
    void ParsePE();
    void PredecodeText() const;
    std::span<const uint8_t> SpanForVA(uint64_t va, size_t size) const;
    const Section* FindSectionByVA(uint64_t va) const;

    // --- Core Analysis Pipeline ---
    void ProcessRoot(size_t root_idx, const DecodedInstr& root_di,
                     std::unordered_map<uint64_t, GlobalAccessReport>& reports) const;

    // --- Heuristics & Classification ---
    void EnrichReport(GlobalAccessReport& rep, bool was_from_lea) const;
    bool LooksLikeVTable(uint64_t va) const;
    bool LooksLikeAscii(uint64_t va, std::string& out_preview) const;
    bool LooksLikeJumpTablePattern(size_t root_index, ZydisRegister base_reg) const;

    // =============================================================================================
    // Member Variables
    // =============================================================================================

    std::span<const uint8_t> m_view;
    bool m_is_memory_image;

    // --- PE Info ---
    uint64_t m_image_base = 0;
    std::vector<Section> m_sections;
    uint64_t m_iat_va = 0, m_iat_end = 0;

    // --- Pre-decoded Code ---
    mutable std::vector<DecodedInstr> m_prog;
    uint64_t m_text_va = 0;
};

} // namespace BinA
