#pragma once
#include <Zydis/Zydis.h>
#include <cstdint>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

namespace BinA {

enum class AccessKind : uint8_t { VIRTUAL_CALL, DATA_LOAD, DATA_STORE };

// Type inference for globals
enum class InferredType : uint8_t {
    UNKNOWN,
    BYTE,      // 8-bit
    WORD,      // 16-bit
    DWORD,     // 32-bit
    QWORD,     // 64-bit
    POINTER,   // Pointer (64-bit on x64)
    FLOAT,     // 32-bit float
    DOUBLE,    // 64-bit double
    FUNCTION_POINTER,  // Called through
    STRUCT     // Complex/mixed accesses
};

struct TypeInfo {
    InferredType type = InferredType::UNKNOWN;
    size_t confidence = 0;  // How many accesses support this type
    std::unordered_map<size_t, size_t> size_histogram;  // operand size -> count
    bool has_float_ops = false;
    bool has_calls = false;
};

// Maximum depth for nested pointer tracking
constexpr size_t MAX_NESTING_DEPTH = 2;

// Forward declaration for nested tracking
struct NestedAccess;

// Tracks statistics for accesses at a specific offset
struct OffsetStats {
    int64_t   relative{};  // Changed to int64_t to handle negative offsets
    size_t    call_hits  = 0;
    size_t    load_hits  = 0;
    size_t    store_hits = 0;
    TypeInfo  type_info;
    
    // Map of nested accesses: offset -> NestedAccess
    // This tracks second-level dereferences (e.g., when this offset contains a pointer)
    std::unordered_map<int64_t, NestedAccess> nested_accesses;
};

// Represents a second-level access through a dereferenced pointer
struct NestedAccess {
    int64_t dereferenced_offset{};  // Offset being accessed through the pointer (signed)
    size_t call_hits = 0;
    size_t load_hits = 0;
    size_t store_hits = 0;
    TypeInfo type_info;
    
    // For deeper nesting (if needed in future), but limited by MAX_NESTING_DEPTH
    std::unordered_map<int64_t, NestedAccess> nested_accesses;
};

// Tracks when a register contains a loaded pointer value
struct DereferencedPointer {
    uint64_t source_global_va{};     // Global variable the pointer was loaded from
    int64_t source_offset{};         // Offset within the global where pointer was loaded (signed)
    ZydisRegister loaded_register{}; // Register containing the loaded pointer
    size_t instruction_index{};      // Instruction where the load occurred
    size_t nesting_level = 1;        // Current nesting depth (1 = first dereference)
    int64_t accumulated_offset{};    // Total offset adjustment from pointer arithmetic
};

struct GlobalAccessReport {
    uint64_t                                   global_va{};
    std::unordered_map<int64_t, OffsetStats>  per_offset;  // Changed to int64_t for signed offsets
};

class GlobalCallAnalyzer {
public:
    explicit GlobalCallAnalyzer(std::span<const uint8_t> module_view);

    /** Disassemble .text and return one report per distinct global handle. */
    [[nodiscard]] std::vector<GlobalAccessReport> Analyze() const;

private:
    // helpers
    void ParsePE();
    static bool IsRIPRelativeMovOrLEA(const ZydisDecodedInstruction&, const ZydisDecodedOperand&);
    static bool OperandReads(const ZydisDecodedOperand& op);
    static bool OperandWrites(const ZydisDecodedOperand& op);
    static ZydisRegister GetFullRegister(ZydisRegister reg);
    static bool RegistersOverlap(ZydisRegister reg1, ZydisRegister reg2);

    // analysis
    void ProcessInstruction(size_t idx,
                            uint64_t ip,
                            const ZydisDecodedInstruction& insn,
                            const ZydisDecodedOperand* operands,
                            std::vector<GlobalAccessReport>& reports,
                            std::unordered_map<ZydisRegister, DereferencedPointer>& register_pointer_map) const;
    
public:
    // Type inference utilities
    static InferredType InferTypeFromStats(const OffsetStats& stats);
    static InferredType InferTypeFromStats(const NestedAccess& nested);
    static const char* TypeToString(InferredType type);

private:
    
    std::span<const uint8_t> m_view;
    std::span<const uint8_t> m_text;
    uint64_t                 m_text_va = 0;
};

} // namespace BinA
