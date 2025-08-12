#include "GlobalCallAnalyzer.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <functional>
#include <chrono>
#include <algorithm>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// Helper to sort map keys for consistent, deterministic output.
template <typename K, typename V>
std::vector<K> get_sorted_keys(const std::unordered_map<K, V>& umap) {
    std::vector<K> keys;
    keys.reserve(umap.size());
    for (const auto& [key, val] : umap) {
        keys.push_back(key);
    }
    std::sort(keys.begin(), keys.end());
    return keys;
}

// A helper class to memory-map a file for efficient read-only access.
class MemoryMappedFile {
public:
    MemoryMappedFile(const char* path) {
        m_fd = open(path, O_RDONLY);
        if (m_fd == -1) throw std::runtime_error("Failed to open file");

        struct stat sb;
        if (fstat(m_fd, &sb) == -1) {
            close(m_fd);
            throw std::runtime_error("Failed to get file size");
        }
        m_size = sb.st_size;

        m_view = mmap(nullptr, m_size, PROT_READ, MAP_PRIVATE, m_fd, 0);
        if (m_view == MAP_FAILED) {
            close(m_fd);
            throw std::runtime_error("Failed to map file");
        }
    }

    ~MemoryMappedFile() {
        if (m_view && m_view != MAP_FAILED) munmap(m_view, m_size);
        if (m_fd != -1) close(m_fd);
    }

    std::span<const uint8_t> GetView() const {
        return {static_cast<const uint8_t*>(m_view), static_cast<size_t>(m_size)};
    }

private:
    int m_fd = -1;
    void* m_view = nullptr;
    size_t m_size = 0;
};

void PrintReports(const std::string& label, const std::vector<BinA::GlobalAccessReport>& reports) {
    std::cout << "Analyzing: " << label << "\n";
    std::cout << "Found " << reports.size() << " global variable references\n\n";

    for (const auto& r : reports) {
        std::cout << "GLOBAL 0x" << std::hex << r.global_va << std::dec;
        if (!r.section_name.empty()) std::cout << " (" << r.section_name << ")";
        if (r.is_in_iat) std::cout << " [IAT]";
        if (r.likely_vtable) std::cout << " [VTABLE]";
        if (r.likely_jump_table) std::cout << " [JUMP TABLE]";
        if (r.likely_string) std::cout << " [STRING: \"" << r.string_preview << "\"]";
        std::cout << '\n';

        for (const auto& offset : get_sorted_keys(r.per_offset)) {
            const auto& st = r.per_offset.at(offset);
            auto inferred_type = BinA::GlobalCallAnalyzer::InferTypeFromStats(st);

            std::cout << "  " << (offset < 0 ? "[-0x" : "[+0x") << std::hex << (offset < 0 ? -offset : offset) << "] ";
            std::cout << std::left << std::setw(14) << BinA::GlobalCallAnalyzer::TypeToString(inferred_type);
            std::cout << " calls=" << std::dec << st.call_hits
                      << ", loads=" << st.load_hits
                      << ", stores=" << st.store_hits;

            if (st.type_info.size_histogram.size() > 1) {
                std::cout << ", sizes={";
                bool first = true;
                for (const auto& [size, count] : st.type_info.size_histogram) {
                    if (!first) std::cout << ", ";
                    std::cout << size << "B:" << count;
                    first = false;
                }
                std::cout << "}";
            }
            std::cout << '\n';

            if (!st.nested_accesses.empty()) {
                std::function<void(const std::unordered_map<int64_t, BinA::NestedAccess>&, const std::string&)> displayNested;
                displayNested = [&](const auto& nestedMap, const std::string& prefix) {
                    auto nested_keys = get_sorted_keys(nestedMap);
                    for (size_t i = 0; i < nested_keys.size(); ++i) {
                        const auto& nrel = nested_keys[i];
                        const auto& nst = nestedMap.at(nrel);
                        bool isLast = (i == nested_keys.size() - 1);

                        std::cout << prefix << (isLast ? "└── " : "├── ");
                        std::cout << (nrel < 0 ? "[-0x" : "[+0x") << std::hex << (nrel < 0 ? -nrel : nrel) << "] ";
                        std::cout << std::left << std::setw(14) << BinA::GlobalCallAnalyzer::TypeToString(BinA::GlobalCallAnalyzer::InferTypeFromStats(nst));
                        std::cout << " calls=" << std::dec << nst.call_hits << ", loads=" << nst.load_hits << ", stores=" << nst.store_hits << '\n';

                        if (!nst.nested_accesses.empty()) {
                            displayNested(nst.nested_accesses, prefix + (isLast ? "    " : "│   "));
                        }
                    }
                };
                displayNested(st.nested_accesses, "      ");
            }
        }
        std::cout << '\n';
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <PE_file_path>\n";
        return 1;
    }

    try {
        auto start_time = std::chrono::high_resolution_clock::now();
        
        std::string label = argv[1];
        MemoryMappedFile mmf(argv[1]);
        BinA::GlobalCallAnalyzer gca(mmf.GetView(), false);
        auto reports = gca.Analyze();

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

        PrintReports(label, reports);
        std::cout << "--------------------------------------------------\n";
        std::cout << "Analysis completed in " << duration.count() << " ms.\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
