#include "GlobalCallAnalyzer.hpp"
#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <sstream>
#include <iomanip>
#include <functional>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <PE_file_path>\n";
        std::cerr << "   or: " << argv[0] << " --loaded <module_name>\n";
        return 1;
    }

    std::vector<uint8_t> file_data;
    
    if (std::string(argv[1]) == "--loaded" && argc >= 3) {
        // Original behavior: analyze already loaded module
        HMODULE mod = GetModuleHandleA(argv[2]);
        if (!mod) { 
            std::cerr << "Module '" << argv[2] << "' not loaded\n"; 
            return 1; 
        }

        MODULEINFO mi{};
        GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi));

        std::span<const uint8_t> view(
            reinterpret_cast<const uint8_t*>(mi.lpBaseOfDll),
            mi.SizeOfImage);

        BinA::GlobalCallAnalyzer gca(view);
        auto reports = gca.Analyze();

        for (const auto& r : reports) {
            std::cout << "GLOBAL 0x" << std::hex << r.global_va << '\n';
            for (const auto& [rel, st] : r.per_offset) {
                // Display signed offset properly
                if (rel < 0) {
                    std::cout << "  [-0x" << std::hex << -rel << "]  ";
                } else {
                    std::cout << "  [+0x" << std::hex << rel << "]  ";
                }
                std::cout << "calls="  << st.call_hits
                          << "  loads=" << st.load_hits
                          << "  stores="<< st.store_hits << '\n';
            }
        }
    } else {
        // New behavior: analyze PE file from disk
        std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
        if (!file) {
            std::cerr << "Failed to open file: " << argv[1] << "\n";
            return 1;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        file_data.resize(size);
        if (!file.read(reinterpret_cast<char*>(file_data.data()), size)) {
            std::cerr << "Failed to read file: " << argv[1] << "\n";
            return 1;
        }

        std::span<const uint8_t> view(file_data);
        
        try {
            BinA::GlobalCallAnalyzer gca(view);
            auto reports = gca.Analyze();

            std::cout << "Analyzing: " << argv[1] << "\n";
            std::cout << "Found " << reports.size() << " global references\n\n";

            for (const auto& r : reports) {
                std::cout << "GLOBAL 0x" << std::hex << r.global_va << '\n';
                for (const auto& [rel, st] : r.per_offset) {
                    auto inferred_type = BinA::GlobalCallAnalyzer::InferTypeFromStats(st);
                    // Display signed offset properly
                    if (rel < 0) {
                        std::cout << "  [-0x" << std::hex << -rel << "]  ";
                    } else {
                        std::cout << "  [+0x" << std::hex << rel << "]  ";
                    }
                    std::cout << "type=" << BinA::GlobalCallAnalyzer::TypeToString(inferred_type)
                              << "  calls="  << st.call_hits
                              << "  loads=" << st.load_hits
                              << "  stores="<< st.store_hits;
                    
                    // Show size histogram if multiple sizes detected
                    if (st.type_info.size_histogram.size() > 1) {
                        std::cout << "  sizes={";
                        bool first = true;
                        for (const auto& [size, count] : st.type_info.size_histogram) {
                            if (!first) std::cout << ", ";
                            std::cout << size << "B:" << count;
                            first = false;
                        }
                        std::cout << "}";
                    }
                    std::cout << '\n';
                    
                    // Display nested accesses with tree-like visualization
                    if (!st.nested_accesses.empty()) {
                        // Define recursive lambda to display nested accesses
                        std::function<void(const std::unordered_map<int64_t, BinA::NestedAccess>&, 
                                           const std::string&, bool)> displayNested;
                        displayNested = [&](const std::unordered_map<int64_t, BinA::NestedAccess>& nestedMap, 
                                            const std::string& prefix, bool isLast) {
                            size_t idx = 0;
                            for (const auto& [nrel, nst] : nestedMap) {
                                bool lastItem = (++idx == nestedMap.size());
                                
                                // Tree visualization
                                std::cout << prefix;
                                if (isLast) {
                                    std::cout << "    ";
                                } else {
                                    std::cout << "│   ";
                                }
                                std::cout << (lastItem ? "└── " : "├── ");
                                
                                // Display nested offset
                                if (nrel < 0) {
                                    std::cout << "[-0x" << std::hex << -nrel << "] ";
                                } else {
                                    std::cout << "[+0x" << std::hex << nrel << "] ";
                                }
                                
                                // Display type and access stats
                                std::cout << "type=" << BinA::GlobalCallAnalyzer::TypeToString(
                                                BinA::GlobalCallAnalyzer::InferTypeFromStats(nst))
                                          << " -> ";
                                
                                if (nst.call_hits > 0) {
                                    std::cout << "calls=" << std::dec << nst.call_hits << " ";
                                }
                                if (nst.load_hits > 0) {
                                    std::cout << "loads=" << std::dec << nst.load_hits << " ";
                                }
                                if (nst.store_hits > 0) {
                                    std::cout << "stores=" << std::dec << nst.store_hits << " ";
                                }
                                
                                // Show pattern frequency
                                size_t totalAccesses = nst.call_hits + nst.load_hits + nst.store_hits;
                                std::cout << "(" << std::dec << totalAccesses << " total accesses)";
                                std::cout << '\n';
                                
                                // Recursively display deeper nests if they exist
                                if (!nst.nested_accesses.empty()) {
                                    std::string newPrefix = prefix + (isLast ? "    " : "│   ");
                                    displayNested(nst.nested_accesses, newPrefix, lastItem);
                                }
                            }
                        };
                        
                        // Start displaying nested accesses
                        displayNested(st.nested_accesses, "  ", false);
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error analyzing file: " << e.what() << "\n";
            return 1;
        }
    }
    
    return 0;
}

