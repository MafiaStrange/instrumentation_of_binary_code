#include <QBDI.h>
#include <iostream>
#include <fstream>
#include <elf.h>

// Global file stream for logging branch instructions
std::ofstream branchLog("branch_log.txt");

// Callback function to log branch instructions
QBDI::VMAction logBranch(QBDI::VM* vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    const QBDI::InstAnalysis* inst = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION);

    if (inst != nullptr && inst->isBranch) {
        QBDI::rword src = gprState->pc;
        QBDI::rword dest = gprState->pc + inst->instSize; // Approximate destination

        branchLog << std::hex << src << "," << dest << "\n";
        std::cout << "Branch from 0x" << std::hex << src << " to 0x" << dest << "\n";
    }

    return QBDI::VMAction::CONTINUE;
}


int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }

    // Load the ELF file to find the entry point
    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        std::cerr << "Failed to open file." << std::endl;
        return 1;
    }

    // Initialize QBDI VM
    QBDI::VM vm;

    // Get initial GPR state
    QBDI::GPRState *state = vm.getGPRState();

    // Finding the start address
    Elf64_Ehdr elfHeader;
    if (fread(&elfHeader, sizeof(Elf64_Ehdr), 1, file) != 1) {
        std::cerr << "Failed to read ELF header." << std::endl;
        fclose(file);
        return 1;
    }

    // Set the entry point to the target binary
    state->pc = elfHeader.e_entry;

    // Setting the Start Address
    QBDI::rword startAddress = state->pc; 

    // Load instrumented module from address 
    vm.addInstrumentedRange(startAddress, startAddress + 0x1000);

    // Register callback for pre-instruction events
    uint32_t cid = vm.addCodeCB(QBDI::PREINST, logBranch, nullptr);
    if (cid == QBDI::INVALID_EVENTID) {
        std::cerr << "Failed to register callback.\n";
        return 1;
    }

    // Setup fake stack
    uint8_t* fakestack;
    bool res = QBDI::allocateVirtualStack(state, 0x100000, &fakestack);
    if (!res) {
        std::cerr << "Failed to allocate memory for fake stack.\n";
        return 1;
    }

    std::cout << "Starting execution...\n";

    // Run the VM
    bool result = vm.run(startAddress, startAddress + 0x1000);
    if (!result) {
        std::cerr << "Execution stopped unexpectedly.\n";
    }

    // Clean up
    QBDI::alignedFree(fakestack);
    branchLog.close();

    return 0;
}
