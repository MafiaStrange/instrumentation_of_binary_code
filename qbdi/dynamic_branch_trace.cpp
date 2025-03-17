#include <QBDI.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <elf.h> // For ELF parsing

// Callback function to log branch instructions
QBDI::VMAction logBranch(QBDI::VMInstanceRef vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    const QBDI::InstAnalysis *inst = vm->getInstAnalysis();

    if (inst == nullptr) {
        return QBDI::CONTINUE;
    }

    if (inst->isBranch) {  // Check if instruction is a branch
        std::cout << "Branch from 0x" << std::hex << gprState->pc << std::endl;
    }

    return QBDI::CONTINUE;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target_binary>" << std::endl;
        return 1;
    }

    // Create a QBDI VM instance
    QBDI::VM vm;
    QBDI::GPRState *state = vm.getGPRState();

    // Allocate a virtual stack
    void *fakestack = QBDI::alignedAlloc(0x100000, 16);
    state->sp = (QBDI::rword)fakestack + 0x100000; // Set stack pointer manually

    // Load the ELF file to find the entry point
    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        std::cerr << "Failed to open file." << std::endl;
        return 1;
    }

    Elf64_Ehdr elfHeader;
    if (fread(&elfHeader, sizeof(Elf64_Ehdr), 1, file) != 1) {
        std::cerr << "Failed to read ELF header." << std::endl;
        fclose(file);
        return 1;
    }

    // Set the entry point to the target binary
    state->pc = elfHeader.e_entry;

    // Register the callback for instruction analysis
    vm.addCodeCB(QBDI::PREINST, logBranch, nullptr);

    // Start execution
    bool success = vm.run(state->pc, state->pc + 0x1000);
    if (!success) {
        std::cerr << "Failed to run the binary." << std::endl;
    }

    // Free the virtual stack
    QBDI::alignedFree(fakestack);

    fclose(file);
    return 0;
}
