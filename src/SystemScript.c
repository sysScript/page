// A simple interpretor for this language.
// Includes comments for users to easily read the code and build off of it <3
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <lightning.h>

#define MEMORY_SIZE 1048576  // 1MB memory
#define MAX_LABELS 1024      // Increased label support
#define MAX_STACK_SIZE 4096  // Call stack size
#define MAX_DEVICES 256      // Maximum memory-mapped devices
#define MAX_STRING_LENGTH 256 // Maximum string length for commands

typedef struct {
    uint8_t *memory;         // Dynamic memory allocation
    uint8_t *code_segment;   // For JIT compilation
    uint64_t registers[32];  // General purpose registers
    uint64_t special_regs[16]; // Special purpose registers (IP, FLAGS, etc.)
    
    int memory_pointer;      // Current memory cell pointer
    int instruction_pointer; // Instruction pointer
    
    int labels[MAX_LABELS];  // Jump labels
    char label_names[MAX_LABELS][32]; // Label names
    int label_count;
    
    int call_stack[MAX_STACK_SIZE]; // Function call stack
    int stack_pointer;
    
    void *mapped_devices[MAX_DEVICES]; // Memory-mapped devices
    size_t device_sizes[MAX_DEVICES];  // Sizes of mapped devices
    int mapped_count;
    
    int debug_mode;
    int unsafe_mode;         // Enable unsafe features (e.g., direct execution)
} Interpreter;

// Hardware access functions with safety mechanisms
uint8_t port_read(uint16_t port) {
    #ifdef ENABLE_REAL_HARDWARE
        // Real hardware implementation (requires root/admin)
        #if defined(__linux__)
            int fd = open("/dev/port", O_RDWR);
            if (fd != -1) {
                uint8_t value;
                lseek(fd, port, SEEK_SET);
                read(fd, &value, 1);
                close(fd);
                return value;
            }
        #endif
    #endif
    
    // Simulated mode or fallback
    printf("[SIM] Reading from port 0x%04x\n", port);
    return 0xAA; // Simulated value
}

void port_write(uint16_t port, uint8_t value) {
    #ifdef ENABLE_REAL_HARDWARE
        // Real hardware implementation (requires root/admin)
        #if defined(__linux__)
            int fd = open("/dev/port", O_RDWR);
            if (fd != -1) {
                lseek(fd, port, SEEK_SET);
                write(fd, &value, 1);
                close(fd);
            }
        #endif
    #endif
    
    // Simulated mode or fallback
    printf("[SIM] Writing 0x%02x to port 0x%04x\n", value, port);
}

// GPU manipulation basics
void gpu_command(Interpreter *interpreter, uint32_t command, uint32_t *params, int param_count) {
    #ifdef ENABLE_GPU_ACCESS
        // Direct GPU access implementation
        // Would use platform-specific APIs like:
        // - Linux: DRM/KMS, Vulkan, or OpenGL
    #endif
    
    // Simulated mode
    printf("[GPU] Command: 0x%08x, Params: ", command);
    for (int i = 0; i < param_count; i++) {
        printf("0x%08x ", params[i]);
    }
    printf("\n");
}

// Memory-mapped device registration
int map_device(Interpreter *interpreter, uint64_t physical_addr, size_t size, const char *device_name) {
    if (interpreter->mapped_count >= MAX_DEVICES) {
        printf("Error: Maximum number of mapped devices reached\n");
        return -1;
    }
    
    #ifdef ENABLE_REAL_HARDWARE
        // Real hardware implementation (requires root/admin)
        int fd = open("/dev/mem", O_RDWR | O_SYNC);
        if (fd == -1) {
            perror("Failed to open /dev/mem");
            return -1;
        }
        
        void *mapped = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, physical_addr);
        close(fd);
        
        if (mapped == MAP_FAILED) {
            perror("Failed to map device memory");
            return -1;
        }
        
        interpreter->mapped_devices[interpreter->mapped_count] = mapped;
        interpreter->device_sizes[interpreter->mapped_count] = size;
        return interpreter->mapped_count++;
    #else
        // Simulated mode
        printf("[Device] Mapped %s at physical address 0x%lx (size: %zu bytes)\n", 
               device_name, (unsigned long)physical_addr, size);
        interpreter->mapped_devices[interpreter->mapped_count] = malloc(size);
        memset(interpreter->mapped_devices[interpreter->mapped_count], 0, size);
        interpreter->device_sizes[interpreter->mapped_count] = size;
        return interpreter->mapped_count++;
    #endif
}

// Code injection functionality
void inject_code(Interpreter *interpreter, uint64_t target_addr, uint8_t *code, size_t code_size) {
    #ifdef ENABLE_CODE_INJECTION
        // Real implementation (requires special permissions)
        // Would need to handle memory protection
        void *page_aligned = (void *)(target_addr & ~0xFFF);
        size_t page_size = (code_size + (target_addr & 0xFFF) + 0xFFF) & ~0xFFF;
        
        if (mprotect(page_aligned, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            perror("Failed to change memory protection");
            return;
        }
        
        memcpy((void *)target_addr, code, code_size);
        
        // Restore protection if needed
        mprotect(page_aligned, page_size, PROT_READ | PROT_EXEC);
    #else
        // Simulated mode
        printf("[CodeInject] Injecting %zu bytes at 0x%lx\n", code_size, (unsigned long)target_addr);
        for (size_t i = 0; i < code_size && i < 16; i++) {
            printf("%02x ", code[i]);
        }
        if (code_size > 16) printf("...");
        printf("\n");
    #endif
}

// Network packet crafting and injection
int send_raw_packet(const uint8_t *packet, size_t packet_size, const char *interface) {
    #ifdef ENABLE_NETWORK_RAW
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) {
            perror("Failed to create raw socket");
            return -1;
        }
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr("192.168.1.1"); // Example destination

        if (sendto(sock, packet, packet_size, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
            perror("Failed to send packet");
            close(sock);
            return -1;
        }
        close(sock);
        return 0;
    #else
        // Simulated mode
        printf("[Network] Sending %zu byte packet on %s\n", packet_size, interface);
        printf("Packet: ");
        for (size_t i = 0; i < packet_size && i < 16; i++) {
            printf("%02x ", packet[i]);
        }
        if (packet_size > 16) printf("...");
        printf("\n");
        return 0;
    #endif
}

// JIT compilation of SystemScript to native code
static jit_state_t *_jit;

void jit_compile(Interpreter *interpreter, const char *code, size_t size) {
    #ifdef ENABLE_JIT
        _jit = jit_new_state();
        jit_prolog();
        // Translate SystemScript to native code
        // Example: Add two numbers
        jit_ldi_ui(JIT_R0, 5); // Load 5 into R0
        jit_ldi_ui(JIT_R1, 10); // Load 10 into R1
        jit_addi(JIT_R0, JIT_R0, JIT_R1); // R0 = R0 + R1
        jit_ret(); // Return
        jit_epilog();
        void (*func)() = jit_emit();
        func();
        jit_clear_state();
    #else
        printf("[JIT] Compiling %zu bytes of SystemScript code\n", size);
    #endif
}

// Initialize interpreter with all needed resources
Interpreter* interpreter_init() {
    Interpreter *interpreter = (Interpreter*)malloc(sizeof(Interpreter));
    if (!interpreter) return NULL;
    
    memset(interpreter, 0, sizeof(Interpreter));
    
    // Allocate main memory
    interpreter->memory = (uint8_t*)malloc(MEMORY_SIZE);
    if (!interpreter->memory) {
        free(interpreter);
        return NULL;
    }
    memset(interpreter->memory, 0, MEMORY_SIZE);
    
    // Initialize other fields
    interpreter->memory_pointer = 0;
    interpreter->instruction_pointer = 0;
    interpreter->stack_pointer = 0;
    interpreter->debug_mode = 0;
    interpreter->unsafe_mode = 0;
    interpreter->label_count = 0;
    interpreter->mapped_count = 0;
    
    return interpreter;
}

void interpreter_cleanup(Interpreter *interpreter) {
    if (!interpreter) return;
    
    // Free main memory
    if (interpreter->memory) {
        free(interpreter->memory);
    }
    
    // Free JIT code segment if allocated
    if (interpreter->code_segment) {
        #ifdef ENABLE_JIT
            munmap(interpreter->code_segment, 4096);
        #else
            free(interpreter->code_segment);
        #endif
    }
    
    // Unmap any memory-mapped devices
    for (int i = 0; i < interpreter->mapped_count; i++) {
        #ifdef ENABLE_REAL_HARDWARE
            munmap(interpreter->mapped_devices[i], interpreter->device_sizes[i]);
        #else
            free(interpreter->mapped_devices[i]);
        #endif
    }
    
    free(interpreter);
}

// Parse a number in various formats
uint64_t parse_number(const char *str, int *advance) {
    uint64_t value = 0;
    int i = 0;
    
    // Hex format (0x...)
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        i = 2;
        while ((str[i] >= '0' && str[i] <= '9') || 
               (str[i] >= 'a' && str[i] <= 'f') || 
               (str[i] >= 'A' && str[i] <= 'F')) {
            
            value = value * 16;
            if (str[i] >= '0' && str[i] <= '9') {
                value += str[i] - '0';
            } else if (str[i] >= 'a' && str[i] <= 'f') {
                value += 10 + (str[i] - 'a');
            } else {
                value += 10 + (str[i] - 'A');
            }
            i++;
        }
    }
    // Binary format (0b...)
    else if (str[0] == '0' && (str[1] == 'b' || str[1] == 'B')) {
        i = 2;
        while (str[i] == '0' || str[i] == '1') {
            value = value * 2 + (str[i] - '0');
            i++;
        }
    }
    // Decimal format
    else {
        while (str[i] >= '0' && str[i] <= '9') {
            value = value * 10 + (str[i] - '0');
            i++;
        }
    }
    
    if (advance) *advance = i;
    return value;
}

// Enhanced SystemScript interpreter with extended command set
void systemscript_run(Interpreter *interpreter, const char *code) {
    int i = 0;
    while (code[i] != '\0') {
        char cmd = code[i];
        
        if (interpreter->debug_mode) {
            printf("Command: %c, Pointer: %d, Value: %d\n", 
                   cmd, interpreter->memory_pointer, 
                   interpreter->memory[interpreter->memory_pointer]);
        }
        
        switch (cmd) {
            // Original commands
            case '+':
                interpreter->memory[interpreter->memory_pointer]++;
                break;
            case '-':
                interpreter->memory[interpreter->memory_pointer]--;
                break;
            case '>':
                if (interpreter->memory_pointer < MEMORY_SIZE - 1) {
                    interpreter->memory_pointer++;
                } else {
                    printf("Error: Memory pointer out of bounds\n");
                }
                break;
            case '<':
                if (interpreter->memory_pointer > 0) {
                    interpreter->memory_pointer--;
                } else {
                    printf("Error: Memory pointer out of bounds\n");
                }
                break;
            case '[':
                if (interpreter->memory[interpreter->memory_pointer] == 0) {
                    int depth = 1;
                    while (depth > 0) {
                        i++;
                        if (!code[i]) break;
                        if (code[i] == '[') depth++;
                        if (code[i] == ']') depth--;
                    }
                }
                break;
            case ']':
                if (interpreter->memory[interpreter->memory_pointer] != 0) {
                    int depth = 1;
                    while (depth > 0) {
                        i--;
                        if (i < 0) break;
                        if (code[i] == ']') depth++;
                        if (code[i] == '[') depth--;
                    }
                }
                break;
            case '.':
                putchar(interpreter->memory[interpreter->memory_pointer]);
                break;
            case ',':
                interpreter->memory[interpreter->memory_pointer] = getchar();
                break;
                
            // Extended commands
            case '@': {
                i++;
                int advance = 0;
                uint64_t addr = parse_number(&code[i], &advance);
                i += advance - 1; // -1 because of the i++ at the end of the loop
                interpreter->memory_pointer = addr % MEMORY_SIZE;
                break;
            }
            
            case '#': { // Hardware port access
                i++;
                int advance = 0;
                uint16_t port = parse_number(&code[i], &advance);
                i += advance;
                
                if (code[i] == '=') { // Write to port
                    i++;
                    advance = 0;
                    uint8_t value = parse_number(&code[i], &advance);
                    i += advance - 1;
                    port_write(port, value);
                } else { // Read from port
                    i--; // Adjust for the i++ at the end of the loop
                    interpreter->memory[interpreter->memory_pointer] = port_read(port);
                }
                break;
            }
            
            case '$': { // CPU register access
                i++;
                char reg_name[16];
                int j = 0;
                // Parse register name
                while ((code[i] >= 'a' && code[i] <= 'z') || 
                       (code[i] >= 'A' && code[i] <= 'Z') ||
                       (code[i] >= '0' && code[i] <= '9')) {
                    
                    reg_name[j++] = code[i++];
                    if (j >= 15) break;
                }
                reg_name[j] = '\0';
                
                // Determine register index
                int reg_idx = -1;
                if (strcmp(reg_name, "eax") == 0) reg_idx = 0;
                else if (strcmp(reg_name, "ebx") == 0) reg_idx = 1;
                else if (strcmp(reg_name, "ecx") == 0) reg_idx = 2;
                else if (strcmp(reg_name, "edx") == 0) reg_idx = 3;
                else if (strcmp(reg_name, "esi") == 0) reg_idx = 4;
                else if (strcmp(reg_name, "edi") == 0) reg_idx = 5;
                else if (strcmp(reg_name, "ebp") == 0) reg_idx = 6;
                else if (strcmp(reg_name, "esp") == 0) reg_idx = 7;
                // ... add more registers as needed
                
                if (reg_idx != -1) {
                    if (code[i] == '=') { // Write to register
                        i++;
                        int advance = 0;
                        uint64_t value = parse_number(&code[i], &advance);
                        i += advance - 1;
                        interpreter->registers[reg_idx] = value;
                    } else { // Read from register
                        i--; // Adjust for the i++ at the end of the loop
                        interpreter->memory[interpreter->memory_pointer] = 
                            interpreter->registers[reg_idx] & 0xFF;
                    }
                } else {
                    printf("Unknown register: %s\n", reg_name);
                    i--; // Adjust for the i++ at the end of the loop
                }
                break;
            }
            
            case '!': { // System call/interrupt
                i++;
                int advance = 0;
                uint32_t syscall_num = parse_number(&code[i], &advance);
                i += advance - 1;
                
                // Simulated system call
                printf("[SYS] System call %u with args: ", syscall_num);
                for (int arg = 0; arg < 6; arg++) {
                    printf("0x%lx ", interpreter->registers[arg]);
                }
                printf("\n");
                
                // Could dispatch to actual system calls here
                break;
            }
            
            case '%': { // Memory-mapped I/O
                i++;
                int advance = 0;
                uint64_t addr = parse_number(&code[i], &advance);
                i += advance;
                
                // Find the right device mapping
                int device_idx = -1;
                uint64_t offset = 0;
                for (int d = 0; d < interpreter->mapped_count; d++) {
                    // In a real implementation, we'd check if addr falls within the mapped range
                    // Here we just use the device index as a handle
                    if (d == (addr >> 24)) {
                        device_idx = d;
                        offset = addr & 0xFFFFFF;
                        break;
                    }
                }
                
                if (device_idx != -1) {
                    if (code[i] == '=') { // Write to mapped memory
                        i++;
                        advance = 0;
                        uint8_t value = parse_number(&code[i], &advance);
                        i += advance - 1;
                        
                        #ifdef ENABLE_REAL_HARDWARE
                            ((uint8_t*)interpreter->mapped_devices[device_idx])[offset] = value;
                        #else
                            printf("[MMIO] Write 0x%02x to device %d at offset 0x%lx\n", 
                                   value, device_idx, (unsigned long)offset);
                            if (interpreter->mapped_devices[device_idx]) {
                                ((uint8_t*)interpreter->mapped_devices[device_idx])[offset % 4096] = value;
                            }
                        #endif
                    } else { // Read from mapped memory
                        i--; // Adjust for the i++ at the end of the loop
                        
                        #ifdef ENABLE_REAL_HARDWARE
                            interpreter->memory[interpreter->memory_pointer] = 
                                ((uint8_t*)interpreter->mapped_devices[device_idx])[offset];
                        #else
                            printf("[MMIO] Read from device %d at offset 0x%lx\n", 
                                   device_idx, (unsigned long)offset);
                            if (interpreter->mapped_devices[device_idx]) {
                                interpreter->memory[interpreter->memory_pointer] = 
                                    ((uint8_t*)interpreter->mapped_devices[device_idx])[offset % 4096];
                            } else {
                                interpreter->memory[interpreter->memory_pointer] = 0xAA; // Simulated value
                            }
                        #endif
                    }
                } else {
                    printf("No device mapping found for address 0x%lx\n", (unsigned long)addr);
                    i--; // Adjust for the i++ at the end of the loop
                }
                break;
            }
            
            case '*': { // Memory dereference
                uint64_t addr = interpreter->memory[interpreter->memory_pointer];
                if (addr < MEMORY_SIZE) {
                    interpreter->memory_pointer = addr;
                } else {
                    printf("Invalid memory address dereference: 0x%lx\n", 
                           (unsigned long)addr);
                }
                break;
            }
            
            case ':': { // Define label
                i++;
                char label[32];
                int j = 0;
                while ((code[i] >= 'a' && code[i] <= 'z') || 
                       (code[i] >= 'A' && code[i] <= 'Z') ||
                       (code[i] >= '0' && code[i] <= '9') ||
                       code[i] == '_') {
                    
                    label[j++] = code[i++];
                    if (j >= 31) break;
                }
                label[j] = '\0';
                
                if (interpreter->label_count < MAX_LABELS) {
                    strcpy(interpreter->label_names[interpreter->label_count], label);
                    interpreter->labels[interpreter->label_count] = i;
                    interpreter->label_count++;
                }
                
                i--; // Adjust for the i++ at the end of the loop
                break;
            }
            
            case ';': { // Jump to label
                i++;
                char label[32];
                int j = 0;
                while ((code[i] >= 'a' && code[i] <= 'z') || 
                       (code[i] >= 'A' && code[i] <= 'Z') ||
                       (code[i] >= '0' && code[i] <= '9') ||
                       code[i] == '_') {
                    
                    label[j++] = code[i++];
                    if (j >= 31) break;
                }
                label[j] = '\0';
                
                // Find the label
                for (int l = 0; l < interpreter->label_count; l++) {
                    if (strcmp(interpreter->label_names[l], label) == 0) {
                        i = interpreter->labels[l] - 1; // -1 because of the i++ at the end
                        break;
                    }
                }
                break;
            }
            
            case '=': { // Assign value
                i++;
                int advance = 0;
                uint64_t value = parse_number(&code[i], &advance);
                i += advance - 1;
                interpreter->memory[interpreter->memory_pointer] = value & 0xFF;
                break;
            }
            
            case '&': { // Bitwise AND
                i++;
                int advance = 0;
                uint8_t value = parse_number(&code[i], &advance);
                i += advance - 1;
                interpreter->memory[interpreter->memory_pointer] &= value;
                break;
            }
            
            case '|': { // Bitwise OR
                i++;
                int advance = 0;
                uint8_t value = parse_number(&code[i], &advance);
                i += advance - 1;
                interpreter->memory[interpreter->memory_pointer] |= value;
                break;
            }
            
            case '^': { // Bitwise XOR
                i++;
                int advance = 0;
                uint8_t value = parse_number(&code[i], &advance);
                i += advance - 1;
                interpreter->memory[interpreter->memory_pointer] ^= value;
                break;
            }
            
            case '~': { // Bitwise NOT
                interpreter->memory[interpreter->memory_pointer] = 
                    ~interpreter->memory[interpreter->memory_pointer];
                break;
            }
            
            case '{': { // Function call
                if (interpreter->stack_pointer < MAX_STACK_SIZE) {
                    interpreter->call_stack[interpreter->stack_pointer++] = i;
                }
                break;
            }
            
            case '}': { // Function return
                if (interpreter->stack_pointer > 0) {
                    i = interpreter->call_stack[--interpreter->stack_pointer];
                }
                break;
            }
            
            // NEW COMMANDS
            
            case 'G': { // GPU commands
                if (code[i+1] == '{') {
                    i += 2;
                    
                    uint32_t gpu_cmd = 0;
                    uint32_t params[16];
                    int param_count = 0;
                    
                    // Parse GPU command
                    int advance = 0;
                    gpu_cmd = parse_number(&code[i], &advance);
                    i += advance;
                    
                    // Parse parameters
                    while (code[i] == ',') {
                        i++;
                        advance = 0;
                        if (param_count < 16) {
                            params[param_count++] = parse_number(&code[i], &advance);
                        }
                        i += advance;
                    }
                    
                    // Execute GPU command
                    gpu_command(interpreter, gpu_cmd, params, param_count);
                    
                    // Find closing brace
                    while (code[i] != '}' && code[i] != '\0') i++;
                }
                break;
            }
            
            case 'M': { // Memory mapping
                if (code[i+1] == '{') {
                    i += 2;
                    
                    // Parse physical address
                    int advance = 0;
                    uint64_t phys_addr = parse_number(&code[i], &advance);
                    i += advance;
                    
                    if (code[i] == ',') {
                        i++;
                        // Parse size
                        advance = 0;
                        size_t size = parse_number(&code[i], &advance);
                        i += advance;
                        
                        // Parse device name if present
                        char device_name[32] = "unnamed";
                        if (code[i] == ',') {
                            i++;
                            int j = 0;
                            while (code[i] != '}' && code[i] != '\0' && j < 31) {
                                device_name[j++] = code[i++];
                            }
                            device_name[j] = '\0';
                        }
                        
                        // Map the device
                        int device_id = map_device(interpreter, phys_addr, size, device_name);
                        interpreter->memory[interpreter->memory_pointer] = device_id;
                    }
                    
                    // Find closing brace
                    while (code[i] != '}' && code[i] != '\0') i++;
                }
                break;
            }
            
            case 'I': { // Code injection
                if (code[i+1] == '{') {
                    i += 2;
                    
                    // Parse target address
                    int advance = 0;
                    uint64_t target = parse_number(&code[i], &advance);
                    i += advance;
                    
                    if (code[i] == ',') {
                        i++;
                        
                        // Parse the code bytes
                        uint8_t inject_bytes[256];
                        int byte_count = 0;
                        
                        while (code[i] != '}' && code[i] != '\0' && byte_count < 256) {
                            if ((code[i] >= '0' && code[i] <= '9') ||
                                (code[i] >= 'a' && code[i] <= 'f') ||
                                (code[i] >= 'A' && code[i] <= 'F')) {
                                
                                advance = 0;
                                inject_bytes[byte_count++] = parse_number(&code[i], &advance) & 0xFF;
                                i += advance;
                            } else {
                                i++;
                            }
                        }
                        
                        // Perform the injection
                        inject_code(interpreter, target, inject_bytes, byte_count);
                    }
                    
                    // Find closing brace
                    while (code[i] != '}' && code[i] != '\0') i++;
                }
                break;
            }
            
            case 'N': { // Network packet
                if (code[i+1] == '{') {
                    i += 2;
                    
                    // Parse interface
                    char interface[32] = "eth0"; // Default
                    if ((code[i] >= 'a' && code[i] <= 'z') ||
                        (code[i] >= 'A' && code[i] <= 'Z')) {
                        
                        int j = 0;
                        while (((code[i] >= 'a' && code[i] <= 'z') ||
                               (code[i] >= 'A' && code[i] <= 'Z') ||
                               (code[i] >= '0' && code[i] <= '9') ||
                                code[i] == '_') && j < 31) {
                            
                            interface[j++] = code[i++];
                        }
                        interface[j] = '\0';
                    }
                    
                    if (code[i] == ',') {
                        i++;
                        
                        // Parse packet data
                        uint8_t packet[1500]; // Max Ethernet frame
                        int packet_size = 0;
                        
                        while (code[i] != '}' && code[i] != '\0' && packet_size < 1500) {
                            if ((code[i] >= '0' && code[i] <= '9') ||
                                (code[i] >= 'a' && code[i] <= 'f') ||
                                (code[i] >= 'A' && code[i] <= 'F')) {
                                
                                int advance = 0;
                                packet[packet_size++] = parse_number(&code[i], &advance) & 0xFF;
                                i += advance;
                            } else {
                                i++;
                            }
                        }
                        
                        // Send the packet
                        send_raw_packet(packet, packet_size, interface);
                    }
                    
                    // Find closing brace
                    while (code[i] != '}' && code[i] != '\0') i++;
                }
                break;
            }
            
            case 'J': { // JIT compile
                if (code[i+1] == '{') {
                    i += 2;
                    
                    char jit_code[4096];
                    int code_len = 0;
                    
                    // Copy the code segment
                    while (code[i] != '}' && code[i] != '\0' && code_len < 4095) {
                        jit_code[code_len++] = code[i++];
                    }
                    jit_code[code_len] = '\0';
                    
                    // Compile and potentially execute
                    jit_compile(interpreter, jit_code, code_len);
                    
                    // Find closing brace if not found yet
                    while (code[i] != '}' && code[i] != '\0') i++;
                }
                break;
            }
            
            case 'D': { // Debug command
                if (code[i+1] == '1') {
                    interpreter->debug_mode = 1;
                    i++;
                } else if (code[i+1] == '0') {
                    interpreter->debug_mode = 0;
                    i++;
                } else {
                    // Toggle debug mode
                    interpreter->debug_mode = !interpreter->debug_mode;
                }
                break;
            }
            
            case 'X': { // Execute machine code at current pointer
                #ifdef ENABLE_DIRECT_EXECUTION
                    if (interpreter->unsafe_mode) {
                        void *page_aligned = (void *)(interpreter->memory_pointer & ~0xFFF);
                        size_t page_size = 4096;
                        if (mprotect(page_aligned, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                            perror("Failed to change memory protection");
                            break;
                        }
                        typedef void (*CodeFunc)(void);
                        CodeFunc func = (CodeFunc)&interpreter->memory[interpreter->memory_pointer];
                        func();
                        mprotect(page_aligned, page_size, PROT_READ | PROT_WRITE);
                    } else {
                        printf("Error: Direct execution is disabled for safety\n");
                    }
                #else
                    printf("Error: Direct execution is not supported\n");
                #endif
                break;
            }
            
            case 'P': { // Process creation and manipulation
                i++;
                if (code[i] == 'C') { // Create process
                    i++;
                    // Extract command to execute
                    char cmd[256];
                    int j = 0;
                    
                    // Skip whitespace
                    while (code[i] == ' ' || code[i] == '\t') i++;
                    
                    // Extract command string
                    while (code[i] != '\0' && code[i] != '\n' && j < 255) {
                        cmd[j++] = code[i++];
                    }
                    cmd[j] = '\0';
                    
                    // Execute process
                    printf("[PROC] Executing command: %s\n", cmd);
                    #ifdef ENABLE_PROCESS_EXECUTION
                        pid_t pid = fork();
                        if (pid == 0) {
                            execlp(cmd, cmd, NULL);
                            exit(0);
                        } else if (pid > 0) {
                            wait(NULL);
                        } else {
                            perror("Failed to fork");
                        }
                    #endif
                    
                    i--; // Adjust for the i++ at the end of the loop
                }
                else if (code[i] == 'I') { // Process injection
                    i++;
                    int advance = 0;
                    uint32_t pid = parse_number(&code[i], &advance);
                    i += advance;
                    
                    printf("[PROC] Process injection into PID %u\n", pid);
                    #ifdef ENABLE_PROCESS_INJECTION
                        // Platform-specific process injection code would go here
                        // This requires advanced permissions and techniques
                    #endif
                    
                    i--; // Adjust for the i++ at the end of the loop
                }
                break;
            }
            
            case 'E': { // Extended memory operations
                i++;
                if (code[i] == 'A') { // Allocate memory
                    i++;
                    int advance = 0;
                    size_t size = parse_number(&code[i], &advance);
                    i += advance;
                    
                    void *mem = malloc(size);
                    printf("[MEM] Allocated %zu bytes at %p\n", size, mem);
                    
                    // Store the pointer in 8 consecutive bytes
                    uint64_t ptr_val = (uint64_t)mem;
                    for (int b = 0; b < 8; b++) {
                        if (interpreter->memory_pointer + b < MEMORY_SIZE) {
                            interpreter->memory[interpreter->memory_pointer + b] = 
                                (ptr_val >> (b * 8)) & 0xFF;
                        }
                    }
                    
                    i--; // Adjust for the i++ at the end of the loop
                }
                else if (code[i] == 'F') { // Free memory
                    // Read pointer from 8 consecutive bytes
                    uint64_t ptr_val = 0;
                    for (int b = 0; b < 8; b++) {
                        if (interpreter->memory_pointer + b < MEMORY_SIZE) {
                            ptr_val |= (uint64_t)interpreter->memory[interpreter->memory_pointer + b] << (b * 8);
                        }
                    }
                    
                    void *mem = (void*)ptr_val;
                    printf("[MEM] Freeing memory at %p\n", mem);
                    free(mem);
                    
                    i++; // Skip the 'F'
                }
                break;
            }
            
            case 'S': { // String operations
                i++;
                if (code[i] == 'C') { // Copy string
                    i++;
                    // Extract string to copy
                    char str[256];
                    int j = 0;
                    
                    if (code[i] == '"') {
                        i++; // Skip opening quote
                        while (code[i] != '"' && code[i] != '\0' && j < 255) {
                            if (code[i] == '\\' && code[i+1] != '\0') {
                                // Handle escape sequences
                                i++;
                                switch (code[i]) {
                                    case 'n': str[j++] = '\n'; break;
                                    case 't': str[j++] = '\t'; break;
                                    case 'r': str[j++] = '\r'; break;
                                    case '0': str[j++] = '\0'; break;
                                    default: str[j++] = code[i]; break;
                                }
                            } else {
                                str[j++] = code[i];
                            }
                            i++;
                        }
                        if (code[i] == '"') i++; // Skip closing quote
                    }
                    str[j] = '\0';
                    
                    // Copy to memory at current pointer
                    for (j = 0; str[j] != '\0' && interpreter->memory_pointer + j < MEMORY_SIZE; j++) {
                        interpreter->memory[interpreter->memory_pointer + j] = str[j];
                    }
                    // Add null terminator
                    if (interpreter->memory_pointer + j < MEMORY_SIZE) {
                        interpreter->memory[interpreter->memory_pointer + j] = '\0';
                    }
                    
                    i--; // Adjust for the i++ at the end of the loop
                }
                else if (code[i] == 'P') { // Print string at pointer
                    i++;
                    int j = 0;
                    while (interpreter->memory_pointer + j < MEMORY_SIZE && 
                           interpreter->memory[interpreter->memory_pointer + j] != '\0') {
                        putchar(interpreter->memory[interpreter->memory_pointer + j]);
                        j++;
                    }
                }
                break;
            }
            
            // Add more advanced commands here
            
            default:
                // Ignore whitespace and unknown commands
                if (cmd != ' ' && cmd != '\t' && cmd != '\n' && cmd != '\r') {
                    if (interpreter->debug_mode) {
                        printf("Unknown command: %c (0x%02x) at position %d\n", 
                               cmd, (unsigned char)cmd, i);
                    }
                }
                break;
        }
        
        i++;
    }
}

void execute_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open script file");
        return;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *code = malloc(file_size + 1);
    if (!code) {
        perror("Failed to allocate memory for code");
        fclose(file);
        return;
    }
    
    size_t read_size = fread(code, 1, file_size, file);
    code[read_size] = '\0';
    fclose(file);

    Interpreter *interpreter = interpreter_init();
    if (interpreter) {
        systemscript_run(interpreter, code);
        interpreter_cleanup(interpreter);
    }

    free(code);
}

void repl() {
    Interpreter *interpreter = interpreter_init();
    if (!interpreter) {
        fprintf(stderr, "Failed to initialize interpreter\n");
        return;
    }
    
    char input[4096];
    
    printf("SystemScript REPL v2.0 (Type 'exit' to quit)\n");
    printf("Warning: Some commands may require elevated privileges for real hardware access\n");
    
    while (1) {
        printf(">>> ");
        if (!fgets(input, sizeof(input), stdin)) break;
        
        // Remove newline
        size_t len = strlen(input);
        if (len > 0 && input[len-1] == '\n') {
            input[len-1] = '\0';
        }
        
        if (strcmp(input, "exit") == 0) break;
        
        // Special REPL commands
        if (strcmp(input, "help") == 0) {
            printf("SystemScript Commands:\n");
            printf("  + - < > [ ] . ,     Basic operations\n");
            printf("  @addr               Set memory pointer\n");
            printf("  #port[=value]       Read/write hardware port\n");
            printf("  $reg[=value]        Access CPU register\n");
            printf("  !syscall            Execute system call\n");
            printf("  %%addr[=value]       Access memory-mapped I/O\n");
            printf("  *                   Dereference pointer\n");
            printf("  :label              Define label\n");
            printf("  ;label              Jump to label\n");
            printf("  =value              Set memory value\n");
            printf("  & | ^ ~             Bitwise operations\n");
            printf("  { }                 Function call/return\n");
            printf("  G{cmd,param,...}    GPU command\n");
            printf("  M{addr,size,name}   Map device\n");
            printf("  I{addr,bytes...}    Inject code\n");
            printf("  N{iface,packet...}  Send network packet\n");
            printf("  J{code...}          JIT compile code\n");
            printf("  D[0|1]              Debug mode\n");
            printf("  X                   Execute at pointer\n");
            printf("  PC cmd              Execute process\n");
            printf("  PI pid              Process injection\n");
            printf("  EA size             Allocate memory\n");
            printf("  EF                  Free memory\n");
            printf("  SC\"string\"          Copy string to memory\n");
            printf("  SP                  Print string at pointer\n");
            continue;
        }
        
        if (strcmp(input, "memory") == 0) {
            // Dump memory around current pointer
            int start = interpreter->memory_pointer - 16;
            if (start < 0) start = 0;
            
            printf("Memory dump (around pointer %d):\n", interpreter->memory_pointer);
            for (int i = 0; i < 8; i++) {
                printf("%08x: ", start + i * 16);
                for (int j = 0; j < 16; j++) {
                    int addr = start + i * 16 + j;
                    if (addr < MEMORY_SIZE) {
                        printf("%02x ", interpreter->memory[addr]);
                        if (addr == interpreter->memory_pointer) {
                            printf("* ");
                        } else {
                            printf("  ");
                        }
                    }
                }
                printf("  |  ");
                for (int j = 0; j < 16; j++) {
                    int addr = start + i * 16 + j;
                    if (addr < MEMORY_SIZE) {
                        char c = interpreter->memory[addr];
                        printf("%c", (c >= 32 && c <= 126) ? c : '.');
                    }
                }
                printf("\n");
            }
            continue;
        }
        
        if (strcmp(input, "registers") == 0) {
            printf("CPU Registers:\n");
            printf("  EAX: 0x%016lx   EBX: 0x%016lx\n", 
                   interpreter->registers[0], interpreter->registers[1]);
            printf("  ECX: 0x%016lx   EDX: 0x%016lx\n", 
                   interpreter->registers[2], interpreter->registers[3]);
            printf("  ESI: 0x%016lx   EDI: 0x%016lx\n", 
                   interpreter->registers[4], interpreter->registers[5]);
            printf("  EBP: 0x%016lx   ESP: 0x%016lx\n", 
                   interpreter->registers[6], interpreter->registers[7]);
            continue;
        }
        
        // Normal command execution
        systemscript_run(interpreter, input);
        printf("\n");
    }
    
    interpreter_cleanup(interpreter);
}

int main(int argc, char *argv[]) {
    // Install signal handlers for safety
    signal(SIGSEGV, SIG_IGN);
    
    printf("SystemScript Interpreter v2.0\n");
    printf("Low-level programming language with direct hardware access capabilities\n\n");
    
    if (argc == 1) {
        // No arguments: Start REPL
        repl();
    } else if (argc == 2) {
        // One argument: Execute .script file
        execute_file(argv[1]);
    } else {
        printf("Usage: %s [filename.script]\n", argv[0]);
        return 1;
    }
    
    return 0;
}
