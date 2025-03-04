/* SystemScript: Advanced Low-Level Programming Language
 * Version 1.0
 * 
 * A comprehensive systems programming language designed for:
 * - Low-level hardware manipulation
 * - High-performance system programming
 * - Full system control and exploitation
 */

#ifndef SYSTEMSCRIPT_H
#define SYSTEMSCRIPT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Language Core Structures
typedef enum {
    TYPE_VOID,       // Void type
    TYPE_INT8,       // 8-bit signed integer
    TYPE_UINT8,      // 8-bit unsigned integer
    TYPE_INT16,      // 16-bit signed integer
    TYPE_UINT16,     // 16-bit unsigned integer
    TYPE_INT32,      // 32-bit signed integer
    TYPE_UINT32,     // 32-bit unsigned integer
    TYPE_INT64,      // 64-bit signed integer
    TYPE_UINT64,     // 64-bit unsigned integer
    TYPE_FLOAT,      // 32-bit floating point
    TYPE_DOUBLE,     // 64-bit floating point
    TYPE_POINTER,    // Generic pointer
    TYPE_ARRAY,      // Array type
    TYPE_STRUCT,     // Struct type
    TYPE_UNION,      // Union type
    TYPE_FUNCTION    // Function pointer
} SystemScriptType;

// Advanced Memory Management
typedef struct {
    void* base_address;     // Base memory address
    size_t size;            // Allocated memory size
    SystemScriptType type;  // Memory region type
    bool is_executable;     // Executable memory flag
    bool is_mapped;         // Memory-mapped device flag
} MemoryRegion;

// Advanced Type System
typedef struct {
    char* name;             // Type name
    size_t size;            // Type size in bytes
    SystemScriptType base_type;  // Base type
    void* type_info;        // Additional type information
} TypeDefinition;

// Hardware Abstraction Layer
typedef struct {
    uint64_t port;          // Hardware port number
    uint64_t base_address;  // Memory-mapped base address
    size_t size;            // Size of memory-mapped region
    void* device_handle;    // Device-specific handle
} HardwareDevice;

// Network Interface Structure
typedef struct {
    char* interface_name;   // Network interface name
    uint8_t mac_address[6]; // MAC address
    void* raw_socket;       // Raw socket handle
} NetworkInterface;

// Advanced Language Features
typedef struct {
    // JIT Compilation Context
    void* jit_context;
    
    // Code Injection Context
    void* code_injection_context;
    
    // Security Context
    bool is_privileged;
    uint64_t security_level;
} SystemScriptRuntime;

// Core Language Operations
typedef enum {
    // Basic Memory Operations
    OP_MEMORY_ALLOCATE,     // Allocate memory
    OP_MEMORY_FREE,         // Free memory
    OP_MEMORY_MAP,          // Memory-map device
    OP_MEMORY_PROTECT,      // Change memory protection
    
    // Hardware Operations
    OP_PORT_READ,           // Read from I/O port
    OP_PORT_WRITE,          // Write to I/O port
    OP_REGISTER_ACCESS,     // Access CPU registers
    
    // System Operations
    OP_SYSCALL,             // Execute system call
    OP_PROCESS_CREATE,      // Create process
    OP_PROCESS_INJECT,      // Inject code into process
    
    // Network Operations
    OP_NETWORK_SEND,        // Send network packet
    OP_NETWORK_RECEIVE,     // Receive network packet
    OP_NETWORK_INTERFACE,   // Network interface control
    
    // Advanced Operations
    OP_JIT_COMPILE,         // Just-In-Time compilation
    OP_CODE_INJECT,         // Code injection
    OP_DEBUG_TRACE          // Debugging trace
} SystemScriptOperation;

// Error Handling
typedef enum {
    ERROR_NONE,
    ERROR_MEMORY_ALLOCATION,
    ERROR_INVALID_ACCESS,
    ERROR_PERMISSION_DENIED,
    ERROR_HARDWARE_ERROR,
    ERROR_NETWORK_ERROR,
    ERROR_RUNTIME_ERROR
} SystemScriptError;

// Main Language Interpreter Structure
typedef struct {
    // Memory Management
    MemoryRegion* memory_regions;
    size_t memory_region_count;
    
    // Type System
    TypeDefinition* type_definitions;
    size_t type_definition_count;
    
    // Hardware Devices
    HardwareDevice* devices;
    size_t device_count;
    
    // Network Interfaces
    NetworkInterface* network_interfaces;
    size_t network_interface_count;
    
    // Runtime Context
    SystemScriptRuntime runtime;
    
    // Error Handling
    SystemScriptError last_error;
} SystemScriptInterpreter;

// Function Prototypes for Core Operations
SystemScriptInterpreter* systemscript_init();
void systemscript_destroy(SystemScriptInterpreter* interpreter);

// Memory Management
void* systemscript_allocate(SystemScriptInterpreter* interpreter, 
                            size_t size, 
                            SystemScriptType type);
bool systemscript_free(SystemScriptInterpreter* interpreter, void* ptr);
bool systemscript_map_device(SystemScriptInterpreter* interpreter, 
                             uint64_t base_address, 
                             size_t size);

// Hardware Interaction
uint64_t systemscript_port_read(SystemScriptInterpreter* interpreter, 
                                uint64_t port);
bool systemscript_port_write(SystemScriptInterpreter* interpreter, 
                             uint64_t port, 
                             uint64_t value);

// System-Level Operations
bool systemscript_syscall(SystemScriptInterpreter* interpreter, 
                          uint64_t syscall_number, 
                          void* args);
bool systemscript_process_inject(SystemScriptInterpreter* interpreter, 
                                 pid_t pid, 
                                 void* code, 
                                 size_t code_size);

// Network Operations
bool systemscript_network_send(SystemScriptInterpreter* interpreter, 
                               const char* interface, 
                               uint8_t* packet, 
                               size_t packet_size);

// Advanced Features
void* systemscript_jit_compile(SystemScriptInterpreter* interpreter, 
                               const char* code);
bool systemscript_debug_trace(SystemScriptInterpreter* interpreter, 
                              SystemScriptOperation op);

// Error Handling
SystemScriptError systemscript_get_last_error(SystemScriptInterpreter* interpreter);
const char* systemscript_error_string(SystemScriptError error);

#endif // SYSTEMSCRIPT_H
