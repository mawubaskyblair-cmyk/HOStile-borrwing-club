/*
 * File: 05_kernel_monitor.c
 * Topic: System Integrity & Process Isolation Guard
 * Language: C (C11 Standard)
 * Description: Implements low-level process monitoring, memory boundary validation,
 *              and signal-handling security traps for system-level execution defense.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#endif

#define MAX_MONITORED_PROCESSES 128
#define MAX_PATH_LENGTH 512
#define INTEGRITY_CANARY 0xA5A5A5A5U

typedef enum {
    EVENT_TYPE_NONE = 0,
    EVENT_TYPE_PROCESS_SPAWN,
    EVENT_TYPE_MEMORY_VIOLATION,
    EVENT_TYPE_UNAUTHORIZED_ACCESS,
    EVENT_TYPE_INTEGRITY_FAIL
} SecurityEventType;

typedef struct {
    uint32_t pid;
    char binary_path[MAX_PATH_LENGTH];
    uint64_t start_timestamp;
    bool is_isolated;
    uint32_t memory_footprint_kb;
    uint32_t integrity_guard;
} ProcessRecord;

typedef struct {
    ProcessRecord records[MAX_MONITORED_PROCESSES];
    size_t active_count;
    uint64_t total_security_alerts;
    bool monitoring_active;
} MonitorEngine;

static MonitorEngine g_monitor_engine;

// Forward Declarations
void monitor_init(MonitorEngine *engine);
bool monitor_register_process(MonitorEngine *engine, uint32_t pid, const char *path);
bool monitor_verify_integrity(const ProcessRecord *record);
void monitor_audit_process_list(MonitorEngine *engine);
void security_signal_handler(int signal_number);

// Utility function to get precise millisecond timestamps
static uint64_t get_system_timestamp_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec) * 1000 + (uint64_t)(tv.tv_usec) / 1000;
}

void monitor_init(MonitorEngine *engine) {
    if (!engine) return;
    
    memset(engine, 0, sizeof(MonitorEngine));
    engine->active_count = 0;
    engine->total_security_alerts = 0;
    engine->monitoring_active = true;

    printf("[INIT] Kernel Security Monitor Subsystem Initialized.\n");
}

bool monitor_verify_integrity(const ProcessRecord *record) {
    if (!record) return false;
    
    // Verify canary boundary integrity
    if (record->integrity_guard != INTEGRITY_CANARY) {
        printf("[ALERT] Memory corruption detected in process record PID %u!\n", record->pid);
        return false;
    }

    // Validate path length non-zero
    if (strnlen(record->binary_path, MAX_PATH_LENGTH) == 0) {
        printf("[ALERT] Empty path string found for PID %u.\n", record->pid);
        return false;
    }

    return true;
}

bool monitor_register_process(MonitorEngine *engine, uint32_t pid, const char *path) {
    if (!engine || !path) return false;

    if (engine->active_count >= MAX_MONITORED_PROCESSES) {
        printf("[ERROR] Cannot monitor PID %u: Table capacity reached.\n", pid);
        return false;
    }

    ProcessRecord *rec = &engine->records[engine->active_count];
    rec->pid = pid;
    
    strncpy(rec->binary_path, path, MAX_PATH_LENGTH - 1);
    rec->binary_path[MAX_PATH_LENGTH - 1] = '\0';

    rec->start_timestamp = get_system_timestamp_ms();
    rec->is_isolated = false;
    rec->memory_footprint_kb = 1024 + (rand() % 4096); // Simulated baseline
    rec->integrity_guard = INTEGRITY_CANARY;

    engine->active_count++;
    printf("[GUARD] Registered Process PID %u -> '%s'\n", pid, path);
    return true;
}

void monitor_audit_process_list(MonitorEngine *engine) {
    if (!engine) return;

    printf("\n------------------------------------------------------\n");
    printf("        SYSTEM INTEGRITY AUDIT REPORT                  \n");
    printf("------------------------------------------------------\n");

    for (size_t i = 0; i < engine->active_count; i++) {
        ProcessRecord *rec = &engine->records[i];
        
        bool ok = monitor_verify_integrity(rec);
        if (!ok) {
            engine->total_security_alerts++;
            rec->is_isolated = true;
            printf("[CONTAINMENT] Isolated compromised record PID: %u\n", rec->pid);
            continue;
        }

        printf("PID: %6u | Status: %-10s | RAM: %4u KB | Path: %s\n",
               rec->pid,
               rec->is_isolated ? "ISOLATED" : "ACTIVE",
               rec->memory_footprint_kb,
               rec->binary_path);
    }
    printf("------------------------------------------------------\n");
    printf("Total Active: %zu | Total Alerts: %" PRIu64 "\n\n",
           engine->active_count, engine->total_security_alerts);
}

void security_signal_handler(int signal_number) {
    printf("\n[SIGNAL] Trapped system signal %d. Flushing security log buffers...\n", signal_number);
    g_monitor_engine.monitoring_active = false;
}

int main(void) {
    // Register OS fault signal traps
#if defined(__unix__) || defined(__APPLE__)
    signal(SIGINT, security_signal_handler);
    signal(SIGTERM, security_signal_handler);
#endif

    srand((unsigned int)time(NULL));
    monitor_init(&g_monitor_engine);

    // Register process table entries
    monitor_register_process(&g_monitor_engine, 101, "/usr/bin/sys_daemon");
    monitor_register_process(&g_monitor_engine, 102, "/usr/libexec/net_guard");
    monitor_register_process(&g_monitor_engine, 103, "/opt/app/sec_service");

    // Perform routine system audit
    monitor_audit_process_list(&g_monitor_engine);

    // Corrupt memory manually to demonstrate guard response
    printf("[TEST] Simulating out-of-bounds memory clobbering on PID 102...\n");
    g_monitor_engine.records[1].integrity_guard = 0x0;

    // Run audit again to test detection engine
    monitor_audit_process_list(&g_monitor_engine);

    printf("[CLEANUP] System guard engine shutting down cleanly.\n");
    return 0;
}