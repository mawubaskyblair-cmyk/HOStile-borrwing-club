"""
File: 02_adversarial_simulator.py
Topic: Hostile Development Systems - Multi-threaded Threat Simulator & Fuzzer
Language: Python (3.10+)
Description: An adversarial simulator designed to test system responses against hostile traffic,
             malicious payloads, memory corruption patterns, and rate-limit evasions.
"""

import sys
import os
import time
import socket
import threading
import random
import string
import hashlib
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(threadName)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

@dataclass
class ThreatPayload:
    payload_id: str
    attack_vector: str
    raw_bytes: bytes
    target_port: int
    severity: int
    metadata: Dict[str, str] = field(default_factory=dict)

class HostilePayloadGenerator:
    """Generates dynamic adversarial payloads to simulate hostile code vectors."""
    
    @staticmethod
    def generate_buffer_overflow(length: int = 1024) -> bytes:
        """Generates cyclic patterned payload for testing memory corruption boundaries."""
        pattern = []
        for i in range(length):
            pattern.append(ord('A') + (i % 26))
        # Append shellcode simulation signature
        return bytes(pattern) + b"\x90\x90\x90\x90\xCC\xCC\xCC\xCC"

    @staticmethod
    def generate_malformed_json() -> bytes:
        """Generates deeply nested and structurally broken JSON payloads."""
        nested = "{\"key\":" * 150 + "\"hostile_overflow_value\"" + "}" * 149
        return nested.encode('utf-8')

    @staticmethod
    def generate_format_string_attack() -> bytes:
        """Generates format string payloads to test string parsing weaknesses."""
        return b"%x.%s.%n.%x.%x.%s.%p.%d.%s%n%n%n%n"

    @staticmethod
    def generate_sql_injection_vector() -> bytes:
        """Generates adversarial SQL injection variants."""
        payloads = [
            "1' OR '1'='1' -- ",
            "admin' --",
            "1 UNION SELECT 1,2,3,4,table_name FROM information_schema.tables --",
            "'; DROP TABLE system_logs; --"
        ]
        return random.choice(payloads).encode('utf-8')

class SystemTelemetryEngine:
    """Monitors simulated application metrics during hostile execution."""
    
    def __init__(self):
        self._lock = threading.Lock()
        self.packets_sent: int = 0
        self.bytes_transmitted: int = 0
        self.detected_blocks: int = 0
        self.errors_logged: int = 0
        self.attack_history: List[Dict] = []

    def log_attack(self, payload_id: str, vector: str, bytes_len: int, blocked: bool):
        with self._lock:
            self.packets_sent += 1
            self.bytes_transmitted += bytes_len
            if blocked:
                self.detected_blocks += 1
            self.attack_history.append({
                "timestamp": time.time(),
                "id": payload_id,
                "vector": vector,
                "size": bytes_len,
                "blocked": blocked
            })

    def print_summary(self):
        with self._lock:
            logging.info("=" * 60)
            logging.info("       ADVERSARIAL SIMULATION RUNTIME METRICS SUMMARY       ")
            logging.info("=" * 60)
            logging.info(f"Total Packets Transmitted : {self.packets_sent}")
            logging.info(f"Total Payload Size        : {self.bytes_transmitted} bytes")
            logging.info(f"Blocked by System Defense  : {self.detected_blocks}")
            logging.info(f"System Bypasses / Passed  : {self.packets_sent - self.detected_blocks}")
            logging.info(f"Defense Efficiency Ratio  : {(self.detected_blocks / max(1, self.packets_sent)) * 100:.2f}%")
            logging.info("=" * 60)

class ThreatOrchestrator:
    """Manages worker threads executing simultaneous attack vectors."""

    def __init__(self, target_host: str = "127.0.0.1", worker_threads: int = 8):
        self.target_host = target_host
        self.worker_threads = worker_threads
        self.telemetry = SystemTelemetryEngine()
        self.is_active = False

    def build_threat_suite(self) -> List[ThreatPayload]:
        suite = []
        vectors = [
            ("BUFFER_OVERFLOW", HostilePayloadGenerator.generate_buffer_overflow(2048), 8080, 5),
            ("MALFORMED_JSON", HostilePayloadGenerator.generate_malformed_json(), 8080, 3),
            ("FORMAT_STRING", HostilePayloadGenerator.generate_format_string_attack(), 9000, 4),
            ("SQL_INJECTION", HostilePayloadGenerator.generate_sql_injection_vector(), 8080, 4)
        ]

        for i in range(40):
            vec_name, raw_data, port, sev = random.choice(vectors)
            p_id = hashlib.sha256(f"{i}-{time.time()}".encode()).hexdigest()[:12]
            suite.append(ThreatPayload(
                payload_id=f"THREAT-{p_id}",
                attack_vector=vec_name,
                raw_bytes=raw_data,
                target_port=port,
                severity=sev,
                metadata={"iteration": str(i), "generator": "HostileFuzzer_v1"}
            ))
        return suite

    def _execute_attack_worker(self, payload: ThreatPayload):
        """Simulates sending attack payload and evaluates dynamic defense reaction."""
        time.sleep(random.uniform(0.01, 0.08)) # Add micro-jitter
        
        # Simulate local defense reaction (mock firewall check)
        is_blocked = False
        if payload.severity >= 4 or b"DROP TABLE" in payload.raw_bytes:
            is_blocked = True
        elif len(payload.raw_bytes) > 1500:
            is_blocked = True

        self.telemetry.log_attack(
            payload_id=payload.payload_id,
            vector=payload.attack_vector,
            bytes_len=len(payload.raw_bytes),
            blocked=is_blocked
        )

        status_str = "BLOCKED" if is_blocked else "PENETRATED"
        logging.info(f"[{status_str}] Payload: {payload.payload_id} | Vector: {payload.attack_vector} | Size: {len(payload.raw_bytes)}B")

    def run_simulation(self):
        logging.info("Starting Hostile Threat Simulation Module...")
        self.is_active = True
        payload_suite = self.build_threat_suite()

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.worker_threads, thread_name_prefix="HostileWorker") as executor:
            futures = [executor.submit(self._execute_attack_worker, p) for p in payload_suite]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    logging.error(f"Worker generated exception: {exc}")
                    self.telemetry.errors_logged += 1

        elapsed = time.time() - start_time
        logging.info(f"Simulation completed in {elapsed:.3f} seconds.")
        self.telemetry.print_summary()

if __name__ == "__main__":
    print("""
    ****************************************************************
    *      HOSTILE DEVELOPMENT SYSTEMS - ADVERSARIAL SIMULATOR     *
    ****************************************************************
    """)
    orchestrator = ThreatOrchestrator(target_host="127.0.0.1", worker_threads=6)
    orchestrator.run_simulation()