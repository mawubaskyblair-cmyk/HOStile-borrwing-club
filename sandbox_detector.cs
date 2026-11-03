/*
 * File: 07_sandbox_detector.cs
 * Topic: Defensive Systems Security - Environment Sanity Checker & Hardware Profiler
 * Language: C# (.NET 8.0 / C# 12)
 * Description: Performs structured environment verification, auditing system hardware limits,
 *              execution timing consistency, and OS environment state to ensure safe execution.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace SecuritySystems.EnvironmentGuard
{
    public enum HealthStatus
    {
        Optimal = 0,
        Degraded = 1,
        Restricted = 2,
        Hostile = 3
    }

    public record EnvironmentCheckResult(
        string CheckName,
        bool Passed,
        string TelemetryDetails,
        int RiskScore
    );

    public class SystemProfilerEngine
    {
        private readonly List<EnvironmentCheckResult> _auditResults = new();
        private int _totalRiskScore = 0;

        public event Action<EnvironmentCheckResult>? OnCheckCompleted;

        public async Task<HealthStatus> RunDiagnosticsAsync(CancellationToken cancellationToken = default)
        {
            Console.WriteLine("=======================================================");
            Console.WriteLine("     SYSTEM ENVIRONMENT SANITY & PROFILE ENGINE      ");
            Console.WriteLine("=======================================================");

            await ExecuteCheckAsync("CPU Core Allocation Audit", AuditCpuCoreCount);
            await ExecuteCheckAsync("System Memory Provisioning", AuditMemorySize);
            await ExecuteCheckAsync("System Storage Boundary Check", AuditStorageCapacity);
            await ExecuteCheckAsync("Execution Timing Consistency", AuditTimingBehavior);
            await ExecuteCheckAsync("Operating System Identity Audit", AuditOperatingSystemEnvironment);

            return EvaluateOverallHealth();
        }

        private async Task ExecuteCheckAsync(string checkName, Func<EnvironmentCheckResult> checkFunc)
        {
            await Task.Yield(); // Ensure async scheduling compliance
            try
            {
                var result = checkFunc();
                _auditResults.Add(result);
                _totalRiskScore += result.RiskScore;
                OnCheckCompleted?.Invoke(result);

                string statusStr = result.Passed ? "[PASS]" : "[WARN]";
                Console.WriteLine($"{statusStr} {result.CheckName}");
                Console.WriteLine($"       Details: {result.TelemetryDetails}");
                Console.WriteLine($"       Score:   +{result.RiskScore}");
                Console.WriteLine("-------------------------------------------------------");
            }
            catch (Exception ex)
            {
                var errorResult = new EnvironmentCheckResult(checkName, false, $"Diagnostic Error: {ex.Message}", 25);
                _auditResults.Add(errorResult);
                _totalRiskScore += 25;
            }
        }

        private EnvironmentCheckResult AuditCpuCoreCount()
        {
            int logicalCores = Environment.ProcessorCount;
            bool isSufficient = logicalCores >= 4;
            int risk = isSufficient ? 0 : 20;

            return new EnvironmentCheckResult(
                "CPU Core Allocation Audit",
                isSufficient,
                $"Detected Logical Cores: {logicalCores} (Threshold >= 4)",
                risk
            );
        }

        private EnvironmentCheckResult AuditMemorySize()
        {
            long gcMemory = GC.GetTotalMemory(forceFullCollection: false);
            // Check system working set
            long workingSetMB = Environment.WorkingSet / (1024 * 1024);
            bool isNormal = workingSetMB >= 16; 
            int risk = isNormal ? 0 : 15;

            return new EnvironmentCheckResult(
                "System Memory Provisioning",
                isNormal,
                $"Allocated Working Set: {workingSetMB} MB",
                risk
            );
        }

        private EnvironmentCheckResult AuditStorageCapacity()
        {
            bool hasValidDrive = false;
            long totalSpaceGB = 0;

            try
            {
                DriveInfo mainDrive = DriveInfo.GetDrives().FirstOrDefault(d => d.IsReady && d.DriveType == DriveType.Fixed) 
                                      ?? DriveInfo.GetDrives().First(d => d.IsReady);

                totalSpaceGB = mainDrive.TotalSize / (1024 * 1024 * 1024);
                hasValidDrive = totalSpaceGB >= 60; // System drives under 60GB indicate heavily restricted virtual environments
            }
            catch
            {
                totalSpaceGB = -1;
            }

            int risk = hasValidDrive ? 0 : 25;
            return new EnvironmentCheckResult(
                "System Storage Boundary Check",
                hasValidDrive,
                $"Primary Disk Space: {totalSpaceGB} GB (Threshold >= 60 GB)",
                risk
            );
        }

        private EnvironmentCheckResult AuditTimingBehavior()
        {
            var stopwatch = Stopwatch.StartNew();
            Thread.Sleep(100);
            stopwatch.Stop();

            // Measure timing drift (e.g., hypervisor stepping overhead)
            double deltaMs = Math.Abs(stopwatch.ElapsedMilliseconds - 100);
            bool timingConsistent = deltaMs < 30; // Drift lower than 30ms acceptable
            int risk = timingConsistent ? 0 : 30;

            return new EnvironmentCheckResult(
                "Execution Timing Consistency",
                timingConsistent,
                $"Expected: 100ms | Actual: {stopwatch.ElapsedMilliseconds}ms | Delta: {deltaMs:F2}ms",
                risk
            );
        }

        private EnvironmentCheckResult AuditOperatingSystemEnvironment()
        {
            string osVersion = RuntimeInformation.OSDescription;
            Architecture arch = RuntimeInformation.OSArchitecture;

            bool isSupportedArch = arch == Architecture.X64 || arch == Architecture.Arm64;
            int risk = isSupportedArch ? 0 : 10;

            return new EnvironmentCheckResult(
                "Operating System Identity Audit",
                isSupportedArch,
                $"OS: {osVersion} | Arch: {arch}",
                risk
            );
        }

        private HealthStatus EvaluateOverallHealth()
        {
            Console.WriteLine($"\n[==>] Cumulative Risk Assessment Score: {_totalRiskScore}/100");

            if (_totalRiskScore >= 60)
            {
                Console.WriteLine("[CRITICAL] Environment risk score indicates restricted or non-standard execution layer.");
                return HealthStatus.Hostile;
            }
            if (_totalRiskScore >= 30)
            {
                Console.WriteLine("[WARN] Degraded environmental resources observed. Proceeding with caution.");
                return HealthStatus.Restricted;
            }

            Console.WriteLine("[OK] System environment integrity verified optimal.");
            return HealthStatus.Optimal;
        }
    }

    public static class Program
    {
        public static async Task Main(string[] args)
        {
            var profiler = new SystemProfilerEngine();
            profiler.OnCheckCompleted += (result) =>
            {
                // Real-time telemetry hook callback
            };

            HealthStatus status = await profiler.RunDiagnosticsAsync();
            Console.WriteLine($"[EXIT] Profiler returned status code: {status} (0x{(int)status:X2})");
        }
    }
}