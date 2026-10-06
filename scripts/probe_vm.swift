// Copyright (c) 2026 dhtfish98. MIT License.
import Foundation
import Virtualization

@main
struct IsolatedLinuxLab {
    static func main() async throws {
        guard CommandLine.arguments.count == 3 else { exit(64) }
        let config = VZVirtualMachineConfiguration()
        config.cpuCount = 2
        config.memorySize = 1024 * 1024 * 1024
        config.platform = VZGenericPlatformConfiguration()
        let boot = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: CommandLine.arguments[1]))
        boot.initialRamdiskURL = URL(fileURLWithPath: CommandLine.arguments[2])
        boot.commandLine = "console=hvc0 rdinit=/bin/sh panic=0"
        config.bootLoader = boot
        let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
        serial.attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: .standardInput,
            fileHandleForWriting: .standardOutput
        )
        config.serialPorts = [serial]
        try config.validate()
        let vm = VZVirtualMachine(configuration: config)
        try await vm.start()
        while vm.state != .stopped {
            try await Task.sleep(for: .milliseconds(200))
        }
    }
}
