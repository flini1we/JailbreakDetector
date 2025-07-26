import Foundation
import UIKit
import Darwin
import MachO
import ObjectiveC

final class JailbreakDetector {
    
    enum CheckType: CaseIterable {
        case urlSchemes
        case suspiciousFiles
        case filePermissions
        case restrictedDirectories
        case fork
        case symbolicLinks
        case dyld
        case objcClasses
        case environmentVariables
        case modernJailbreakPaths
        case suspiciousProcesses
    }
    
    struct CheckResult {
        let passed: Bool
        let failMessage: String
        let checkType: CheckType
        
        static func success(checkType: CheckType) -> Self {
            CheckResult(passed: true, failMessage: "", checkType: checkType)
        }
    }
    
    struct JailbreakStatus {
        let isJailbroken: Bool
        let failMessage: String
        let failedChecks: [CheckType]
    }
    
    static func isDeviceJailbroken() -> Bool {
        return !performChecks().passed
    }
    
    static func getDetailedStatus() -> JailbreakStatus {
        let status = performChecks()
        return JailbreakStatus(
            isJailbroken: !status.passed,
            failMessage: status.failMessage,
            failedChecks: status.failedChecks.map { $0.checkType }
        )
    }
}

private extension JailbreakDetector {
    
    private struct Configuration {
        static let suspiciousSchemes = [
            "undecimus://",
            "sileo://",
            "zbra://",
            "filza://",
            "newterm://"
        ]
        
        static let jailbreakPaths = [
            /// Modern jailbreak paths
            "/var/jb/usr/lib/libjailbreak.dylib",
            "/var/jb/usr/lib/libsubstitute.dylib",
            "/var/jb/usr/lib/libsubstrate.dylib",
            "/var/jb/usr/lib/libhooker.dylib",
            
            /// Common jailbreak paths
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/lib/libhooker.dylib",
            "/usr/lib/libsubstitute.dylib",
            "/usr/lib/substrate",
            "/usr/lib/TweakInject",
            
            /// System paths
            "/var/lib/undecimus",
            "/var/mobile/Library/undecimus",
            "/var/root/Library/undecimus",
            
            /// Additional paths
            "/var/containers/Bundle/Application/dopamine",
            "/var/containers/Bundle/Application/palera1n",
            "/var/containers/Bundle/Application/odyssey",
            "/var/containers/Bundle/Application/taurine"
        ]
        
        static let filePremissionPaths = [
            "/.installed_unc0ver",
            "/.bootstrapped_electra",
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib"
        ]
        
        static let restrictedDirectories = ["/", "/private/", "/jb/"]
        
        static let symbolicLinks = [
            "/var/lib/undecimus/apt",
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/arm-apple-darwin9",
            "/usr/include",
            "/usr/libexec",
            "/usr/share"
        ]
        
        static let suspiciousLibraries: Set<String> = [
            "systemhook.dylib",
            "SubstrateLoader.dylib",
            "SSLKillSwitch2.dylib",
            "MobileSubstrate.dylib",
            "TweakInject.dylib",
            "CydiaSubstrate",
            "libhooker",
            "Substitute",
            "FridaGadget",
            "frida",
            "libcycript"
        ]
        
        static let suspiciousVariables = [
            "DYLD_INSERT_LIBRARIES",
            "FRIDA_SERVER",
            "LIBHOOKER_LOAD",
            "SUBSTRATE_RUN",
            "SUBSTITUTE_LOAD",
            "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH"
        ]
        
        static let modernJailbreakPaths = [
            "/var/jb/usr/lib/libjailbreak.dylib",
            "/var/jb/usr/lib/libsubstitute.dylib",
            "/var/jb/usr/lib/libsubstrate.dylib",
            "/var/jb/usr/lib/libhooker.dylib",
            "/var/root/Library/LaunchDaemons/com.apple.SpringBoard.plist",
            "/var/root/Library/LaunchDaemons/com.apple.backboardd.plist"
        ]
        
        static let suspiciousProcesses = [
            "frida-server",
            "frida-helper",
            "frida-agent",
            "substitute",
            "substrate",
            "hooker",
            "jailbreakd"
        ]
    }
    
    static func performChecks() -> (passed: Bool, failMessage: String, failedChecks: [CheckResult]) {
        var passed = true,
            failMessage = "",
            failedChecks: [CheckResult] = []
        
        for check in CheckType.allCases {
            let result = performCheck(type: check)
            passed = passed && result.passed
            
            if !result.passed {
                failedChecks.append(result)
                if !failMessage.isEmpty {
                    failMessage += ", "
                }
                failMessage += result.failMessage
            }
        }
        
        return (passed, failMessage, failedChecks)
    }
    
    static func performCheck(type: CheckType) -> CheckResult {
        
        switch type {
        case .urlSchemes:
            return checkURLSchemes()
        case .suspiciousFiles:
            return checkSuspiciousFiles()
        case .filePermissions:
            return checkFilePermissions()
        case .restrictedDirectories:
            return checkRestrictedDirectories()
        case .fork:
            return checkFork()
        case .symbolicLinks:
            return checkSymbolicLinks()
        case .dyld:
            return checkDYLD()
        case .objcClasses:
            return checkSuspiciousObjCClasses()
        case .environmentVariables:
            return checkEnvironmentVariables()
        case .modernJailbreakPaths:
            return checkModernJailbreakPaths()
        case .suspiciousProcesses:
            return checkSuspiciousProcesses()
        }
    }
    
    static func checkURLSchemes() -> CheckResult {
        
        for scheme in Configuration.suspiciousSchemes {
            if let url = URL(string: scheme), UIApplication.shared.canOpenURL(url) {
                return CheckResult(
                    passed: false,
                    failMessage: "Suspicious URL scheme detected: \(scheme)",
                    checkType: .urlSchemes
                )
            }
        }
        
        return .success(checkType: .urlSchemes)
    }
    
    static func checkSuspiciousFiles() -> CheckResult {
        
        for path in Configuration.jailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                return CheckResult(
                    passed: false,
                    failMessage: "Suspicious file exists: \(path)",
                    checkType: .suspiciousFiles
                )
            }
            
            if let fileHandle = FileHandle(forReadingAtPath: path) {
                fileHandle.closeFile()
                return CheckResult(
                    passed: false,
                    failMessage: "Suspicious file can be opened: \(path)",
                    checkType: .suspiciousFiles
                )
            }
        }
        
        return .success(checkType: .suspiciousFiles)
    }
    
    static func checkFilePermissions() -> CheckResult {
        
        for path in Configuration.filePremissionPaths {
            if FileManager.default.isReadableFile(atPath: path) {
                return CheckResult(
                    passed: false,
                    failMessage: "Suspicious file is readable: \(path)",
                    checkType: .filePermissions
                )
            }
        }
        
        return .success(checkType: .filePermissions)
    }
    
    static func checkRestrictedDirectories() -> CheckResult {
        
        for path in Configuration.restrictedDirectories {
            do {
                let testFile = path + UUID().uuidString
                try "restrictedDir".write(toFile: testFile, atomically: true, encoding: .utf8)
                try FileManager.default.removeItem(atPath: testFile)
                return CheckResult(
                    passed: false,
                    failMessage: "Can write to restricted path: \(path)",
                    checkType: .restrictedDirectories
                )
            } catch {}
        }
        
        return .success(checkType: .restrictedDirectories)
    }
    
    static func checkFork() -> CheckResult {
        let pointerToFork = UnsafeMutableRawPointer(bitPattern: -2)
        let forkPtr = dlsym(pointerToFork, "fork")
        typealias ForkType = @convention(c) () -> pid_t
        let fork = unsafeBitCast(forkPtr, to: ForkType.self)
        let forkResult = fork()
        
        if forkResult >= 0 {
            if forkResult > 0 { kill(forkResult, SIGTERM) }
            return CheckResult(
                passed: false,
                failMessage: "Fork was able to create a new process (sandbox violation)",
                checkType: .fork
            )
        }
        
        return .success(checkType: .fork)
    }
    
    static func checkSymbolicLinks() -> CheckResult {
        
        for path in Configuration.symbolicLinks {
            do {
                let result = try FileManager.default.destinationOfSymbolicLink(atPath: path)
                if !result.isEmpty {
                    return CheckResult(
                        passed: false,
                        failMessage: "Non standard symbolic link detected: \(path) points to \(result)",
                        checkType: .symbolicLinks
                    )
                }
            } catch {}
        }
        
        return .success(checkType: .symbolicLinks)
    }
    
    static func checkDYLD() -> CheckResult {
        
        for index in 0..<_dyld_image_count() {
            let imageName = String(cString: _dyld_get_image_name(index))
            for library in Configuration.suspiciousLibraries where imageName.localizedCaseInsensitiveContains(library) {
                return CheckResult(
                    passed: false,
                    failMessage: "Suspicious library loaded: \(imageName)",
                    checkType: .dyld
                )
            }
        }
        
        return .success(checkType: .dyld)
    }
    
    static func checkSuspiciousObjCClasses() -> CheckResult {
        
        if let shadowRulesetClass = objc_getClass("ShadowRuleset") as? NSObject.Type {
            let selector = Selector(("internalDictionary"))
            if class_getInstanceMethod(shadowRulesetClass, selector) != nil {
                return CheckResult(
                    passed: false,
                    failMessage: "Shadow anti-anti-jailbreak detector detected",
                    checkType: .objcClasses
                )
            }
        }
        
        return .success(checkType: .objcClasses)
    }
    
    static func checkEnvironmentVariables() -> CheckResult {
        
        let env = ProcessInfo.processInfo.environment
        
        for variable in Configuration.suspiciousVariables {
            if env[variable] != nil {
                return CheckResult(
                    passed: false,
                    failMessage: "Suspicious environment variable detected: \(variable)",
                    checkType: .environmentVariables
                )
            }
        }
        
        return .success(checkType: .environmentVariables)
    }
    
    static func checkModernJailbreakPaths() -> CheckResult {
        
        for path in Configuration.modernJailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                return CheckResult(
                    passed: false,
                    failMessage: "Modern jailbreak path detected: \(path)",
                    checkType: .modernJailbreakPaths
                )
            }
        }
        
        return .success(checkType: .modernJailbreakPaths)
    }
    
    static func checkSuspiciousProcesses() -> CheckResult {
        var mib = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0],
            size = 0
        
        if sysctl(&mib, 4, nil, &size, nil, 0) != 0 {
            return .success(checkType: .suspiciousProcesses)
        }
        
        let count = size / MemoryLayout<kinfo_proc>.stride
        var procBuffer = [kinfo_proc](repeating: kinfo_proc(), count: count)
        if sysctl(&mib, 4, &procBuffer, &size, nil, 0) != 0 {
            return .success(checkType: .suspiciousProcesses)
        }
        
        for i in 0..<count {
            let proc = procBuffer[i]
            if let processName = getProcessName(proc) {
                for suspiciousProcess in Configuration.suspiciousProcesses {
                    if processName.contains(suspiciousProcess) {
                        return CheckResult(
                            passed: false,
                            failMessage: "Suspicious process detected: \(suspiciousProcess)",
                            checkType: .suspiciousProcesses
                        )
                    }
                }
            }
        }
        
        return .success(checkType: .suspiciousProcesses)
    }
    
    static func getProcessName(_ proc: kinfo_proc) -> String? {
        let name = withUnsafePointer(to: proc.kp_proc.p_comm) { ptr in
            let cString = UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            return String(cString: cString)
        }
        return name.isEmpty ? nil : name
    }
}

