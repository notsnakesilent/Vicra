# Vicra

Vicra is a C++ toolkit designed to flawlessly detect advanced security measures and anti-tampering mechanisms in Windows software. It is intended for use by reverse engineers, security researchers, and developers who need to analyze how processes defend against code injection, debugging, and memory inspection.

## Purpose

Vicra aims to provide automated, extensible detection of Windows process security features and mitigation policies. The toolkit can help identify:

- Techniques that prevent code injection or dynamic code execution
- Process-level memory protection and inspection countermeasures
- Anti-debugging mechanisms
- Callback-based hooks and notification lists

## Exact Detection List

# Callbacks:
- Vectored Exception Handler 
- Loader Notifications
- Thread Local Storage

# Memory:
- Dynamically allocated syscall stubs
- Invalid CR3 (Regards EasyAntiCheat)
- Inline Hooks
- EAT Hooks

# Objects:
- Thread Flags (ThreadHideFromDebugger, ThreadBypassProcessFreeze)
- Devices
- Huge file backed sections 
- Job's

# Policies:
- Process Flags (VadTrackingDisabled, SystemProcess, DisallowUserTerminate)
- Process Protection
- Signature Enforcement Policy
- Debug Related

## Usage

```
Source-x64.exe <ProcessName>
```
