# Vicra

Vicra is a C++ toolkit designed to flawlessly detect advanced security measures and anti-tampering mechanisms in Windows software. It is intended for use by reverse engineers, security researchers, and developers who need to analyze how processes defend against code injection, debugging, and memory inspection.

# Exact Detection List

## Callbacks:
- Vectored Exception Handler 
- Loader Notifications
- Thread Local Storage

## Memory:
- Dynamically allocated syscall stubs
- Invalid CR3 (Regards EasyAntiCheat)
- Inline Hooks
- EAT Hooks

## Objects:
- Thread Flags (ThreadHideFromDebugger, ThreadBypassProcessFreeze)
- Devices
- Huge file backed sections 
- Job's

## Policies:
- Process Flags (VadTrackingDisabled, SystemProcess, DisallowUserTerminate)
- Process Protection
- Signature Enforcement Policy
- Debug Related

# Usage:

```
Source-x64.exe <ProcessName>
```
