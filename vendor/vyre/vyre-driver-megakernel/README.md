# vyre-driver-megakernel

Shared megakernel dispatch contracts for the vyre stack.

This crate owns the public work-queue shape (`WorkItem`), dispatch guards
(`MegakernelConfig`), capability metadata (`MegakernelCaps`), and result
summary (`MegakernelReport`) used by runtime-owned megakernel integrations.
