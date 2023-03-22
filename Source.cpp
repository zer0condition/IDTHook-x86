#include <ntddk.h>
#include <intrin.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct _IDTR {
    USHORT limit;
    ULONG_PTR base;
} IDTR, * PIDTR;
#pragma pack(pop)

typedef struct _IsrInfo {
    ULONG vector;
    PVOID isrAddress;
    PVOID originalIsrAddress;
    UCHAR originalIsrBytes[16];
} IsrInfo;

PVOID GetIDTBase()
{
    IDTR idtr = { 0 };
    __sidt(&idtr);

    return (PVOID)idtr.base;
}

ULONG GetIDTEntrySize()
{
    return sizeof(ULONG_PTR) * 2; // IDT entry size is 16 bytes (2 pointers)
}

ULONG GetIDTSize()
{
    PVOID idtBase = GetIDTBase();

    if (!idtBase)
        return 0;

    IDTR idtr = { 0 };
    __sidt(&idtr);

    return (ULONG)(idtr.limit / GetIDTEntrySize() + 1);
}

VOID HookedIsr(_In_ ULONG64 vector) {
    KdPrint("Hooked ISR called for vector %llu\n", vector);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {

    PVOID idtBase = GetIDTBase();   // Get the Interrupt Descriptor Table (IDT) address
    ULONG idtEntrySize = GetIDTEntrySize(); // Get the IDT entry size
    ULONG idtSize = GetIDTSize();   // Get the number of IDT entries

    if (idtSize == NULL) {
        return STATUS_ABANDONED;
    }

    idtSize /= idtEntrySize;

    KdPrint("IDTBase %p\n", idtBase);
    KdPrint("IDTEntries: %lu\n", idtSize);
    KdPrint("IDTEntrySize: %lu\n", idtEntrySize);

    IsrInfo* isrList = (IsrInfo*)ExAllocatePoolWithTag(NonPagedPool, idtSize * sizeof(IsrInfo), 'IDTR');
    if (isrList == NULL) {
        return STATUS_ABANDONED;
    }

    for (ULONG i = 0; i < idtSize; i++) {
        IsrInfo& isrInfo = isrList[i];
        isrInfo.vector = i;
        isrInfo.isrAddress = reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(idtBase) + i * idtEntrySize);
        isrInfo.originalIsrAddress = nullptr;

        memcpy(isrInfo.originalIsrBytes, isrInfo.isrAddress, sizeof(isrInfo.originalIsrBytes));
    }

    IsrInfo& isrInfo = isrList[0x21]; // IRQ1
    UCHAR jumpInstruction[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
    ULONG_PTR jumpOffset = reinterpret_cast<ULONG_PTR>(HookedIsr);
    memcpy(jumpInstruction + 2, &jumpOffset, sizeof(jumpOffset));
    memcpy(isrInfo.isrAddress, jumpInstruction, sizeof(jumpInstruction));

    isrInfo.originalIsrAddress = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(isrInfo.isrAddress) - sizeof(isrInfo.originalIsrBytes));
    memcpy(isrInfo.originalIsrBytes, isrInfo.originalIsrAddress, sizeof(isrInfo.originalIsrBytes));

    KdPrint("Hooked ISR vector: %lu\n", isrInfo.vector);
    KdPrint("Hooked ISR address: %p\n", isrInfo.isrAddress);
    KdPrint("Original ISR address: %p\n", isrInfo.originalIsrAddress);

    memcpy(isrInfo.originalIsrAddress, isrInfo.originalIsrBytes, sizeof(isrInfo.originalIsrBytes)); // Restore original

    ExFreePoolWithTag(isrList, 'IDTR');

    return STATUS_SUCCESS;
}
