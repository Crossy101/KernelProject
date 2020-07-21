#include <cstddef>
#include "Structs.h"

typedef BYTE uint8_t;

template <typename t = void*> //free pasta
t find_pattern(void* start, size_t length, const char* pattern, const char* mask) {
	const auto data = static_cast<const char*>(start);
	const auto pattern_length = strlen(mask);

	for (size_t i = 0; i <= length - pattern_length; i++)
	{
		bool accumulative_found = true;

		for (size_t j = 0; j < pattern_length; j++)
		{
			if (!MmIsAddressValid(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(data) + i + j)))
			{
				accumulative_found = false;
				break;
			}

			if (data[i + j] != pattern[j] && mask[j] != '?')
			{
				accumulative_found = false;
				break;
			}
		}

		if (accumulative_found)
		{
			return (t)(reinterpret_cast<uintptr_t>(data) + i);
		}
	}

	return (t)nullptr;
}

uintptr_t dereference(uintptr_t address, unsigned int offset) {
	if (address == 0)
		return 0;

	return address + (int)((*(int*)(address + offset) + offset) + sizeof(int));
}

uintptr_t get_kerneladdr(const char* name, size_t& size) {

	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	ZwQuerySystemInformation(SystemModuleInformation, &neededSize, 0, &neededSize);

	PSYSTEM_MODULE_INFORMATION pModuleList;

	pModuleList = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, neededSize, 'what');

	if (!pModuleList) {
		DbgPrint("ExAllocatePoolWithTag failed(kernel addr)\n");
		return 0;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation,
		pModuleList,
		neededSize,
		0
	);

	ULONG i = 0;
	uintptr_t address = 0;

	for (i = 0; i < pModuleList->ulModuleCount; i++)
	{
		SYSTEM_MODULE mod = pModuleList->Modules[i];

		address = uintptr_t(pModuleList->Modules[i].Base);
		size = uintptr_t(pModuleList->Modules[i].Size);
		if (strstr(mod.ImageName, name) != NULL)
			break;
	}

	ExFreePoolWithTag(pModuleList, 'what');

	return address;
}

void ClearPIDDBCacheTable()
{
	PRTL_AVL_TABLE PiDDBCacheTable;

	size_t size;
	uintptr_t ntoskrnlBase = get_kerneladdr("ntoskrnl.exe", size);

	DbgPrint("ntoskrnl.exe: %d\n", ntoskrnlBase);
	DbgPrint("ntoskrnl.exe size: %d\n", size);

	//48 8D 0D ?? ?? ?? ?? 45 8D 41 38 E8 ?? ?? ?? ??
	PiDDBCacheTable = (PRTL_AVL_TABLE)dereference(find_pattern<uintptr_t>((void*)ntoskrnlBase, size, "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x3D\x00\x00\x00\x00\x0F\x83\x00\x00\x00\x00", "xxx????x????x????xx????"), 3);

	DbgPrint("PiDDBCacheTable: %d\n", PiDDBCacheTable);

	uintptr_t entry_address = uintptr_t(PiDDBCacheTable->BalancedRoot.RightChild) + sizeof(RTL_BALANCED_LINKS);
	DbgPrint("entry_address: %d\n", entry_address);

	PiDDBCacheEntry* entry = (PiDDBCacheEntry*)(entry_address);

	/*capcom.sys(drvmap) : 0x57CD1415 iqvw64e.sys(kdmapper) : 0x5284EAC3, also cpuz driver*/
	if (entry->TimeDateStamp == 0x57CD1415 || entry->TimeDateStamp == 0x5284EAC3) {
		entry->TimeDateStamp = 0x54EAC3;
		entry->DriverName = RTL_CONSTANT_STRING(L"AgileVPS.sys");
	}

	ULONG count = 0;
	for (auto link = entry->List.Flink; link != entry->List.Blink; link = link->Flink, count++)
	{
		PiDDBCacheEntry* cache_entry = (PiDDBCacheEntry*)(link);

		if (cache_entry->TimeDateStamp == 0x57CD1415 || cache_entry->TimeDateStamp == 0x5284EAC3) {
			cache_entry->TimeDateStamp = 0xB97F50A5 + count;
			cache_entry->DriverName = RTL_CONSTANT_STRING(L"AgileVPS.sys");
		}

		DbgPrint("cache_entry count: %lu name: %wZ \t\t stamp: %x\n",
			count,
			cache_entry->DriverName,
			cache_entry->TimeDateStamp);
	}

}

void GetModuleBaseAddress(__in p_info buff)
{
	PEPROCESS pProcess = NULL;
	ULONG totalCount = 0;
	KAPC_STATE apk;

	__try
	{
		PsLookupProcessByProcessId((HANDLE)buff->pid, &pProcess);

		LARGE_INTEGER time = { 0 };
		time.QuadPart = -250ll * 10 * 1000;     // 250 msec.
			
			KeStackAttachProcess(pProcess, &apk);
			PPEB pPeb = PsGetProcessPeb(pProcess);
			if (!pPeb)
			{
				DbgPrint("BlackBone: Loader was not intialiezd in time. Aborting\n");
				return;
			}

			// Still no loader
			if (!pPeb->Ldr)
			{
				DbgPrint("BlackBone: Loader was not intialiezd in time. Aborting\n");
				return;
			}

			UNICODE_STRING moduleName;
			RtlInitUnicodeString(&moduleName, L"iRacingSim64DX11.exe");

			// Search in InLoadOrderModuleList
			for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
				pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
				pListEntry = pListEntry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (RtlCompareUnicodeString(&pEntry->BaseDllName, &moduleName, TRUE) == 0)
					buff->value = (ULONG_PTR)pEntry->DllBase;
			}
			KeUnstackDetachProcess(&apk);

			return;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("BlackBone: EXECEPTION_HANDLED\n");
		return;
	}
	return;
}

NTSTATUS ReadWriteVirtualMemory(IN PCOPY_MEMORY pCopy)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL, pSourceProc = NULL, pTargetProc = NULL;
	PVOID pSource = NULL, pTarget = NULL;

	status = PsLookupProcessByProcessId((HANDLE)pCopy->pid, &pProcess);

	if (NT_SUCCESS(status))
	{
		SIZE_T bytes = 0;

		// Write
		if (pCopy->write != FALSE)
		{
			pSourceProc = PsGetCurrentProcess();
			pTargetProc = pProcess;
			pSource = (PVOID)pCopy->localbuf;
			pTarget = (PVOID)pCopy->targetPtr;
		}
		// Read
		else
		{
			pSourceProc = pProcess;
			pTargetProc = PsGetCurrentProcess();
			pSource = (PVOID)pCopy->targetPtr;
			pTarget = (PVOID)pCopy->localbuf;
		}

		status = MmCopyVirtualMemory(pSourceProc, pSource, pTargetProc, pTarget, pCopy->size, KernelMode, &bytes);
	}
	else
		DbgPrint("BlackBone: PsLookupProcessByProcessId failed with status 0x%X\n", status);

	if (pProcess)
		ObDereferenceObject(pProcess);

	return status;
}

NTSTATUS ProtectVirtualMemory(IN PPROTECT_MEMORY pProtect)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;

	status = PsLookupProcessByProcessId((HANDLE)pProtect->pid, &pProcess);
	if (NT_SUCCESS(status))
	{
		KAPC_STATE apc;
		PVOID base = (PVOID)pProtect->base;
		SIZE_T size = (SIZE_T)pProtect->size;
		ULONG oldProt = 0;

		KeStackAttachProcess(pProcess, &apc);
		if (pProtect->newProtection == 0)
		{
			status = ZwProtectVirtualMemory(ZwCurrentProcess(), &base, &size, (ULONG)PAGE_EXECUTE_READWRITE, &oldProt);
		}
		else
		{
			status = ZwProtectVirtualMemory(ZwCurrentProcess(), &base, &size, (ULONG)PAGE_EXECUTE_READ, &oldProt);
		}
		KeUnstackDetachProcess(&apc);
	}
	else
		DbgPrint("BlackBone: PsLookupProcessByProcessId failed with status 0x%X\n", status);

	if (pProcess)
		ObDereferenceObject(pProcess);

	return status;
}



NTSTATUS ControlIO(PDEVICE_OBJECT device_obj, PIRP irp) {
	irp->IoStatus.Status = STATUS_SUCCESS;

	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);

	ULONG inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

	auto IoBuffer = irp->AssociatedIrp.SystemBuffer;

	switch (irpStack->MajorFunction)
	{
		case IRP_MJ_DEVICE_CONTROL:
		{
			ULONG IOControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

			switch (IOControlCode)
			{
				case IO_DISPATCH_READWRITE:
				{
					if (inputBufferLength >= sizeof(_COPY_MEMORY) && IoBuffer)
						irp->IoStatus.Status = ReadWriteVirtualMemory((PCOPY_MEMORY)IoBuffer);
					else
						irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
				}
				break;
				case IO_DISPATCH_PROTECT:
				{
					if(inputBufferLength >= sizeof(_PROTECT_MEMORY) && IoBuffer)
						irp->IoStatus.Status = ProtectVirtualMemory((PPROTECT_MEMORY)IoBuffer);
					else
						irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
				}
				break;
				default:
					break;
				}
			break;
		}
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS UnsupportedIO(PDEVICE_OBJECT device_obj, PIRP irp) {
	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS CreateIO(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS CloseIO(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}


VOID OnDriverUnload(PDRIVER_OBJECT driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);

	DbgPrint("DRIVER UNLOADED!");
}

NTSTATUS DriverInitialize(PDRIVER_OBJECT driverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(RegistryPath);

	if (!driverObject)
	{
		DbgPrint("Driver object has not been loaded/given!");
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}

	DbgPrint("Loaded Driver Object!!\n");

	// Normalize name and symbolic link.
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;
	RtlInitUnicodeString(&deviceNameUnicodeString, L"\\Device\\AgileVPS");
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, L"\\DosDevices\\AgileVPS");

	PDEVICE_OBJECT deviceObject = NULL;
	ntStatus = IoCreateDevice(driverObject, 0, &deviceNameUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("Failed to create device object! %d", ntStatus);
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	DbgPrint("Created Device Object!");

	deviceObject->Flags |= DO_BUFFERED_IO;

	// Create the symbolic link
	ntStatus = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("DispatchTestSys IoCreateSymbolicLink fail! Status: %d\n", ntStatus);
		return ntStatus;
	}
	DbgPrint("Created symbolic link!");

	driverObject->MajorFunction[IRP_MJ_CREATE] = CreateIO;
	driverObject->MajorFunction[IRP_MJ_CLOSE] = CloseIO;
	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ControlIO;
	driverObject->DriverUnload = &OnDriverUnload;
	deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	ClearPIDDBCacheTable();

	DbgPrint("Kernel Driver is booted!");

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNICODE_STRING drv_name{};

	RtlInitUnicodeString(&drv_name, L"\\Driver\\AgileVPS");

	DbgPrint("DRIVER ENTRY!\r\n");

	return IoCreateDriver(&drv_name, &DriverInitialize);
}
