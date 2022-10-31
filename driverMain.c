#include <ntddk.h>
#include "myntapi.h"
#include <minwindef.h>
#include "structs.h"
#include "ioctls.h"
#include "imports.h"
#include "physmem.h"

PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING dev, dos;

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp);


NTSTATUS MajorFunctionControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	ULONG BytesIO = 0;

	PIO_STACK_LOCATION CurrentStackLocation = IoGetCurrentIrpStackLocation(Irp);

	ULONG ControlCode = CurrentStackLocation->Parameters.DeviceIoControl.IoControlCode;

	if (ControlCode == COOLCODE_REQUESTGUARDEDREGION)
	{
		PCOOL_GUARDEDREGION_REQUESTS ReadInput = (PCOOL_GUARDEDREGION_REQUESTS)Irp->AssociatedIrp.SystemBuffer;

		if (ReadInput->FirstPointer == 0) return STATUS_UNSUCCESSFUL;

		uint64_t GuardedRegion = GetGuardedRegion(ReadInput->FirstPointer);
		if (!GuardedRegion) return STATUS_UNSUCCESSFUL;

		ReadInput->GuardedRegion = GuardedRegion;

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(COOL_GUARDEDREGION_REQUESTS);

		goto CompleteRequest;
	}
	else if (ControlCode == COOLCODE_REQUESTMODULEBASE)
	{
		PCOOL_MODULE_REQUESTS ReadInput = (PCOOL_MODULE_REQUESTS)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS source_process = NULL;
		if (ReadInput->TargetProcessID == 0) return STATUS_UNSUCCESSFUL;

		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)ReadInput->TargetProcessID, &source_process);
		if (status != STATUS_SUCCESS) return STATUS_UNSUCCESSFUL;

		uint64_t Base = PsGetProcessSectionBaseAddress(source_process);
		if (!Base) return STATUS_UNSUCCESSFUL;

		ReadInput->ReturnAddress = Base;

		ObDereferenceObject(source_process);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(COOL_MODULE_REQUESTS);

		goto CompleteRequest;
	}
	else if (ControlCode == COOLCODE_READPHYSICAL)
	{
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		PCOOL_RWPHYSICAL_REQUESTS ReadInput = (PCOOL_RWPHYSICAL_REQUESTS)Irp->AssociatedIrp.SystemBuffer;

		if (ReadInput->SourceProcessID == 0 || ReadInput->SourceAddress == 0) return STATUS_UNSUCCESSFUL;

		size_t memsize = 0;
		ReadProcessMemory(ReadInput->SourceProcessID, (void*)ReadInput->SourceAddress, (void*)ReadInput->ReturnAddress, ReadInput->Size, &memsize);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(COOL_RWPHYSICAL_REQUESTS);

		goto CompleteRequest;
	}
	else if (ControlCode == COOLCODE_WRITEPHYSICAL)
	{
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		PCOOL_RWPHYSICAL_REQUESTS ReadInput = (PCOOL_RWPHYSICAL_REQUESTS)Irp->AssociatedIrp.SystemBuffer;

		if (ReadInput->SourceProcessID == 0 || ReadInput->SourceAddress == 0) return STATUS_UNSUCCESSFUL;

		size_t memsize = 0;
		WriteProcessMemory(ReadInput->SourceProcessID, (void*)ReadInput->SourceAddress, (void*)ReadInput->ReturnAddress, ReadInput->Size, &memsize);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(COOL_RWPHYSICAL_REQUESTS);

		goto CompleteRequest;
	}
	else
	{
		Status = STATUS_INVALID_PARAMETER;
		BytesIO = 0;

		goto CompleteRequest;
	}

CompleteRequest:
	Irp->IoStatus.Information = BytesIO;
	Irp->IoStatus.Status = Status;
	IofCompleteRequest(Irp, 0);
	return Status;
}

NTSTATUS MajorFunctionCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS StatusCode = 0;

	if (!Irp)
	{
		return STATUS_UNSUCCESSFUL;
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = StatusCode;
	IofCompleteRequest(Irp, 0);

	return 0;
}

NTSTATUS MajorFunctionClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	if (!Irp)
	{
		return STATUS_UNSUCCESSFUL;
	}

	Irp->IoStatus.Status = 0;
	Irp->IoStatus.Information = 0;
	IofCompleteRequest(Irp, 0);
	return 0;
}

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS RealDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS StatusCodeBuffer = STATUS_UNSUCCESSFUL;

	RtlInitUnicodeString(&dev, L"\\Device\\coolschool");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\coolschool");

	StatusCodeBuffer = IoCreateDevice(DriverObject, 0, &dev, 0x22u, 0, 1u, &pDeviceObject);

	if (StatusCodeBuffer >= STATUS_SUCCESS)
	{
		StatusCodeBuffer = IoCreateSymbolicLink(&dos, &dev);

		if (StatusCodeBuffer >= STATUS_SUCCESS)
		{
			DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MajorFunctionControl;
			DriverObject->MajorFunction[IRP_MJ_CREATE] = MajorFunctionCreate;
			DriverObject->MajorFunction[IRP_MJ_CLOSE] = MajorFunctionClose;
			DriverObject->DriverUnload = UnloadDriver;

			if (StatusCodeBuffer >= STATUS_SUCCESS)
			{
				return StatusCodeBuffer;
			}

			IoDeleteSymbolicLink(&dos);
		}
	}

	if (pDeviceObject)
	{
		IoDeleteDevice(pDeviceObject);
	}

	return StatusCodeBuffer;
}