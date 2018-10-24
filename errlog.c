/*
 * errlog.c
 * Copyright 2017 Peter Jones <pjones@redhat.com>
 *
 * Distributed under terms of the GPLv3 license.
 */

#include "shim.h"

static CHAR16 **errs = NULL;
static UINTN nerrs = 0;

EFI_STATUS
VLogError(const char *file, int line, const char *func, CHAR16 *fmt, va_list args)
{
	va_list args2;
	CHAR16 **newerrs;
	CHAR16 *firstBuffer;
	CHAR16 *secondBuffer;
	const UINTN fixedMessageSize = 128 * sizeof(CHAR16);

	/*
	 * Kaspersky Lab Patch.
	 *
	 * Note that implementation of SPrint (and VSPrint respectively):
	 *     1. Does not check pointer to NULL, so given buffer always considered valid.
	 *     2. Interprets zero length as buffer without limitation.
	 * So SPrint(NULL, 0, ...) is **not** valid call and overwrites bottom memory.
	 *
	 * Also first call of VLogError() causes ReallocatePool(NULL, sizeof(CHAR16*), 3 * sizeof(CHAR16*)).
	 * Although ReallocatePool() checks source pointer to NULL before copying, this use case is error-prone.
	 *
	 * Also fixed memory leaks.
	 */

	firstBuffer = AllocateZeroPool(fixedMessageSize);
	if (!firstBuffer)
	{
		return EFI_OUT_OF_RESOURCES;
	}

	secondBuffer = AllocateZeroPool(fixedMessageSize);
	if (!secondBuffer)
	{
		FreePool(firstBuffer);
		return EFI_OUT_OF_RESOURCES;
	}

	if (!nerrs)
	{
		newerrs = AllocatePool(3 * sizeof(*errs));
	}
	else
	{
		newerrs = ReallocatePool(errs,
		                        (nerrs + 1) * sizeof(*errs),
		                        (nerrs + 3) * sizeof(*errs));
	}

	if (!newerrs)
	{
		FreePool(firstBuffer);
		FreePool(secondBuffer);
		return EFI_OUT_OF_RESOURCES;
	}

	newerrs[nerrs] = firstBuffer;
	newerrs[nerrs+1] = secondBuffer;

	SPrint(newerrs[nerrs], fixedMessageSize, L"%a:%d %a() ", file, line, func);
	va_copy(args2, args);
	VSPrint(newerrs[nerrs+1], fixedMessageSize, fmt, args2);
	va_end(args2);

	nerrs += 2;
	newerrs[nerrs] = NULL;
	errs = newerrs;

	return EFI_SUCCESS;
}

EFI_STATUS
LogError_(const char *file, int line, const char *func, CHAR16 *fmt, ...)
{
	va_list args;
	EFI_STATUS efi_status;

	va_start(args, fmt);
	efi_status = VLogError(file, line, func, fmt, args);
	va_end(args);

	return efi_status;
}

VOID
PrintErrors(VOID)
{
	UINTN i;

	if (!verbose)
		return;

	for (i = 0; i < nerrs; i++)
		console_print(L"%s", errs[i]);
}

VOID
ClearErrors(VOID)
{
	UINTN i;

	for (i = 0; i < nerrs; i++)
		FreePool(errs[i]);
	FreePool(errs);
	nerrs = 0;
	errs = NULL;
}

// vim:fenc=utf-8:tw=75
