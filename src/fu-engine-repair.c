/*
 * Copyright (C) 2023 Kate Hsuan <hpa@redhat.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#define G_LOG_DOMAIN "FuEngine"

#include "config.h"

#include <fwupdplugin.h>

#include <fcntl.h>
#include <glib/gi18n.h>
#include <glib/gstdio.h>
#ifdef HAVE_GIO_UNIX
#include <gio/gunixfdlist.h>
#include <glib-unix.h>
#endif
#include <locale.h>
#include <stdlib.h>
#include <unistd.h>

#include "fu-console.h"
#include "fu-engine-repair.h"
#include "fu-engine.h"
#include "fu-plugin-private.h"
#include "fu-security-attr-common.h"
#include "fu-security-attrs-private.h"
#include "fu-util-common.h"

static gboolean
is_grubby_installed(GError **error)
{
	g_autofree gchar *grubby = NULL;

	grubby = fu_path_find_program("grubby", error);
	if (!grubby)
		return FALSE;

	return TRUE;
}

static gboolean
grubby_set(gboolean enable, const gchar *grubby_arg, GError **error)
{
	g_autofree gchar *output = NULL;
	g_autofree gchar *arg_string = NULL;
	const gchar *argv_grubby[] = {"", "--update-kernel=DEFAULT", "", NULL};
	g_autofree gchar *grubby = NULL;

	grubby = fu_path_find_program("grubby", NULL);
	argv_grubby[0] = grubby;

	if (enable)
		arg_string = g_strdup_printf("--args=%s", grubby_arg);
	else
		arg_string = g_strdup_printf("--remove-args=%s", grubby_arg);

	argv_grubby[2] = arg_string;

	if (!g_spawn_sync(NULL,
			  (gchar **)argv_grubby,
			  NULL,
			  G_SPAWN_DEFAULT,
			  NULL,
			  NULL,
			  &output,
			  NULL,
			  NULL,
			  error))
		return FALSE;

	return TRUE;
}

static gboolean
grubby_set_lockdown(gboolean enable, GError **error)
{
	g_autofree gchar *kernel_cmdline = NULL;
	gsize length;

	if (enable) {
		return grubby_set(TRUE, "lockdown=confidentiality", error);
	} else {
		if (!g_file_get_contents("/proc/cmdline", &kernel_cmdline, &length, error)) {
			g_set_error_literal(error,
					    FWUPD_ERROR_INTERNAL,
					    FWUPD_ERROR_READ,
					    "Fail on reading kernel parameter.");
			return FALSE;
		}

		if (!g_str_match_string("lockdown=", kernel_cmdline, TRUE)) {
			g_set_error_literal(
			    error,
			    FWUPD_ERROR_INTERNAL,
			    FWUPD_ERROR_READ,
			    "Can't be reverted since kernel lockdown was disabled.");
			return FALSE;
		}

		return grubby_set(FALSE, "lockdown=confidentiality", error);
	}
}

static gboolean
grubby_set_iommu(gboolean enable, GError **error)
{
	if (enable)
		return grubby_set(TRUE, "iommu=force", error);
	else
		return grubby_set(FALSE, "iommu=force", error);
}

static gboolean
fu_engine_repair_kernel_lockdown(FuEngine *engine, const gchar *action, GError **error)
{
	FuSecurityAttrs *attrs;
	FwupdSecurityAttr *attr;
	guint flags;

	attrs = fu_engine_get_host_security_attrs(engine);
	if (!attrs)
		return FALSE;

	attr = fu_security_attrs_get_by_appstream_id(attrs, FWUPD_SECURITY_ATTR_ID_UEFI_SECUREBOOT);
	if (!attr)
		return FALSE;

	flags = fwupd_security_attr_get_flags(attr);

	if (!g_strcmp0(action, "undo")) {
		if (flags == FWUPD_SECURITY_ATTR_FLAG_SUCCESS) {
			g_set_error_literal(
			    error,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    FWUPD_ERROR_NOTHING_TO_DO,
			    "Kernel lockdown can't be disabled when secure boot is enabled.");
			return FALSE;
		} else {
			return grubby_set_lockdown(FALSE, error);
		}
	}

	return grubby_set_lockdown(TRUE, error);
}

static gboolean
fu_engine_repair_iommu(const gchar *action, GError **error)
{
	g_autofree gchar *kernel_cmdline = NULL;
	gsize length = 0;

	if (!is_grubby_installed(error)) {
		g_set_error_literal(error,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    FWUPD_ERROR_NOTHING_TO_DO,
				    "Grubby was not installed.");
		return FALSE;
	}

	if (!g_file_get_contents("/proc/cmdline", &kernel_cmdline, &length, error)) {
		g_set_error_literal(error,
				    FWUPD_ERROR_INTERNAL,
				    FWUPD_ERROR_READ,
				    "Fail on reading kernel parameter.");
		return FALSE;
	}

	if (g_str_match_string("iommu=", kernel_cmdline, TRUE) ||
	    g_str_match_string("intel_iommu=", kernel_cmdline, TRUE) ||
	    g_str_match_string("amd_iommu=", kernel_cmdline, TRUE)) {
		g_set_error_literal(error,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    FWUPD_ERROR_NOTHING_TO_DO,
				    "IOMMU had been already set.");
		return FALSE;
	}

	if (!g_strcmp0(action, "undo"))
		return grubby_set_iommu(FALSE, error);

	return grubby_set_iommu(TRUE, error);
}

static gboolean
fu_engine_repair_or_unsupport(FuEngine *engine, const gchar *appstream_id, GError **error)
{
	FuSecurityAttrs *attrs;
	FwupdSecurityAttr *attr;
	GHashTable *settings = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	attrs = fu_engine_get_host_security_attrs(engine);
	if (!attrs)
		return FALSE;

	attr = fu_security_attrs_get_by_appstream_id(attrs, appstream_id);
	if (!attr)
		return FALSE;

	/* check fixable BIOS settings */
	if (fwupd_security_attr_get_bios_setting_id(attr) != NULL &&
	    fwupd_security_attr_get_bios_setting_current_value(attr) != NULL &&
	    fwupd_security_attr_get_bios_setting_target_value(attr) != NULL) {
		g_hash_table_insert(
		    settings,
		    g_strdup(fwupd_security_attr_get_bios_setting_id(attr)),
		    g_strdup(fwupd_security_attr_get_bios_setting_target_value(attr)));
		if (!fu_engine_modify_bios_settings(engine, settings, FALSE, error))
			return FALSE;

		return TRUE;
	}

	g_set_error_literal(error,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    FWUPD_ERROR_NOTHING_TO_DO,
			    "Repair item is not supported.");
	return FALSE;
}

gboolean
fu_engine_repair_do_undo(FuEngine *self, const gchar *key, const gchar *value, GError **error)
{
	if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_PREBOOT_DMA_PROTECTION)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_PREBOOT_DMA_PROTECTION,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_ENCRYPTED_RAM)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_ENCRYPTED_RAM,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_ENABLED)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_ENABLED,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_VERIFIED)) {
		return fu_engine_repair_or_unsupport(
		    self,
		    FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_VERIFIED,
		    error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_ACM)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_ACM,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_POLICY)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_POLICY,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_OTP)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_OTP,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_INTEL_CET_ENABLED)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_INTEL_CET_ENABLED,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_INTEL_CET_ACTIVE)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_INTEL_CET_ACTIVE,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_INTEL_SMAP)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_INTEL_SMAP,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_IOMMU)) {
		return fu_engine_repair_iommu (value, error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_KERNEL_LOCKDOWN)) {
		return fu_engine_repair_kernel_lockdown(self, value, error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_KERNEL_SWAP)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_KERNEL_SWAP,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_KERNEL_TAINTED)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_KERNEL_TAINTED,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_MEI_MANUFACTURING_MODE)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_MEI_MANUFACTURING_MODE,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_MEI_OVERRIDE_STRAP)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_MEI_OVERRIDE_STRAP,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_MEI_KEY_MANIFEST)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_MEI_KEY_MANIFEST,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_MEI_VERSION)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_MEI_VERSION,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_SPI_BIOSWE)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_SPI_BIOSWE,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_SPI_BLE)) {
		return fu_engine_repair_or_unsupport(self, FWUPD_SECURITY_ATTR_ID_SPI_BLE, error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_SPI_SMM_BWP)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_SPI_SMM_BWP,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_SPI_DESCRIPTOR)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_SPI_DESCRIPTOR,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_SUSPEND_TO_IDLE)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_SUSPEND_TO_IDLE,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_SUSPEND_TO_RAM)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_SUSPEND_TO_RAM,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_TPM_EMPTY_PCR)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_TPM_EMPTY_PCR,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_TPM_RECONSTRUCTION_PCR0)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_TPM_RECONSTRUCTION_PCR0,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_TPM_VERSION_20)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_TPM_VERSION_20,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_UEFI_SECUREBOOT)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_UEFI_SECUREBOOT,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_PLATFORM_DEBUG_ENABLED)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_PLATFORM_DEBUG_ENABLED,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_PLATFORM_FUSED)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_PLATFORM_FUSED,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_PLATFORM_DEBUG_LOCKED)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_PLATFORM_DEBUG_LOCKED,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_UEFI_PK)) {
		return fu_engine_repair_or_unsupport(self, FWUPD_SECURITY_ATTR_ID_UEFI_PK, error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_SUPPORTED_CPU)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_SUPPORTED_CPU,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_AMD_ROLLBACK_PROTECTION)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_AMD_ROLLBACK_PROTECTION,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_AMD_SPI_WRITE_PROTECTION)) {
		return fu_engine_repair_or_unsupport(
		    self,
		    FWUPD_SECURITY_ATTR_ID_AMD_SPI_WRITE_PROTECTION,
		    error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_AMD_SPI_REPLAY_PROTECTION)) {
		return fu_engine_repair_or_unsupport(
		    self,
		    FWUPD_SECURITY_ATTR_ID_AMD_SPI_REPLAY_PROTECTION,
		    error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_HOST_EMULATION)) {
		return fu_engine_repair_or_unsupport(self,
						     FWUPD_SECURITY_ATTR_ID_HOST_EMULATION,
						     error);
	} else if (!g_strcmp0(key, FWUPD_SECURITY_ATTR_ID_BIOS_ROLLBACK_PROTECTION)) {
		return fu_engine_repair_or_unsupport(
		    self,
		    FWUPD_SECURITY_ATTR_ID_BIOS_ROLLBACK_PROTECTION,
		    error);
	} else {
		g_set_error_literal(error,
				    FWUPD_ERROR_NOT_SUPPORTED,
				    FWUPD_ERROR_NOTHING_TO_DO,
				    "Repair item is not found.");
	}

	return FALSE;
}
