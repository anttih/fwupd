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
#include "fu-engine-security.h"
#include "fu-engine.h"
#include "fu-plugin-private.h"
#include "fu-security-attr-common.h"
#include "fu-security-attrs-private.h"
#include "fu-util-common.h"

static gboolean
grubby_set_lockdown(const gchar *grubby, gboolean enable, GError **error)
{
	if (enable)
		return fu_kernel_set_commandline(grubby, TRUE, "lockdown=confidentiality", error);
	else
		return fu_kernel_set_commandline(grubby, FALSE, "lockdown=confidentiality", error);
}

static gboolean
grubby_set_iommu(const gchar *grubby, gboolean enable, GError **error)
{
	if (enable)
		return fu_kernel_set_commandline(grubby, TRUE, "iommu=force", error);
	else
		return fu_kernel_set_commandline(grubby, FALSE, "iommu=force", error);
}

static gboolean
fu_engine_security_kernel_lockdown(FuEngine *engine, gboolean enable, GError **error)
{
	g_autofree gchar *grubby = NULL;
	g_autoptr(GHashTable) kernel_param = NULL;
	FuSecurityAttrs *attrs;
	FwupdSecurityAttr *attr;
	guint flags;

	grubby = fu_kernel_get_grubby_path(error);
	if (grubby == NULL)
		return FALSE;

	kernel_param = fu_kernel_get_cmdline(error);
	if (kernel_param == NULL)
		return FALSE;

	attrs = fu_engine_get_host_security_attrs(engine);
	if (attrs == NULL) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INTERNAL,
				    "Fail on getting security attributes.");
		return FALSE;
	}

	attr = fu_security_attrs_get_by_appstream_id(attrs, FWUPD_SECURITY_ATTR_ID_UEFI_SECUREBOOT);
	if (attr == NULL) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_READ,
				    "Secure boot attribute can't be found.");
		return FALSE;
	}

	flags = fwupd_security_attr_get_flags(attr);

	switch (enable) {
	case TRUE:
		if (g_hash_table_contains(kernel_param, "lockdown")) {
			g_set_error_literal(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_READ,
					    "Kernel lockdown has already been enabled.");
			return FALSE;
		}
		return grubby_set_lockdown(grubby, TRUE, error);
		break;

	case FALSE:
		if (flags == FWUPD_SECURITY_ATTR_FLAG_SUCCESS) {
			g_set_error_literal(
			    error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOTHING_TO_DO,
			    "Kernel lockdown can't be disabled when secure boot is enabled.");
			return FALSE;
		} else {
			if (!g_hash_table_contains(kernel_param, "lockdown")) {
				g_set_error_literal(
				    error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_READ,
				    "Can't be reverted since kernel lockdown was disabled.");
				return FALSE;
			}
			return grubby_set_lockdown(grubby, FALSE, error);
		}
		break;

	default:
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INTERNAL,
				    "Incorrect action setting.");
		return FALSE;
	}
}

static gboolean
fu_engine_security_iommu_remediation(gboolean enable, GError **error)
{
	g_autofree gchar *grubby = NULL;
	g_autoptr(GHashTable) kernel_param = NULL;
	gchar *value = NULL;

	grubby = fu_path_find_program("grubby", error);
	if (!grubby)
		return FALSE;

	kernel_param = fu_kernel_get_cmdline(error);
	if (!kernel_param) {
		return FALSE;
	}

	switch (enable) {
	case TRUE:
		if (g_hash_table_contains(kernel_param, "iommu") ||
		    g_hash_table_contains(kernel_param, "intel_iommu") ||
		    g_hash_table_contains(kernel_param, "amd_iommu")) {
			g_set_error_literal(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_NOTHING_TO_DO,
					    "IOMMU had been already set.");
			return FALSE;
		}

		return grubby_set_iommu(grubby, TRUE, error);
		break;

	case FALSE:
		value = g_hash_table_lookup(kernel_param, "iommu");
		if (!value) {
			g_set_error_literal(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_NOTHING_TO_DO,
					    "IOMMU was not set.");
			return FALSE;
		}

		if (g_strcmp0(value, "force\n")) {
			g_set_error_literal(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_NOTHING_TO_DO,
					    "IOMMU was not set to \"force\"");
			return FALSE;
		}

		return grubby_set_iommu(grubby, FALSE, error);
		break;

	default:
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INTERNAL,
				    "Incorrect action setting.");
		return FALSE;
	}
}

static gboolean
fu_engine_security_bios_setting_revert(FuEngine *engine,
				       const gchar *appstream_id,
				       const gchar *bios_id,
				       const gchar *current_value,
				       GError **error)
{
	g_autofree gchar *previous_setting = NULL;
	g_autoptr(GHashTable) settings =
	    g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	previous_setting =
	    fu_engine_get_previous_bios_setting(engine, appstream_id, current_value, error);
	if (!previous_setting)
		return FALSE;

	g_hash_table_insert(settings, g_strdup(bios_id), g_strdup(previous_setting));

	if (!fu_engine_modify_bios_settings(engine, settings, FALSE, error))
		return FALSE;

	return TRUE;
}

static gboolean
fu_engine_security_remediation(FuEngine *engine,
			       FuSecurityAttrs *attrs,
			       const gchar *appstream_id,
			       gboolean enable,
			       GError **error)
{
	FwupdSecurityAttr *attr;
	g_autoptr(GHashTable) settings =
	    g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	attr = fu_security_attrs_get_by_appstream_id(attrs, appstream_id);
	if (!attr) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INTERNAL,
				    "Attribute was not found");
		return FALSE;
	}

	/* find fixable BIOS settings */
	if (fwupd_security_attr_get_bios_setting_id(attr) != NULL &&
	    fwupd_security_attr_get_bios_setting_current_value(attr) != NULL &&
	    fwupd_security_attr_get_bios_setting_target_value(attr) != NULL) {
		switch (enable) {
		case TRUE:
			g_hash_table_insert(
			    settings,
			    g_strdup(fwupd_security_attr_get_bios_setting_id(attr)),
			    g_strdup(fwupd_security_attr_get_bios_setting_target_value(attr)));
			if (!fu_engine_modify_bios_settings(engine, settings, FALSE, error))
				return FALSE;

			return TRUE;
			break;

		case FALSE:
			return fu_engine_security_bios_setting_revert(
			    engine,
			    appstream_id,
			    fwupd_security_attr_get_bios_setting_id(attr),
			    fwupd_security_attr_get_bios_setting_current_value(attr),
			    error);
			break;

		default:
			g_set_error_literal(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_INTERNAL,
					    "Incorrect action setting.");
			return FALSE;
		}
	}

	g_set_error_literal(error,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    FWUPD_ERROR_NOTHING_TO_DO,
			    "Repair item is not supported.");
	return FALSE;
}

gboolean
fu_engine_security_harden(FuEngine *self,
			  const gchar *appstream_id,
			  gboolean enable,
			  GError **error)
{
	g_autoptr(GPtrArray) attrs_array = NULL;
	FuSecurityAttrs *attrs;

	/* dedicated treatment */
	if (!g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_IOMMU)) {
		return fu_engine_security_iommu_remediation(enable, error);
	} else if (!g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_KERNEL_LOCKDOWN)) {
		return fu_engine_security_kernel_lockdown(self, enable, error);
	}

	/* for those BIOS fixes and unsupported items */
	attrs = fu_engine_get_host_security_attrs(self);
	if (!attrs) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INTERNAL,
				    "Fail on getting security attributes.");
		return FALSE;
	}

	attrs_array = fu_security_attrs_get_all(attrs);

	for (guint i = 0; i < attrs_array->len; i++) {
		FwupdSecurityAttr *attr = g_ptr_array_index(attrs_array, i);
		const gchar *appstream_tmp = fwupd_security_attr_get_appstream_id(attr);
		if (!g_strcmp0(appstream_id, appstream_tmp)) {
			return fu_engine_security_remediation(self,
							      attrs,
							      appstream_id,
							      enable,
							      error);
		}
	}

	/* for unknown Appstream IDs */
	g_set_error_literal(error,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    FWUPD_ERROR_NOTHING_TO_DO,
			    "Repair item is not found.");
	return FALSE;
}
