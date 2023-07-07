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
	FuPlugin *plugin;
	gboolean ret = FALSE;
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

	plugin = fu_engine_get_plugin_by_name(engine, fwupd_security_attr_get_plugin(attr), error);
	if (plugin)
		ret = fu_plugin_runner_security_remediation(plugin, enable, attr, error);

	if (ret) {
		return TRUE;
	} else if (g_error_matches(*error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED)) {
		g_clear_error(error);
	} else {
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
fu_engine_security_harden(FuEngine *engine,
			  const gchar *appstream_id,
			  gboolean enable,
			  GError **error)
{
	g_autoptr(GPtrArray) attrs_array = NULL;
	FuSecurityAttrs *attrs;

	/* for those BIOS fixes and unsupported items */
	attrs = fu_engine_get_host_security_attrs(engine);
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
			return fu_engine_security_remediation(engine,
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
