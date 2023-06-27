/*
 * Copyright (C) 2017 Kate Hsuan <hpa@redhat.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <fwupdplugin.h>

#include "fwupd-security-attr-private.h"

#include "fu-engine.h"

/**
 * FuEngineSecurityAction:
 * @FU_ENGINE_SECURITY_HARDEN_SET:		Perform the hardening action
 * @FU_ENGINE_SECURITY_HARDEN_UNSET:		Cancel the hardening action
 *
 * The flags to use when calculating an HSI version.
 **/
typedef enum {
	FU_ENGINE_SECURITY_HARDEN_SET = 0,
	FU_ENGINE_SECURITY_HARDEN_UNSET = 1 << 0,
} FuEngineSecurityAction;

gboolean
fu_engine_security_harden(FuEngine *self, const gchar *key, const gchar *value, GError **error);
