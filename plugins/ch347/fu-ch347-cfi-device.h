/*
 * Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <fwupdplugin.h>

#define FU_TYPE_CH347_CFI_DEVICE (fu_ch347_cfi_device_get_type())
G_DECLARE_FINAL_TYPE(FuCh347CfiDevice, fu_ch347_cfi_device, FU, CH347_CFI_DEVICE, FuCfiDevice)
