/*
 * Copyright (C) 2021 Synaptics Incorporated <simon.ho@synaptics.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>

#include <string.h>

#include "fu-synaptics-cape-firmware.h"

typedef struct __attribute__((packed)) {
	guint32 data[8];
} FuCapeHidFwCmdUpdateWritePar;

struct _FuSynapticsCapeFirmware {
	FuFirmware parent_instance;
	guint16 vid;
	guint16 pid;
};

G_DEFINE_TYPE(FuSynapticsCapeFirmware, fu_synaptics_cape_firmware, FU_TYPE_FIRMWARE)

guint16
fu_synaptics_cape_firmware_get_vid(FuSynapticsCapeFirmware *self)
{
	g_return_val_if_fail(FU_IS_SYNAPTICS_CAPE_FIRMWARE(self), 0);
	return self->vid;
}

guint16
fu_synaptics_cape_firmware_get_pid(FuSynapticsCapeFirmware *self)
{
	g_return_val_if_fail(FU_IS_SYNAPTICS_CAPE_FIRMWARE(self), 0);
	return self->pid;
}

static void
fu_synaptics_cape_firmware_export(FuFirmware *firmware,
				  FuFirmwareExportFlags flags,
				  XbBuilderNode *bn)
{
	FuSynapticsCapeFirmware *self = FU_SYNAPTICS_CAPE_FIRMWARE(firmware);
	fu_xmlb_builder_insert_kx(bn, "vid", self->vid);
	fu_xmlb_builder_insert_kx(bn, "pid", self->pid);
}

static gboolean
fu_synaptics_cape_firmware_parse(FuFirmware *firmware,
				 GBytes *fw,
				 gsize offset,
				 FwupdInstallFlags flags,
				 GError **error)
{
	FuSynapticsCapeFirmware *self = FU_SYNAPTICS_CAPE_FIRMWARE(firmware);
	gsize bufsz = 0x0;
	gsize offset_local = offset;
	guint16 version_w = 0;
	guint16 version_x = 0;
	guint16 version_y = 0;
	guint16 version_z = 0;
	const guint8 *buf = g_bytes_get_data(fw, &bufsz);
	g_autofree gchar *version_str = NULL;
	g_autoptr(FuFirmware) img_hdr = fu_firmware_new();
	g_autoptr(GBytes) fw_body = NULL;
	g_autoptr(GBytes) fw_hdr = NULL;

	/* check alignment */
	if ((guint32)bufsz % 4 != 0) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_INVALID_FILE,
				    "data not aligned to 32 bits");
		return FALSE;
	}
	if (!fu_struct_unpack_from("<[LLLLL]",
				   error,
				   buf,
				   bufsz,
				   &offset,
				   &self->vid,
				   &self->pid,
				   NULL,  /* firmware update type */
				   NULL,  /* firmware identifier */
				   NULL)) /* crc value */
		return FALSE;
	fw_hdr = fu_bytes_new_offset(fw, offset_local, offset - offset_local, error);
	if (fw_hdr == NULL)
		return FALSE;
	fu_firmware_set_id(img_hdr, FU_FIRMWARE_ID_HEADER);
	fu_firmware_set_bytes(img_hdr, fw_hdr);
	fu_firmware_add_image(firmware, img_hdr);

	if (!fu_struct_unpack_from("<[HHHHL]",
				   error,
				   buf,
				   bufsz,
				   &offset,
				   &version_w,
				   &version_x,
				   &version_y,
				   &version_z,
				   NULL)) /* reserved3 */
		return FALSE;
	version_str = g_strdup_printf("%u.%u.%u.%u", version_z, version_y, version_x, version_w);
	fu_firmware_set_version(FU_FIRMWARE(self), version_str);

	/* body */
	fw_body = fu_bytes_new_offset(fw, offset, bufsz - offset, error);
	if (fw_body == NULL)
		return FALSE;
	fu_firmware_set_id(firmware, FU_FIRMWARE_ID_PAYLOAD);
	fu_firmware_set_bytes(firmware, fw_body);
	return TRUE;
}

static GBytes *
fu_synaptics_cape_firmware_write(FuFirmware *firmware, GError **error)
{
	FuSynapticsCapeFirmware *self = FU_SYNAPTICS_CAPE_FIRMWARE(firmware);
	guint64 ver = fu_firmware_get_version_raw(firmware);
	g_autoptr(GByteArray) buf = g_byte_array_new();
	g_autoptr(GBytes) payload = NULL;

	/* header */
	fu_byte_array_append_uint32(buf, self->vid, G_LITTLE_ENDIAN);
	fu_byte_array_append_uint32(buf, self->pid, G_LITTLE_ENDIAN);
	fu_byte_array_append_uint32(buf, 0x0, G_LITTLE_ENDIAN);	      /* update type */
	fu_byte_array_append_uint32(buf, 0x0, G_LITTLE_ENDIAN);	      /* identifier */
	fu_byte_array_append_uint32(buf, 0xffff, G_LITTLE_ENDIAN);    /* crc_value */
	fu_byte_array_append_uint16(buf, ver >> 0, G_LITTLE_ENDIAN);  /* version w */
	fu_byte_array_append_uint16(buf, ver >> 16, G_LITTLE_ENDIAN); /* version x */
	fu_byte_array_append_uint16(buf, ver >> 32, G_LITTLE_ENDIAN); /* version y */
	fu_byte_array_append_uint16(buf, ver >> 48, G_LITTLE_ENDIAN); /* version z */
	fu_byte_array_append_uint32(buf, 0x0, G_LITTLE_ENDIAN);	      /* reserved */

	/* payload */
	payload = fu_firmware_get_bytes_with_patches(firmware, error);
	if (payload == NULL)
		return NULL;
	fu_byte_array_append_bytes(buf, payload);
	fu_byte_array_align_up(buf, FU_FIRMWARE_ALIGNMENT_32, 0xFF);

	return g_byte_array_free_to_bytes(g_steal_pointer(&buf));
}

static gboolean
fu_synaptics_cape_firmware_build(FuFirmware *firmware, XbNode *n, GError **error)
{
	FuSynapticsCapeFirmware *self = FU_SYNAPTICS_CAPE_FIRMWARE(firmware);
	guint64 tmp;

	/* optional properties */
	tmp = xb_node_query_text_as_uint(n, "vid", NULL);
	if (tmp != G_MAXUINT64 && tmp <= G_MAXUINT16)
		self->vid = tmp;
	tmp = xb_node_query_text_as_uint(n, "pid", NULL);
	if (tmp != G_MAXUINT64 && tmp <= G_MAXUINT16)
		self->pid = tmp;

	/* success */
	return TRUE;
}

static void
fu_synaptics_cape_firmware_init(FuSynapticsCapeFirmware *self)
{
	fu_firmware_add_flag(FU_FIRMWARE(self), FU_FIRMWARE_FLAG_HAS_VID_PID);
}

static void
fu_synaptics_cape_firmware_class_init(FuSynapticsCapeFirmwareClass *klass)
{
	FuFirmwareClass *klass_firmware = FU_FIRMWARE_CLASS(klass);
	klass_firmware->parse = fu_synaptics_cape_firmware_parse;
	klass_firmware->export = fu_synaptics_cape_firmware_export;
	klass_firmware->write = fu_synaptics_cape_firmware_write;
	klass_firmware->build = fu_synaptics_cape_firmware_build;
}

FuFirmware *
fu_synaptics_cape_firmware_new(void)
{
	return FU_FIRMWARE(g_object_new(FU_TYPE_SYNAPTICS_CAPE_FIRMWARE, NULL));
}
