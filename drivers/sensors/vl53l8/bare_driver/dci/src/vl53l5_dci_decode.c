/*******************************************************************************
* Copyright (c) 2022, STMicroelectronics - All Rights Reserved
*
* This file is part of VL53L8 Kernel Driver and is dual licensed,
* either 'STMicroelectronics Proprietary license'
* or 'BSD 3-clause "New" or "Revised" License' , at your option.
*
********************************************************************************
*
* 'STMicroelectronics Proprietary license'
*
********************************************************************************
*
* License terms: STMicroelectronics Proprietary in accordance with licensing
* terms at www.st.com/sla0081
*
* STMicroelectronics confidential
* Reproduction and Communication of this document is strictly prohibited unless
* specifically authorized in writing by STMicroelectronics.
*
*
********************************************************************************
*
* Alternatively, VL53L8 Kernel Driver may be distributed under the terms of
* 'BSD 3-clause "New" or "Revised" License', in which case the following
* provisions apply instead of the ones mentioned above :
*
********************************************************************************
*
* License terms: BSD 3-clause "New" or "Revised" License.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
* this list of conditions and the following disclaimer in the documentation
* and/or other materials provided with the distribution.
*
* 3. Neither the name of the copyright holder nor the names of its contributors
* may be used to endorse or promote products derived from this software
* without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*
*******************************************************************************/

#include "vl53l5_dci_decode.h"
#include "vl53l5_dci_helpers.h"
#include "vl53l5_globals.h"
#include "vl53l5_driver_dev_path.h"
#include "vl53l5_platform_log.h"
#include "vl53l5_error_codes.h"
#include "dci_luts.h"
#include "vl53l5_decode_switch.h"
#include "vl53l5_core_dev_path.h"
#ifdef VL53L5_PATCH_DATA_ENABLED
#include "page_map_switch.h"
#endif

#define trace_print(level, ...) \
	_LOG_TRACE_PRINT(VL53L5_TRACE_MODULE_DCI, \
	level, VL53L5_TRACE_FUNCTION_ALL, ##__VA_ARGS__)

#define LOG_FUNCTION_START(fmt, ...) \
	_LOG_FUNCTION_START(VL53L5_TRACE_MODULE_DCI, fmt, ##__VA_ARGS__)

#define LOG_FUNCTION_END(status, ...) \
	_LOG_FUNCTION_END(VL53L5_TRACE_MODULE_DCI, status, ##__VA_ARGS__)

static int32_t _decode_raw_data(
	struct vl53l5_dev_handle_t *p_dev, uint8_t *p_buff,
	uint32_t buff_count, uint16_t *p_idx_checks, uint32_t num_idx_checks,
	bool is_range_data);

int32_t vl53l5_dci_decode_range_data(
	struct vl53l5_dev_handle_t *p_dev)
{
	int32_t status = VL53L5_ERROR_NONE;
	uint32_t read_size = 0;
	uint8_t *p_buff = NULL;

	LOG_FUNCTION_START("");

	if (VL53L5_ISNULL(p_dev)) {
		status = VL53L5_ERROR_INVALID_PARAMS;
		goto exit;
	}
	if (VL53L5_COMMS_BUFF_ISNULL(p_dev)) {
		status = VL53L5_ERROR_INVALID_PARAMS;
		goto exit;
	}

	read_size = RANGE_DATA_READ_SIZE(p_dev);

	if (p_dev->host_dev.revision_id == 0x0C) {
		read_size = RANGE_DATA_READ_SIZE(p_dev) + BYTE_4;
		p_buff = &RANGE_DATA_START(p_dev)[VL53L5_UI_DUMMY_BYTES];

	} else {
		p_buff = RANGE_DATA_START(p_dev);
	}

	if (read_size != VL53L5_COMMS_BUFF_COUNT(p_dev)) {
		trace_print(VL53L5_TRACE_LEVEL_ERRORS,
			"Rng data size %d does not match comms buff count %d\n",
			read_size,
			VL53L5_COMMS_BUFF_COUNT(p_dev));

		status = VL53L5_DATA_BUFFER_MISMATCH;
		goto exit;
	}

	status = _decode_raw_data(
		p_dev, p_buff, RANGE_DATA_SIZE(p_dev), NULL, 0, true);

exit:
	LOG_FUNCTION_END(status);
	return status;
}

int32_t vl53l5_dci_decode_data(
	struct vl53l5_dev_handle_t *p_dev,
	uint8_t *buffer,
	uint32_t data_size)
{
	int32_t status = VL53L5_ERROR_NONE;

	LOG_FUNCTION_START("");

	if (VL53L5_ISNULL(p_dev)) {
		status = VL53L5_ERROR_INVALID_PARAMS;
		goto exit;
	}
	if (VL53L5_ISNULL(buffer)) {
		status = VL53L5_ERROR_INVALID_PARAMS;
		goto exit;
	}

	status = _decode_raw_data(p_dev, buffer, data_size, NULL, 0, false);

exit:
	LOG_FUNCTION_END(status);
	return status;
}

static int32_t _decode_raw_data(
	struct vl53l5_dev_handle_t *p_dev, uint8_t *p_buff,
	uint32_t buff_count, uint16_t *p_idx_checks, uint32_t num_idx_checks,
	bool is_range_data)
{
	int32_t status = VL53L5_ERROR_NONE;
	uint8_t type = 0;
	uint32_t block_byte_size = 0;
	uint16_t idx = 0;
	uint32_t bytes_decoded = 0;

#ifdef VL53L5_PATCH_DATA_ENABLED
	uint16_t page_index = 0;
#endif

	(void)p_idx_checks;
	(void)num_idx_checks;
	do {
		trace_print(
			VL53L5_TRACE_LEVEL_DEBUG,
			"Decoding block header: [%02x][%02x][%02x][%02x]\n",
			p_buff[bytes_decoded],
			p_buff[bytes_decoded + 1],
			p_buff[bytes_decoded + 2],
			p_buff[bytes_decoded + 3]);

		status = vl53l5_dci_decode_block_header(
			&p_buff[bytes_decoded], buff_count - bytes_decoded,
			&type, &block_byte_size, &idx);
		if (status < STATUS_OK)
			goto exit;

		if (type == DCI_BH__P_TYPE__END_OF_DATA)
			break;

		if ((type == DCI_BH__P_TYPE__GRP_PARAMS_START) ||
				(type == DCI_BH__P_TYPE__GRP_PARAMS_END)) {

			if ((!is_range_data) && (idx > MAX_NUM_RANGE_RETURNS)) {
				status = VL53L5_INVALID_GROUP_INDEX;
				goto exit;
			}

			bytes_decoded += BYTE_4;

			continue;
		}

		if (type == 0xC) {
#ifdef VL53L5_PATCH_DATA_ENABLED

			page_index = idx;
#else

			if (!is_range_data) {
				status = VL53L5_INVALID_PAGE_ERROR;
				goto exit;
			}

			if (idx != 0) {
				status = VL53L5_INVALID_PAGE_ERROR;
				goto exit;
			}
#endif

			bytes_decoded += BYTE_4;

			continue;
		}

		bytes_decoded += BYTE_4;

#ifdef VL53L5_PATCH_DATA_ENABLED

		status = dci_page_map_switch(idx,
					     block_byte_size,
					     &p_buff[bytes_decoded],
					     p_dev,
					     page_index);
#else
		status = vl53l5_decode_switch(
			idx, block_byte_size, &p_buff[bytes_decoded], p_dev);
#endif
		if (status < STATUS_OK)
			goto exit;

		bytes_decoded += block_byte_size;

	} while (bytes_decoded < buff_count);

	if (type != DCI_BH__P_TYPE__END_OF_DATA) {
		status = VL53L5_DCI_END_BLOCK_ERROR;
		goto exit;
	}

exit:
	return status;
}
