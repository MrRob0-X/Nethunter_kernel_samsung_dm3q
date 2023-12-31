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

#include "vl53l5_api_ranging.h"
#include "vl53l5_globals.h"
#include "vl53l5_dci_core.h"
#include "vl53l5_dci_ranging.h"
#include "vl53l5_driver_dev_path.h"
#include "vl53l5_dci_utils.h"
#include "vl53l5_error_codes.h"
#include "vl53l5_platform_log.h"

#define trace_print(level, ...) \
	_LOG_TRACE_PRINT(VL53L5_TRACE_MODULE_API, \
	level, VL53L5_TRACE_FUNCTION_ALL, ##__VA_ARGS__)
#define LOG_FUNCTION_START(fmt, ...) \
	_LOG_FUNCTION_START(VL53L5_TRACE_MODULE_API, fmt, ##__VA_ARGS__)
#define LOG_FUNCTION_END(status, ...) \
	_LOG_FUNCTION_END(VL53L5_TRACE_MODULE_API, status, ##__VA_ARGS__)
#define LOG_FUNCTION_END_FLUSH(status, ...) \
	do { \
	_LOG_FUNCTION_END(VL53L5_TRACE_MODULE_API, status, ##__VA_ARGS__);\
	_FLUSH_TRACE_TO_OUTPUT();\
	} while (0)

int32_t vl53l5_check_data_ready(struct vl53l5_dev_handle_t *p_dev)
{
	int32_t status = STATUS_OK;
	uint8_t stored_stream_id = 0;

	LOG_FUNCTION_START("");

	if (VL53L5_ISNULL(p_dev)) {
		status = VL53L5_ERROR_INVALID_PARAMS;
		goto exit;
	}
	if (VL53L5_COMMS_BUFF_ISNULL(p_dev)) {
		status = VL53L5_ERROR_INVALID_PARAMS;
		goto exit;
	}

	status = VL53L5_GET_VERSION_CHECK_STATUS(p_dev);
	if (status < STATUS_OK)
		goto exit;

	stored_stream_id = VL53L5_UI_DEV_STREAM(p_dev);

	status = vl53l5_dci_get_device_info(p_dev);
	if (status < STATUS_OK)

		goto exit_reset_stream_id;

	status = vl53l5_dci_check_device_info(p_dev,
					      stored_stream_id,
					      true,
					      true);
	if (status == VL53L5_TOO_HIGH_AMBIENT_WARNING)
		goto exit;

exit_reset_stream_id:

	VL53L5_UI_DEV_STREAM(p_dev) = stored_stream_id;

exit:
	switch (status) {
	case VL53L5_NO_NEW_RANGE_DATA_ERROR:
	case VL53L5_TOO_HIGH_AMBIENT_WARNING:

	case STATUS_OK:

		LOG_FUNCTION_END(status);
		break;
	default:

		LOG_FUNCTION_END_FLUSH(status);
		break;
	}

	return status;
}

int32_t vl53l5_get_range_data(
	struct vl53l5_dev_handle_t *p_dev)
{
	int32_t status = VL53L5_ERROR_NONE;

	if (VL53L5_ISNULL(p_dev)) {
		status = VL53L5_ERROR_INVALID_PARAMS;
		goto exit;
	}
	if (VL53L5_COMMS_BUFF_ISNULL(p_dev)) {
		status = VL53L5_ERROR_INVALID_PARAMS;
		goto exit;
	}

	status = VL53L5_GET_VERSION_CHECK_STATUS(p_dev);

	if (status < STATUS_OK)
		goto exit;

	status = vl53l5_dci_read_range(p_dev);

exit:
	LOG_FUNCTION_END_FLUSH(status);
	return status;
}
