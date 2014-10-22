/*****************************************************************************
** Copyright (C) 2014 Secure Systems Group.                                 **
** Copyright (C) 2014 Intel Corporation.                                    **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <zlib.h>

#include "com_protocol.h"
#include "tee_logging.h"

static const uint32_t COM_MSG_START = 0xABCDEF12;
#define TRY_READ_FD_COUNT 5
#define ELEMENTS_IN_MESSAGE 2

/* Transport information */
struct com_trasnport_info {
	uint64_t checksum;
	uint32_t start;
	uint32_t data_len; /* data_len: user message length */
} __attribute__ ((aligned));

static int read_iov_element(int fd, struct iovec *iov)
{
	int read_bytes = 0;

	while (1) {

		read_bytes = readv(fd, iov, 1);

		if (read_bytes == -1) {

			if (errno == EINTR)
				continue;

			OT_LOG(LOG_ERR, "read error");
			return -1;
		}
	}

	return read_bytes;
}

int com_recv_msg(int sockfd, void **msg, int *msg_len)
{
	struct iovec iov[ELEMENTS_IN_MESSAGE];
	int ret;
	struct com_trasnport_info com_recv_trans_info;

	if (!*msg || !msg_len) {
		OT_LOG(LOG_ERR, "Invalid parameters")
		return 1;
	}

	/* Set NULL, because then can use ERR-goto and not refering unmalloced memory */
	*msg = NULL;

	/*Transport capsule */
	iov[0].iov_base = &com_recv_trans_info;
	iov[0].iov_len = sizeof(struct com_trasnport_info);

	/* Read transport capsule */
	if (read_iov_element(sockfd, &iov[0]) == -1) {
		OT_LOG(LOG_ERR, "Problem with reading transport capsule");
		goto err;
	}

	/* Transport information read. Verify bit sequence */
	if (com_recv_trans_info.start != COM_MSG_START) {
		OT_LOG(LOG_ERR, "Read data is not beginning correctly");
		goto err;
	}

	/* Malloc space for incomming message and read message */
	*msg_len = com_recv_trans_info.data_len;
	*msg = malloc(*msg_len);
	if (!*msg) {
		OT_LOG(LOG_ERR, "Out of memory");
		ret = 1;
		goto err;
	}

	iov[1].iov_base = *msg;
	iov[1].iov_len = *msg_len;

	if (read_iov_element(sockfd, &iov[1]) == -1) {
		OT_LOG(LOG_ERR, "Problem with reading msg");
		goto err;
	}

	/* Calculate and verify checksum */
	if (com_recv_trans_info.checksum != crc32(0, *msg, *msg_len)) {
		OT_LOG(LOG_ERR, "Message checksum is not matching, discard msg");
		goto err;
	}

	return 0;

err:
	free(*msg); /* Discardin msg */
	*msg_len = 0;
	*msg = NULL;
	return ret;
}

int com_send_msg(int sockfd, void *msg, int msg_len)
{
	struct iovec iov[ELEMENTS_IN_MESSAGE];
	int bytes_write;
	struct com_trasnport_info com_trans_info;

	if (!msg) {
		OT_LOG(LOG_ERR, "message null");
		return -1;
	}

	/* Fill and calculate transport information */
	com_trans_info.start = COM_MSG_START;
	com_trans_info.data_len = msg_len;
	com_trans_info.checksum = crc32(0, msg, msg_len);

	iov[0].iov_base = &com_trans_info;
	iov[0].iov_len = sizeof(struct com_trasnport_info);

	iov[1].iov_base = msg;
	iov[1].iov_len = msg_len;

	/* Send message */
	while (1) {

		bytes_write = writev(sockfd, iov, ELEMENTS_IN_MESSAGE);
		if (bytes_write == -1) {
			if (errno == EINTR)
				continue;

			OT_LOG(LOG_ERR, "send error");
			return -1;
		}
	}

	return bytes_write - sizeof(struct com_trasnport_info);
}

uint8_t com_get_msg_name(void *msg)
{
	/* Not the most optimized operation, but I do not know a better way than
	 * a "hardcoded" solution. */

	struct com_msg_hdr msg_hdr;

	if (!msg) {
		OT_LOG(LOG_ERR, "message null");
		return -1;
	}

	memcpy(&msg_hdr, msg, sizeof(struct com_msg_hdr));
	return msg_hdr.msg_name;
}

uint8_t com_get_msg_type(void *msg)
{
	struct com_msg_hdr msg_hdr;

	if (!msg) {
		OT_LOG(LOG_ERR, "message null");
		return -1;
	}

	memcpy(&msg_hdr, msg, sizeof(struct com_msg_hdr));
	return msg_hdr.msg_type;
}

uint64_t com_get_msg_sess_id(void *msg)
{
	struct com_msg_hdr msg_hdr;

	if (!msg) {
		OT_LOG(LOG_ERR, "message null");
		return -1;
	}

	memcpy(&msg_hdr, msg, sizeof(struct com_msg_hdr));
	return msg_hdr.sess_id;
}
