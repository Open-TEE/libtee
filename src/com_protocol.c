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

#include <sys/ioctl.h>
#include <stdlib.h>
#include <zlib.h>
#include <string.h>
#include <errno.h>
#include <sys/select.h>

#include "com_protocol.h"
#include "tee_logging.h"

static const uint32_t COM_MSG_START = 0xABCDEF12;
#define TRY_READ_FD_COUNT 5

/* Transport information */
struct com_trasnport_info {
	uint64_t checksum;
	uint32_t start;
	uint32_t data_len; /* data_len: user message length */
} __attribute__ ((aligned));

static int read_all(int fd, void *buf, int buf_len)
{
	int total_read_bytes = 0, read_bytes = 0, i = 0;
	fd_set set;
	struct timeval timeout;
	int select_ret;

	FD_ZERO(&set);
	FD_SET(fd, &set);

	for (i = 0; (i < TRY_READ_FD_COUNT && total_read_bytes < buf_len); ++i) {

		timeout.tv_sec = 2;
		timeout.tv_usec = 0;

		select_ret = select(fd + 1, &set, NULL, NULL, &timeout);
		if (select_ret == -1) {
			if (errno == EINTR) {
				i--;
				continue;
			}

			return -1;

		} else if (select_ret == 0) {
			continue;

		} else {
			read_bytes = read(fd, ((unsigned char *)buf) + total_read_bytes,
					  buf_len - total_read_bytes);

			if (read_bytes == -1) {

				if (errno == EINTR) {
					i--;
					continue;
				}

				OT_LOG(LOG_ERR, "read error");
				return -1;
			}

			total_read_bytes += read_bytes;
		}
	}

	return total_read_bytes;
}

static int write_all(int fd, void *buf, int buf_len)
{
	int total_written_bytes = 0;
	int written_bytes = 0;

	while (total_written_bytes < buf_len) {

		written_bytes = write(fd, ((unsigned char *)buf) + total_written_bytes,
				      buf_len - total_written_bytes);

		if (written_bytes == -1) {
			OT_LOG(LOG_ERR, "write error");
			return written_bytes;
		}

		total_written_bytes += written_bytes;
	}

	return total_written_bytes;
}

static int reset_socket(int sockfd)
{
	int bytes_availible, ret;
	void *discard_buf = NULL;

	/* Temporary solution. See comment in com_recv_msg(). Malloc function
	 * will make this function simpler than round-buffer-solutions */

	if (ioctl(sockfd, FIONREAD, &bytes_availible) == -1) {
		OT_LOG(LOG_ERR, "IOCTL error");
		if (errno == EBADF)
			return -1;
		return 0; /* Lets hope this will clear it self */
	}

	discard_buf = malloc(bytes_availible);
	if (!discard_buf) {
		OT_LOG(LOG_ERR, "out of memory");
		return 0; /* Lets hope this will clear it self */
	}

	ret = read_all(sockfd, discard_buf, bytes_availible);
	free(discard_buf);

	/* If we had partial read, ignore and hope that it clear by it self */
	return ret == bytes_availible ? 0 : ret;
}

int com_recv_msg(int sockfd, void **msg, int *msg_len)
{
	int ret;
	struct com_trasnport_info com_recv_trans_info;

	if (!*msg_len || !msg_len) {
		OT_LOG(LOG_ERR, "Invalid parameters")
		return 1;
	}

	/* TODO: Wind socket to correct starting point. Previous read might gone bad and therefore
	 * there might be data and it is not starting correct sequence. Current solution might
	 * discard/ignore/not notice messages from socket! */

	/* Read transport capsule */
	ret = read_all(sockfd, &com_recv_trans_info, sizeof(struct com_trasnport_info));
	if (ret != sizeof(struct com_trasnport_info)) {
		/* We did have an IO error or there was not enough data at fd */
		OT_LOG(LOG_ERR, "read -1 or corrupted messge");
		goto err;
	}

	/* Transport information read. Verify bit sequence */
	if (com_recv_trans_info.start != COM_MSG_START) {
		OT_LOG(LOG_ERR, "Read data is not beginning correctly");
		ret = reset_socket(sockfd);
		if (ret == 0)
			ret = 1; /* Socket OK, but message was not read -> 1 */

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

	ret = read_all(sockfd, *msg, *msg_len);
	if (ret != *msg_len) {
		OT_LOG(LOG_ERR, "read -1 or corrupted messge");
		ret = reset_socket(sockfd);
		if (ret == 0)
			ret = 1; /* Socket OK, but message was not read -> 1 */

		goto err;
	}

	/* Calculate and verify checksum */
	if (com_recv_trans_info.checksum != crc32(0, *msg, *msg_len)) {
		OT_LOG(LOG_ERR, "Message checksum is not matching, discard msg");
		ret = 1;
		goto err;
	}

	return 0;

err:
	free(*msg); /* Discardin msg */
	*msg_len = 0;
	*msg = NULL;
	return ret;
}

int com_wait_and_recv_msg(int sockfd, void **msg, int *msg_len)
{
	fd_set set;
	struct timeval timeout;
	int select_ret;

	FD_ZERO(&set);
	FD_SET(sockfd, &set);

	while (1) {

		timeout.tv_sec = 1000;
		timeout.tv_usec = 0;

		select_ret = select(sockfd + 1, &set, NULL, NULL, &timeout);
		if (select_ret == -1) {
			if (errno == EINTR)
				continue;

			return -1;

		} else if (select_ret == 0) {
			continue;

		} else {
			break;

		}
	}

	return com_recv_msg(sockfd, msg, msg_len);

}

int com_send_msg(int sockfd, void *msg, int msg_len)
{
	int bytes_write;
	unsigned char *send_buf;
	struct com_trasnport_info com_trans_info;

	if (!msg) {
		OT_LOG(LOG_ERR, "message null");
		return -1;
	}

	send_buf = malloc(msg_len + sizeof(struct com_trasnport_info));
	if (!send_buf) {
		OT_LOG(LOG_ERR, "out of memory");
		return -1;
	}

	/* Fill and calculate transport information */
	com_trans_info.start = COM_MSG_START;
	com_trans_info.data_len = msg_len;
	com_trans_info.checksum = crc32(0, msg, msg_len);

	memcpy(send_buf, &com_trans_info, sizeof(struct com_trasnport_info));
	memcpy(send_buf + sizeof(struct com_trasnport_info), msg, msg_len);

	/* Send transport info */
	bytes_write = write_all(sockfd, send_buf, msg_len + sizeof(struct com_trasnport_info));
	if (bytes_write == -1) {
		OT_LOG(LOG_ERR, "send error");
		return -1;
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
