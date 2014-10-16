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

#ifndef __COM_PROTOCOL_H__
#define __COM_PROTOCOL_H__

/*!
 * \file com_protocol.h
 * \brief
 *
 * Use com_recv_msg(), com_send_msg(), com_wait_and_recv_msg() functions, because there function
 * will add or remove and check transport information.
 * If message is corrupted, it will be discarted.
 *
 * Protocol format:
 *
 * |------------|---------------|---------------|---------------|
 * | Start bit	| Message	| Checksum	| Payload	|
 * | sequence	| length	| Checksum	| Payload	|
 * |------------|---------------|---------------|---------------|
 *
 * Start bit sequence: Message starting with pre defined bit sequence
 * Message length: Payyload
 * Checksum: CRC32 checksum is calculated over payload
 * (TODO: calculate checksum: bit seq + msg len + payload)
 * Payload: actual message
 */

#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>

#include "tee_shared_data_types.h"

/* Communication protocol message names */
#define COM_MSG_NAME_RESERVED			0x00 /* Zero is reserved */
#define COM_MSG_NAME_CA_INIT_CONTEXT		0x01
#define COM_MSG_NAME_OPEN_SESSION		0x02
#define COM_MSG_NAME_CREATED_TA			0x03
#define COM_MSG_NAME_INVOKE_CMD			0x04
#define COM_MSG_NAME_CLOSE_SESSION		0x05
#define COM_MSG_NAME_CA_FINALIZ_CONTEXT		0x06
#define COM_MSG_NAME_PROC_STATUS_CHANGE		0x07
#define COM_MSG_NAME_FD_ERR			0x08

/* Request is used innerly */
#define COM_TYPE_QUERY				1
#define COM_TYPE_RESPONSE			0

#define TA_MAX_NAME_LEN				255

/* Definitions */
typedef uint8_t com_msg_hdr_t; /* Used with com base types */
typedef TEE_Result com_err_t; /* Error type */
typedef uint64_t sess_t;

enum sender_t {
	com_sender_CA,
	com_sender_TA,
	com_sender_launcher,
	com_sender_manager,
};

struct com_msg_hdr {
	com_msg_hdr_t msg_name;
	com_msg_hdr_t msg_type;
	sess_t sess_id;
	enum sender_t sender_type; /* Not used by client */
};

/*
 * ## Message section start ##
 */
struct com_msg_ca_init_tee_conn {
	struct com_msg_hdr msg_hdr;
	/* Empty */
};

struct com_msg_error {
	struct com_msg_hdr msg_hdr;
	com_err_t err_origin;
	com_err_t err_name;
	int errno_val;
};

struct com_msg_error_from_ta {
	struct com_msg_hdr msg_hdr;
	com_err_t err_origin;
	com_err_t err_name;
	uint64_t session_id;
};

struct com_msg_open_session {
	struct com_msg_hdr msg_hdr;
	char ta_so_name[TA_MAX_NAME_LEN];
	TEE_UUID uuid;
	TEE_Result return_code_create_entry;
	TEE_Result return_code_open_session;
	uint32_t return_origin;
	int sess_fd_to_caller;
	/* parameters */
};

struct com_msg_invoke_cmd {
	struct com_msg_hdr msg_hdr;
	TEE_Result return_code;
	uint32_t cmd_id;
	uint64_t session_id;
	uint32_t return_origin;
	/* parameters */
};

struct com_msg_ta_created {
	struct com_msg_hdr msg_hdr;
	pid_t pid;
};

struct com_msg_close_session {
	struct com_msg_hdr msg_hdr;
	uint32_t should_ta_destroy;
};

struct com_msg_ca_finalize_constex {
	struct com_msg_hdr msg_hdr;
	/* Empty */
};

struct com_msg_proc_status_change {
	struct com_msg_hdr msg_hdr;
	/* Empty */
};

struct com_msg_fd_err {
	struct com_msg_hdr msg_hdr;
	int err_no;
	void *proc_ptr;
};

/*
 *  ## Message section end ##
 */


/* Function for receiving and  sending messages */
int com_recv_msg(int sockfd, void **msg, int *msg_len);
int com_wait_and_recv_msg(int sockfd, void **msg, int *msg_len);
int com_send_msg(int sockfd, void *msg, int msg_len);

/* Get-functions for accessing protocol base functionality. */
com_msg_hdr_t com_get_msg_name(void *msg);
com_msg_hdr_t com_get_msg_type(void *msg);
sess_t com_get_msg_sess_id(void *msg);

#endif /* __COM_PROTOCOL_H__ */

