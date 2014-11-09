/*****************************************************************************
** Copyright (C) 2013 Intel Corporation.                                    **
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
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>

#include "com_protocol.h"
#include "socket_help.h"
#include "tee_client_api.h"
#include "tee_logging.h"

/* TODO fix this to point to the correct location */
const char *sock_path = "/tmp/open_tee_sock";

/* Mutex is used when write function occur to FD which is connected to TEE */
pthread_mutex_t fd_write_mutex = PTHREAD_MUTEX_INITIALIZER;

struct context_internal {
	pthread_mutex_t mutex;
	int sockfd;
	uint8_t init;
};

struct session_internal {
	pthread_mutex_t mutex;
	uint64_t sess_id;
	int sockfd;
	uint8_t init;
};


static int send_msg(int fd, void *msg, int msg_len, pthread_mutex_t mutex)
{
	int ret;

	if (pthread_mutex_lock(&mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex");
		return -1;
	}

	ret = com_send_msg(fd, msg, msg_len);

	if (pthread_mutex_unlock(&mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex")

	return ret;
}

/*!
 * \brief wait_socket_close
 * This function is not interested any data that is comming from socket.
 * It only breaks it while loop, when error occured.
 * \param fd
 */
static void wait_socket_close(int fd)
{
	const int tmp_len = 8;
	char tmp[tmp_len];
	int read_bytes;

	while (1) {
		read_bytes = read(fd, &tmp, tmp_len);
		if (read_bytes == -1) {

			if (errno == EINTR)
				continue;

			break;

		} else if (read_bytes == 0) {
			/* If socket other end is closed before this function read is called,
			 * read returns zero */
			break;

		} else {
			continue;
		}
	}
}

static bool get_return_vals_from_err_msg(void *msg, TEE_Result *err_name, uint32_t *err_origin)
{
	uint8_t msg_name;

	if (!msg) {
		OT_LOG(LOG_ERR, "msg NULL");
		return false;
	}

	if (com_get_msg_name(msg, &msg_name)) {
		OT_LOG(LOG_ERR, "Failed to retreave message name");
		return false;
	}

	if (msg_name != COM_MSG_NAME_ERROR) {
		OT_LOG(LOG_ERR, "Not an error message");
		return false;
	}

	if (err_name)
		*err_name = ((struct com_msg_error *) msg)->ret;

	if (err_origin)
		*err_origin = ((struct com_msg_error *) msg)->ret_origin;

	return true;
}

static bool verify_msg_name_and_type(void *msg, uint8_t expected_name, uint8_t expected_type)
{
	uint8_t msg_name, msg_type;

	if (!msg) {
		OT_LOG(LOG_ERR, "msg NULL");
		return false;
	}

	if (com_get_msg_name(msg, &msg_name) || com_get_msg_type(msg, &msg_type)) {
		OT_LOG(LOG_ERR, "Failed to retreave message name and type");
		return false;
	}

	if (msg_name != expected_name) {
		OT_LOG(LOG_ERR, "Not expexted name of the message");
		return false;
	}

	if (msg_type != expected_type) {
		OT_LOG(LOG_ERR, "Not expexted type of the message");
		return false;
	}

	return true;
}

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
	int com_ret;
	TEE_Result ret = TEEC_SUCCESS;
	struct sockaddr_un sock_addr;
	struct com_msg_ca_init_tee_conn init_msg;
	struct com_msg_ca_init_tee_conn *recv_msg = NULL;
	struct context_internal *inter_imp = NULL;

	/* We ignore the name as we are only communicating with a single instance of the emulator */
	(void)name;

	if (!context) {
		OT_LOG(LOG_ERR, "Contex NULL or initialized")
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	inter_imp = malloc(sizeof(struct context_internal));
	if (!inter_imp) {
		OT_LOG(LOG_ERR, "Failed to create space for context");
		return TEEC_ERROR_OUT_OF_MEMORY;
	}


	/* Init context mutex */
	if (pthread_mutex_init(&inter_imp->mutex, NULL)) {
		OT_LOG(LOG_ERR, "Failed to init mutex")
		return TEEC_ERROR_GENERIC;
	}

	inter_imp->sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (inter_imp->sockfd == -1) {
		OT_LOG(LOG_ERR, "Socket creation failed")
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_1;
	}

	memset(&sock_addr, 0, sizeof(struct sockaddr_un));
	strncpy(sock_addr.sun_path, sock_path, sizeof(sock_addr.sun_path) - 1);
	sock_addr.sun_family = AF_UNIX;

	if (connect(inter_imp->sockfd,
		    (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_un)) == -1) {
		OT_LOG(LOG_ERR, "Failed to connect to TEE")
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	/* Fill init message */
	init_msg.msg_hdr.msg_name = COM_MSG_NAME_CA_INIT_CONTEXT;
	init_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	init_msg.msg_hdr.sess_id = 0;     /* ignored */

	/* Send init message to TEE */
	if (send_msg(inter_imp->sockfd, &init_msg, sizeof(struct com_msg_ca_init_tee_conn),
		     fd_write_mutex) != sizeof(struct com_msg_ca_init_tee_conn)) {
		OT_LOG(LOG_ERR, "Failed to send context initialization msg");
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	/* Wait for answer */
	com_ret = com_recv_msg(inter_imp->sockfd, (void **)(&recv_msg), NULL);

	/* If else is only for correct log message */
	if (com_ret == -1) {
		OT_LOG(LOG_ERR, "Socket error");
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;

	} else if (com_ret > 0) {
		OT_LOG(LOG_ERR, "Received bad message, discarding");
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	/* Check received message */
	if (!verify_msg_name_and_type(recv_msg, COM_MSG_NAME_CA_INIT_CONTEXT, COM_TYPE_RESPONSE)) {
		ret = TEEC_ERROR_COMMUNICATION;
		goto err_2;
	}

	ret = recv_msg->ret;
	free(recv_msg);

	context->imp = inter_imp;

	return ret;

err_2:
	close(inter_imp->sockfd);
err_1:
	pthread_mutex_destroy(&inter_imp->mutex);
	free(recv_msg);
	free(inter_imp);
	context->imp = NULL;
	return ret;
}

void TEEC_FinalizeContext(TEEC_Context *context)
{
	struct com_msg_ca_finalize_constex fin_con_msg;
	struct context_internal *inter_imp;

	if (!context)
		return;

	inter_imp = (struct context_internal *)context->imp;
	if (!inter_imp)
		return;

	fin_con_msg.msg_hdr.msg_name = COM_MSG_NAME_CA_FINALIZ_CONTEXT;
	fin_con_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	fin_con_msg.msg_hdr.sess_id = 0;     /* ignored */

	if (pthread_mutex_lock(&inter_imp->mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex")
		goto err;
	}

	/* Message filled. Send message */
	if (send_msg(inter_imp->sockfd, &fin_con_msg,
			 sizeof(struct com_msg_ca_finalize_constex), fd_write_mutex) !=
	    sizeof(struct com_msg_ca_finalize_constex)) {
		OT_LOG(LOG_ERR, "Failed to send message TEE");
		goto unlock;
	}

	/* We are not actually receiving any data from TEE. This call is here for blocking
	 * purpose. It is preventing closing this side socket before TEE closes connection. With
	 * this it is easier segregate expected disconnection and not expected disconnection.
	 * This blocking will end when TEE closes its side socket. */
	wait_socket_close(inter_imp->sockfd);

unlock:
	if (pthread_mutex_unlock(&inter_imp->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex")

err:
	inter_imp->init = 0;
	close(inter_imp->sockfd);
	while (pthread_mutex_destroy(&inter_imp->mutex)) {
		if (errno != EBUSY) {
			OT_LOG(LOG_ERR, "Failed to destroy mutex")
			break;
		}
		/* Busy loop */
	}

	free(inter_imp);
	context->imp = NULL;
}

TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session,
			     const TEEC_UUID *destination, uint32_t connection_method,
			     void *connection_data, TEEC_Operation *operation,
			     uint32_t *return_origin)
{
	struct com_msg_open_session open_msg;
	struct com_msg_open_session *recv_msg = NULL;
	int com_ret = 0;
	TEEC_Result result = TEEC_SUCCESS;
	struct context_internal *context_internal = NULL;
	struct session_internal *session_internal = NULL;

	/* Not used on purpose. Reminding about implement memory stuff. (only UUID is handeled) */
	connection_method = connection_method;
	connection_data = connection_data;
	operation = operation;

	if (!context || !session) {
		OT_LOG(LOG_ERR, "Context or session NULL or in improper state");
		if (return_origin)
			*return_origin = TEE_ORIGIN_API;
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	context_internal = (struct context_internal *)context->imp;

	session_internal = malloc (sizeof(struct session_internal));
	if (!session_internal) {
		OT_LOG(LOG_ERR, "Failed to create memory for session");
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	/* Fill open msg */

	/* Header section */
	open_msg.msg_hdr.msg_name = COM_MSG_NAME_OPEN_SESSION;
	open_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	open_msg.msg_hdr.sess_id = 0; /* manager will generate */

	/* UUID */
	memcpy(&open_msg.uuid, destination, sizeof(TEEC_UUID));

	/* ## TODO: Operation parameters and rest params ## */

	if (pthread_mutex_lock(&context_internal->mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex");
		if (return_origin)
			*return_origin = TEE_ORIGIN_API;
		return TEEC_ERROR_GENERIC;
	}

	/* Message filled. Send message */
	if (send_msg(context_internal->sockfd, &open_msg, sizeof(struct com_msg_open_session),
		     fd_write_mutex) != sizeof(struct com_msg_open_session)) {
		OT_LOG(LOG_ERR, "Failed to send message TEE");
		goto err_com;
	}

	/* Wait for answer */
	com_ret = com_recv_msg(context_internal->sockfd, (void **)(&recv_msg), NULL);
	if (com_ret == -1) {
		OT_LOG(LOG_ERR, "Socket error");
		goto err_com;

	} else if (com_ret > 0) {
		OT_LOG(LOG_ERR, "Received bad message, discarding");
		/* TODO: Do what? End session? Problem: We do not know what message was
		 * incomming. Error or Response to open session message. Worst case situation is
		 * that task is complited, but message delivery only failed. Just report
		 * communication error and dump problem "upper layer". */
		goto err_com;
	}

	if (pthread_mutex_unlock(&context_internal->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex"); /* No action */

	/* Check received message */
	if (!verify_msg_name_and_type(recv_msg, COM_MSG_NAME_OPEN_SESSION, COM_TYPE_RESPONSE)) {
		if (!get_return_vals_from_err_msg(recv, &result, return_origin))
			goto err_com;

		goto err_msg;
	}

	/* Message received succesfully */
	result = recv_msg->return_code_open_session;
	if (return_origin)
		*return_origin = recv_msg->return_origin;

	/* ## TODO/NOTE: Take operation parameter from message! ## */

	session_internal->sockfd = context_internal->sockfd;
	session_internal->mutex = context_internal->mutex;
	session_internal->sess_id = recv_msg->msg_hdr.sess_id;
	session->imp = session_internal;
	free(recv_msg);
	return result;

err_com:
	if (return_origin)
		*return_origin = TEE_ORIGIN_COMMS;
	result = TEEC_ERROR_COMMUNICATION;

err_msg:
	if (pthread_mutex_unlock(&context_internal->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex");

	free(recv_msg);
	free(session_internal);
	session->imp = NULL;
	return result;
}

void TEEC_CloseSession(TEEC_Session *session)
{
	struct com_msg_close_session close_msg;
	struct session_internal *internal_imp = NULL;

	if (!session) {
		OT_LOG(LOG_ERR, "Session NULL or not initialized");
		return;
	}

	internal_imp = (struct session_internal *)session->imp;
	if (!internal_imp)
		return;

	close_msg.msg_hdr.msg_name = COM_MSG_NAME_CLOSE_SESSION;
	close_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	close_msg.msg_hdr.sess_id = internal_imp->sess_id;

	/* Message filled. Send message */
	if (pthread_mutex_lock(&internal_imp->mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex")
		goto err;
	}

	/* Message filled. Send message */
	if (send_msg(internal_imp->sockfd, &close_msg, sizeof(struct com_msg_close_session),
		     fd_write_mutex) != sizeof(struct com_msg_close_session))
		OT_LOG(LOG_ERR, "Failed to send message TEE");

	if (pthread_mutex_unlock(&internal_imp->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex")

err:
	free(internal_imp);
	session->imp = NULL;
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t command_id,
			       TEEC_Operation *operation, uint32_t *return_origin)
{
	struct com_msg_invoke_cmd invoke_msg;
	struct com_msg_invoke_cmd *recv_msg = NULL;
	int com_ret = 0;
	TEEC_Result result = TEEC_SUCCESS;
	struct session_internal *session_internal;

	command_id = command_id; /* Not used on purpose. Reminding about implement memory stuff */

	if (!session || !operation) {
		OT_LOG(LOG_ERR, "session or operation NULL or session not initialized")
		if (return_origin)
			*return_origin = TEE_ORIGIN_API;
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	session_internal = (struct session_internal *)session->imp;
	if (!session_internal)
		return TEEC_ERROR_BAD_PARAMETERS;

	/* Fill message */
	invoke_msg.msg_hdr.msg_name = COM_MSG_NAME_INVOKE_CMD;
	invoke_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	invoke_msg.msg_hdr.sess_id = session_internal->sess_id;

	/* ## TODO/NOTE: Map operation to message! ## */

	/* Message filled. Send message */
	if (pthread_mutex_lock(&session_internal->mutex)) {
		OT_LOG(LOG_ERR, "Failed to lock mutex");
		if (return_origin)
			*return_origin = TEE_ORIGIN_API;
		return TEEC_ERROR_GENERIC;
	}

	/* Message filled. Send message */
	if (send_msg(session_internal->sockfd, &invoke_msg,
		     sizeof(struct com_msg_invoke_cmd), fd_write_mutex) !=
	    sizeof(struct com_msg_invoke_cmd)) {
		OT_LOG(LOG_ERR, "Failed to send message TEE")
		goto err_com_1;
	}

	/* Wait for answer */
	com_ret = com_recv_msg(session_internal->sockfd, (void **)(&recv_msg), NULL);
	if (com_ret == -1) {
		OT_LOG(LOG_ERR, "Socket error")
		goto err_com_1;
	} else if (com_ret > 0) {
		OT_LOG(LOG_ERR, "Received bad message, discarding")
		/* TODO: Do what? End session? Problem: We do not know what message was
		 * incomming. Error or Response to invoke cmd message. Worst case situation is
		 * that task is complited, but message delivery only failed. For now, just report
		 * communication error and dump problem "upper layer". */
		goto err_com_1;
	}

	if (pthread_mutex_unlock(&session_internal->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex"); /* No action */

	/* Check received message */
	if (!verify_msg_name_and_type(recv_msg, COM_MSG_NAME_INVOKE_CMD, COM_TYPE_RESPONSE)) {
		if (!get_return_vals_from_err_msg(recv, &result, return_origin))
			goto err_com_2;

		goto err_msg;
	}

	/* Success. Let see result */
	result = recv_msg->return_code;
	if (return_origin)
		*return_origin = recv_msg->return_origin;

	/* ## TODO/NOTE: Take operation parameter from message! ## */

	free(recv_msg);
	return result;

err_com_1:
	if (pthread_mutex_unlock(&session_internal->mutex))
		OT_LOG(LOG_ERR, "Failed to unlock mutex");
err_com_2:
	if (return_origin)
		*return_origin = TEE_ORIGIN_COMMS;
	result = TEEC_ERROR_COMMUNICATION;
err_msg:
	free(recv_msg);
	return result;
}

void TEEC_RequestCancellation(TEEC_Operation *operation)
{
	/* PLACEHOLDER */

	operation = operation;
}
