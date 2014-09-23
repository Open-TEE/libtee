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

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/un.h>
#include <syslog.h>

#include "utils.h"
#include "socket_help.h"
#include "com_protocol.h"
#include "tee_client_api.h"

static const uint8_t INITIALIZED = 0xca;
static const uint8_t UNITIALIZED = 0xcf;

/* TODO fix this to point to the correct location */
const char *sock_path = "/tmp/open_tee_sock";

/*!
 * \brief create_shared_mem_internal
 * Create a memory mapped shared memory object that can be used to transfer data between the TEE
 * and the Client application
 * \param context The context to which we are registering the memory
 * \param shared_mem Shared memory object that contains the definition of the region we are creating
 * \param type The type of memory allocation \sa enum mem_type
 * \return TEEC_SUCCESS on success, other error on failure
 */
static TEEC_Result create_shared_mem_internal(TEEC_Context *context, TEEC_SharedMemory *shared_mem,
					      enum mem_type type)
{
	int flag = 0;
	int fd;
	void *address = NULL;
	TEEC_Result ret = TEEC_SUCCESS;

	if (!context || !shared_mem || shared_mem->init == INITIALIZED)
		return TEEC_ERROR_BAD_PARAMETERS;

	/* The name of the shm object files should be in the format "/somename\0"
	 * so we will generate a random name that matches this format based of of
	 * a UUID
	 */
	if (generate_random_path(&shared_mem->shm_uuid) == -1)
		return TEEC_ERROR_OUT_OF_MEMORY;

	if ((shared_mem->flags & TEEC_MEM_OUTPUT) && !(shared_mem->flags & TEEC_MEM_INPUT))
		flag |= O_RDONLY; /* It is an outbuffer only so we just need read access */
	else
		flag |= O_RDWR;

	fd = shm_open(shared_mem->shm_uuid, (flag | O_CREAT | O_EXCL),
		      (S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP));
	if (fd == -1) {
		ret = TEEC_ERROR_GENERIC;
		goto errorExit;
	}

	/* if ftruncate 0 is used this will result in no file being created, mmap will fail below */
	if (ftruncate(fd, shared_mem->size != 0 ? shared_mem->size : 1) == -1) {
		ret = TEEC_ERROR_GENERIC;
		goto errorTruncate;
	}

	/* mmap does not allow for the size to be zero, however the TEEC API allows it, so map a
	 * size of 1 byte, though it will probably be mapped to a page
	 */
	address = mmap(NULL, shared_mem->size != 0 ? shared_mem->size : 1,
		       ((flag == O_RDONLY) ? PROT_READ : (PROT_WRITE | PROT_READ)),
		       MAP_SHARED, fd, 0);
	if (address == MAP_FAILED) {
		ret = TEEC_ERROR_OUT_OF_MEMORY;
		goto errorTruncate;
	}

	/* If we are allocating memory the buffer is the new mmap'd region, where as if we are
	 * only registering memory the buffer has already been alocated locally, so the mmap'd
	 * region is where we will copy the data just before we call a command in the TEE, so it
	 * must be stored seperatly in the "implementation deined section"
	 */
	if (type == ALLOCATED)
		shared_mem->buffer = address;
	else if (type == REGISTERED)
		shared_mem->reg_address = address;

	//TODO we must register the shared memory with the context
	shared_mem->parent_ctx = context;
	shared_mem->type = type;
	shared_mem->init = INITIALIZED;

	return TEEC_SUCCESS;

errorTruncate:
	shm_unlink(shared_mem->shm_uuid);

errorExit:
	free(shared_mem->shm_uuid);
	return ret;
}

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
	int sockfd;
	int recv_bytes;
	struct sockaddr_un sock_addr;
	struct com_msg_ca_init_tee_conn com_init_msg;
	struct com_msg_ca_init_tee_conn *recv_msg = NULL;

	/* We ignore the name as we are only communicating with a single instance of the emulator */
	(void)name;

	if (!context || context->init == INITIALIZED)
		return TEEC_ERROR_BAD_PARAMETERS;

	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return TEEC_ERROR_COMMUNICATION;

	memset(&sock_addr, 0, sizeof(struct sockaddr_un));
	strncpy(sock_addr.sun_path, sock_path, sizeof(sock_addr.sun_path) - 1);
	sock_addr.sun_family = AF_UNIX;

	if (connect(sockfd, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_un)) == -1)
		return TEEC_ERROR_COMMUNICATION;

	/* Fill init message */
	com_init_msg.msg_hdr.msg_name = COM_MSG_NAME_CA_INIT_CONTEXT;
	com_init_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	com_init_msg.msg_hdr.sess_id = 0; /* ignored */
	com_init_msg.msg_hdr.sender_type = 0; /* ignored */

	/* Send init message to TEE */
	if (com_send_msg(sockfd, &com_init_msg, sizeof(struct com_msg_ca_init_tee_conn)) !=
	    sizeof(struct com_msg_ca_init_tee_conn))
		goto err_com;

	/* Wait for answer */
	if (com_wait_and_recv_msg(sockfd, (void **)(&recv_msg), &recv_bytes, NULL) == -1)
		goto err_com;

	/* Check message */
	if (recv_msg->msg_hdr.msg_name != COM_MSG_NAME_CA_INIT_CONTEXT ||
	    recv_msg->msg_hdr.msg_type != COM_TYPE_RESPONSE) {
		printf("TEEC_InitializeContext: Not expected message\n");
		goto err_com;
	}

	context->init = INITIALIZED;
	context->sockfd  = sockfd;
	free(recv_msg);

	return TEEC_SUCCESS;

err_com:
	close(sockfd);
	free(recv_msg);
	return TEEC_ERROR_COMMUNICATION;
}

void TEEC_FinalizeContext(TEEC_Context *context)
{
	struct com_msg_ca_finalize_constex fin_con_msg;
	int ret;

	if (!context || context->init != INITIALIZED)
		return;

	//TODO should check that we do not have any open sessions first -No programmer error :/

	fin_con_msg.msg_hdr.msg_name = COM_MSG_NAME_CA_FINALIZ_CONTEXT;
	fin_con_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	fin_con_msg.msg_hdr.sess_id = 0; /* ignored */
	fin_con_msg.msg_hdr.sender_type = 0; /* ignored */

	/* Message filled. Send message */
	ret = com_send_msg(context->sockfd, &fin_con_msg, sizeof(struct com_msg_ca_finalize_constex));
	if (ret == COM_RET_IO_ERROR)
		return;

	/* Context will be finalized */

	close(context->sockfd);
	context->init = UNITIALIZED;
	return;
}

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context, TEEC_SharedMemory *shared_mem)
{
	if (!context || !shared_mem || !shared_mem->buffer)
		return TEEC_ERROR_BAD_PARAMETERS;

	return create_shared_mem_internal(context, shared_mem, REGISTERED);
}

TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context, TEEC_SharedMemory *shared_mem)
{
	return create_shared_mem_internal(context, shared_mem, ALLOCATED);
}

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *shared_mem)
{
	void *address;

	if (!shared_mem || shared_mem->init != INITIALIZED)
		return;

	/* If we allocated the memory free the buffer, other wise if it is just registered
	 * the buffer belongs to the Client Application, so we should not free it, instead
	 * we should free the mmap'd region that was mapped to support it
	 */
	if (shared_mem->type == ALLOCATED)
		address = shared_mem->buffer;
	else
		address = shared_mem->reg_address;

	/* Remove the memory mapped region and the shared memory */
	munmap(address, shared_mem->size);
	shm_unlink(shared_mem->shm_uuid);
	free(shared_mem->shm_uuid);

	//TODO we must unregister the shared memory from the Context

	shared_mem->init = 0xFF;
	return;
}

TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session,
			     const TEEC_UUID *destination, uint32_t connection_method,
			     void *connection_data, TEEC_Operation *operation,
			     uint32_t *return_origin)
{
	/* TODO: Add parameters check */

	struct com_msg_open_session open_msg;
	struct com_msg_open_session *recv_msg = NULL;
	int recv_bytes;
	int ret = 0;
	com_msg_hdr_t msg_name;
	TEEC_Result result = TEEC_SUCCESS;

	//if (!destination || !operation || !return_origin)
	//	goto err_para;

	if (!context || context->init == UNITIALIZED)
		goto err_para;

	if (!session || session->init == INITIALIZED)
		goto err_para;

	/* To be sure, reset all to zero */
	memset(&open_msg, 0, sizeof(struct com_msg_open_session));

	/* Fill open msg */

	/* Header section */
	open_msg.msg_hdr.msg_name = COM_MSG_NAME_OPEN_SESSION;
	open_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	open_msg.msg_hdr.sess_id = 0; /* manager filled */
	open_msg.msg_hdr.sender_type = 0; /* manger filled */

	/* UUID */
	memcpy(&open_msg.uuid, destination, sizeof(TEEC_UUID));

	/* ## TODO: Operation parameters and rest params ## */

	/* Message filled. Send message */
	ret = com_send_msg(context->sockfd, &open_msg, sizeof(struct com_msg_open_session));
	if (ret == COM_RET_IO_ERROR)
		goto err_com;

	/* Wait for answer */
	ret = com_wait_and_recv_msg(context->sockfd, &recv_msg, &recv_bytes, NULL);
	if (ret == -1)
		goto err_com;
	if (ret > 0) {
		/* TODO: Do what? End session? Problem: We do not know what message was
		 * incomming. Error or Response to open session message. Worst case situation is
		 * that task is complited, but message delivery only failed. Just report
		 * communication error and dump problem "upper layer". */
	}

	/* Check received message */
	msg_name = com_get_msg_name(recv_msg);
	if (msg_name == COM_MSG_NAME_ERROR) {
		*return_origin = ((struct com_msg_error *) recv_msg)->err_origin;
		result = ((struct com_msg_error *) recv_msg)->err_name;

	} else if (msg_name == COM_MSG_NAME_OPEN_SESSION) {
		/* session opened. Succesfully
		 * Manager is sending now session socket */

		if (recv_fd(context->sockfd, &session->sockfd) == -1)
			goto err_com;

		if (recv_msg->return_code_open_session != TEE_SUCCESS)
			close(session->sockfd);

		*return_origin = recv_msg->return_origin;
		result = recv_msg->return_code_open_session;

		/* TODO: Return parameters!! */
	}

	session->init = INITIALIZED;
	free(recv_msg);
	return result;

err_com:
	free(recv_msg);
	*return_origin = TEEC_ORIGIN_COMMS;
	return TEEC_ERROR_COMMUNICATION;

err_para:
	*return_origin = TEE_ORIGIN_API;
	return TEEC_ERROR_BAD_PARAMETERS;
}

void TEEC_CloseSession(TEEC_Session *session)
{
	struct com_msg_close_session close_msg;
	int ret;

	if (!session || session->init != INITIALIZED)
		return;

	close_msg.msg_hdr.msg_name = COM_MSG_NAME_CLOSE_SESSION;
	close_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	close_msg.msg_hdr.sess_id = 0; /* manager filled */
	close_msg.msg_hdr.sender_type = 0; /* manger filled */

	/* Message filled. Send message */
	ret = com_send_msg(session->sockfd, &close_msg, sizeof(struct com_msg_close_session));
	if (ret == COM_RET_IO_ERROR)
		return;

	/* Session closing is on going and it will be closed */

	close(session->sockfd);
	session->init = UNITIALIZED;
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t command_id,
			       TEEC_Operation *operation, uint32_t *return_origin)
{
	command_id = command_id;
	operation = operation;

	if (!session || session->init == UNITIALIZED)
		return;

	//if (!operation || !return_origin)
	//	return;

	struct com_msg_invoke_cmd invoke_msg;
	struct com_msg_invoke_cmd *recv_msg = NULL;
	int ret = 0;
	int recv_bytes;
	TEEC_Result result = TEEC_SUCCESS;
	com_msg_hdr_t msg_name;

	/* Fill message */
	invoke_msg.msg_hdr.msg_name = COM_MSG_NAME_INVOKE_CMD;
	invoke_msg.msg_hdr.msg_type = COM_TYPE_QUERY;
	invoke_msg.msg_hdr.sess_id = 0; /* manager filled */
	invoke_msg.msg_hdr.sender_type = 0; /* manger filled */

	/* Message filled. Send message */
	ret = com_send_msg(session->sockfd, &invoke_msg, sizeof(struct com_msg_invoke_cmd));
	if (ret == COM_RET_IO_ERROR)
		goto err_com;

	/* Wait for answer */
	ret = com_wait_and_recv_msg(session->sockfd, &recv_msg, &recv_bytes, NULL);
	if (ret == -1)
		goto err_com;
	if (ret > 0) {
		/* TODO: Do what? End session? Problem: We do not know what message was
		 * incomming. Error or Response to open session message. Worst case situation is
		 * that task is complited, but message delivery only failed. Just report
		 * communication error and dump problem "upper layer". */
	}

	/* Check received message */
	msg_name = com_get_msg_name(recv_msg);
	if (msg_name == COM_MSG_NAME_ERROR) {
		*return_origin = ((struct com_msg_error *) recv_msg)->err_origin;
		result = ((struct com_msg_error *) recv_msg)->err_name;
	}
	if (msg_name == COM_MSG_NAME_INVOKE_CMD) {
		/* Success. Let see result */
		result = recv_msg->return_code;
		*return_origin = recv_msg->return_origin;
	}

	free(recv_msg);
	return result;

err_com:
	close(session->sockfd);
	free(recv_msg);
	*return_origin = TEEC_ORIGIN_COMMS;
	return TEEC_ERROR_COMMUNICATION;
}

void TEEC_RequestCancellation(TEEC_Operation *operation)
{
	if (!operation)
		return;

	return;
}
