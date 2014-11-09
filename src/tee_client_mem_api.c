/*****************************************************************************
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

#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>

#include "tee_client_api.h"
#include "utils.h"
#include "tee_logging.h"


enum mem_type {
	REGISTERED = 0,
	ALLOCATED = 0xa110ca7e
};

struct shared_mem_internal {
	char *shm_uuid;		  /*!< Pointer to the shared memory object that has been created */
	void *reg_address;	/*!< store the mmap address that is used for registered mem */
	enum mem_type type;       /*!< The type of the memory, i.e. allocated or registered */
};

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
	struct shared_mem_internal *internal_imp;

	if (!context || !shared_mem)
		return TEEC_ERROR_BAD_PARAMETERS;

	internal_imp = malloc(sizeof(struct shared_mem_internal));
	if (!internal_imp) {
		OT_LOG(LOG_ERR, "Failed to allocate memory for Shared memory");
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	/* The name of the shm object files should be in the format "/somename\0"
	 * so we will generate a random name that matches this format based of of
	 * a UUID
	 */
	if (generate_random_path(&internal_imp->shm_uuid) == -1)
		return TEEC_ERROR_OUT_OF_MEMORY;

	if ((shared_mem->flags & TEEC_MEM_OUTPUT) && !(shared_mem->flags & TEEC_MEM_INPUT))
		flag |= O_RDONLY; /* It is an outbuffer only so we just need read access */
	else
		flag |= O_RDWR;

	fd = shm_open(internal_imp->shm_uuid, (flag | O_CREAT | O_EXCL),
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
	address =
	    mmap(NULL, shared_mem->size != 0 ? shared_mem->size : 1,
		 ((flag == O_RDONLY) ? PROT_READ : (PROT_WRITE | PROT_READ)), MAP_SHARED, fd, 0);
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
		internal_imp->reg_address = address;

	internal_imp->type = type;
	shared_mem->imp = internal_imp;

	return TEEC_SUCCESS;

errorTruncate:
	shm_unlink(internal_imp->shm_uuid);

errorExit:
	free(internal_imp->shm_uuid);
	free(internal_imp);
	return ret;
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
	struct shared_mem_internal *internal_imp = NULL;

	if (!shared_mem)
		return;

	internal_imp = (struct shared_mem_internal *)shared_mem->imp;
	if (!internal_imp)
		return;

	/* If we allocated the memory free the buffer, other wise if it is just registered
	 * the buffer belongs to the Client Application, so we should not free it, instead
	 * we should free the mmap'd region that was mapped to support it
	 */
	if (internal_imp->type == ALLOCATED)
		address = shared_mem->buffer;
	else
		address = internal_imp->reg_address;

	/* Remove the memory mapped region and the shared memory */
	munmap(address, shared_mem->size);
	shm_unlink(internal_imp->shm_uuid);
	free(internal_imp->shm_uuid);
	free(internal_imp);
	shared_mem->imp = NULL;

	return;
}
