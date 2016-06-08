/* vim:set ft=c ts=2 sw=2 sts=2 et cindent: */
/** \file */
/*
 * Portions created by Alan Antonuk are Copyright (c) 2013-2014 Alan Antonuk.
 * All Rights Reserved.
 *
 * Portions created by Michael Steinert are Copyright (c) 2012-2013 Michael
 * Steinert. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef AMQP_SSL_H
#define AMQP_SSL_H

#include <amqp.h>

AMQP_BEGIN_DECLS

/**
 * Create a new SSL/TLS socket object.
 *
 * The returned socket object is owned by the \ref amqp_connection_state_t object
 * and will be destroyed when the state object is destroyed or a new socket
 * object is created.
 *
 * If the socket object creation fails, the \ref amqp_connection_state_t object
 * will not be changed.
 *
 * The object returned by this function can be retrieved from the
 * amqp_connection_state_t object later using the amqp_get_socket() function.
 *
 * Calling this function may result in the underlying SSL library being initialized.
 * \sa amqp_set_initialize_ssl_library()
 *
 * \param [in,out] state The connection object that owns the SSL/TLS socket
 * \return A new socket object or NULL if an error occurred.
 *
 * \since v0.4.0
 */
AMQP_PUBLIC_FUNCTION
amqp_socket_t *
AMQP_CALL
amqp_ssl_socket_new(amqp_connection_state_t state);

/**
 * Set the CA certificate.
 *
 * \param [in,out] self An SSL/TLS socket object.
 * \param [in] cacert Path to the CA cert file in PEM format.
 *
 * \return \ref AMQP_STATUS_OK on success an \ref amqp_status_enum value on
 *  failure.
 *
 * \since v0.4.0
 */
AMQP_PUBLIC_FUNCTION
int
AMQP_CALL
amqp_ssl_socket_set_cacert(amqp_socket_t *self,
                           const char *cacert);

/**
 * Set the client key.
 *
 * \param [in,out] self An SSL/TLS socket object.
 * \param [in] cert Path to the client certificate in PEM foramt.
 * \param [in] key Path to the client key in PEM format.
 *
 * \return \ref AMQP_STATUS_OK on success an \ref amqp_status_enum value on
 *  failure.
 *
 * \since v0.4.0
 */
AMQP_PUBLIC_FUNCTION
int
AMQP_CALL
amqp_ssl_socket_set_key(amqp_socket_t *self,
                        const char *cert,
                        const char *key);

/**
 * Set the client key from a buffer.
 *
 * \param [in,out] self An SSL/TLS socket object.
 * \param [in] cert Path to the client certificate in PEM foramt.
 * \param [in] key A buffer containing client key in PEM format.
 * \param [in] n The length of the buffer.
 *
 * \return \ref AMQP_STATUS_OK on success an \ref amqp_status_enum value on
 *  failure.
 *
 * \since v0.4.0
 */
AMQP_PUBLIC_FUNCTION
int
AMQP_CALL
amqp_ssl_socket_set_key_buffer(amqp_socket_t *self,
                               const char *cert,
                               const void *key,
                               size_t n);

/**
 * Enable or disable peer verification.
 *
 * If peer verification is enabled then the common name in the server
 * certificate must match the server name. Peer verification is enabled by
 * default.
 *
 * \param [in,out] self An SSL/TLS socket object.
 * \param [in] verify Enable or disable peer verification.
 *
 * \since v0.4.0
 */
AMQP_PUBLIC_FUNCTION
void
AMQP_CALL
amqp_ssl_socket_set_verify(amqp_socket_t *self,
                           amqp_boolean_t verify);

/**
 * Sets whether rabbitmq-c initializes the underlying SSL library.
 *
 * For SSL libraries that require a one-time initialization across
 * a whole program (e.g., OpenSSL) this sets whether or not rabbitmq-c
 * will initialize the SSL library when the first call to
 * amqp_open_socket() is made. You should call this function with
 * do_init = 0 if the underlying SSL library is initialized somewhere else
 * the program.
 *
 * Failing to initialize or double initialization of the SSL library will
 * result in undefined behavior
 *
 * By default rabbitmq-c will initialize the underlying SSL library
 *
 * NOTE: calling this function after the first socket has been opened with
 * amqp_open_socket() will not have any effect.
 *
 * \param [in] do_initialize If 0 rabbitmq-c will not initialize the SSL
 *                           library, otherwise rabbitmq-c will initialize the
 *                           SSL library
 *
 * \since v0.4.0
 */
AMQP_PUBLIC_FUNCTION
void
AMQP_CALL
amqp_set_initialize_ssl_library(amqp_boolean_t do_initialize);

AMQP_END_DECLS

#endif /* AMQP_SSL_H */
