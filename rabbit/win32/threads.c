/* vim:set ft=c ts=2 sw=2 sts=2 et cindent: */
/*
 * Copyright 2012-2013 Michael Steinert
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

#include "threads.h"

DWORD
pthread_self(void)
{
  return GetCurrentThreadId();
}

int
pthread_mutex_init(pthread_mutex_t *mutex, void *attr)
{
  *mutex = malloc(sizeof(CRITICAL_SECTION));
  if (!*mutex) {
    return 1;
  }
  InitializeCriticalSection(*mutex);
  return 0;
}

int
pthread_mutex_lock(pthread_mutex_t *mutex)
{
  if (!*mutex) {
    return 1;
  }

  EnterCriticalSection(*mutex);
  return 0;
}

int
pthread_mutex_unlock(pthread_mutex_t *mutex)
{
  if (!*mutex) {
    return 1;
  }

  LeaveCriticalSection(*mutex);
  return 0;
}
