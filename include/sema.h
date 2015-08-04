/**
 *  copyright 2015 pi-lar GmbH
 *  original version was taken from chimera project (MIT licensed), but heavily modified
 *  Stephan Schwichtenberg
 **/

#ifndef _NP_SEMAPHORE_H_
#define _NP_SEMAPHORE_H_

typedef struct Semaphore
{
    int val;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} Sema;

void *sema_create (int val);
void sema_destroy (void *v);
int sema_p (void *v, double timeout);
void sema_v (void *v);

#endif /* _NP_SEMAPHORE_H_ */
