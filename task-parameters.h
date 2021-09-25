#ifndef TASK_PARAMS_H
#define TASK_PARAMS_H

#include <openssl/bio.h>

typedef unsigned long long longlong;
struct TaskParameters
{
	BIGNUM* start;
	BIGNUM* increment;
	int id;
	void (*checkTargets)(longlong, BIGNUM*, int, const char*);
	void (*reportProgress)(BIGNUM*, int);
};
#endif
