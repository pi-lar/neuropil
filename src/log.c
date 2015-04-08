/*
** $Id: log.c,v 1.15 2006/09/05 06:09:35 krishnap Exp $
**
** Matthew Allen
** description: 
*/

#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

// TODO OS dependant import ?
#include <sys/time.h>
#include <time.h>

// extern FILE *stdin;
extern LOG *logger;

void log_message(int level, const char* srcFile, const char* funcName, int lineno, const char* msg, ...)
{
	if ( (level & logger->level) > LOG_NONE) {
		char buffer[1024];
		va_list ap;
		va_start (ap, msg);
		vsprintf (buffer, msg, ap);
		va_end(ap);

		struct timeval tval;
		gettimeofday(&tval, (struct timezone*)0);
		int millis = tval.tv_usec;
		char timebuf[80];
		strftime(timebuf, 80, "%Y-%m-%d %H:%M:%S", localtime(&tval.tv_sec));

		fprintf(logger->fp, "%s.%i %-15.15s:%-25.25s:%-4d # %-8d # %s\n", timebuf, millis,
				srcFile, funcName, lineno, level, buffer);
		fflush(logger->fp);
	} else {
		// printf("not logging to file(%p): %d & %d = %d\n", logger, level, logger->level, level & logger->level);
	}
}

void log_init(const char* filename, int level) {

	logger = (LOG *) malloc(sizeof(LOG));

    snprintf (logger->filename, 255, "%s", filename);
	logger->fp = fopen(logger->filename, "a");
    logger->level = level;
	fprintf(logger->fp, "initialized log system %p: %s (%p) %d\n", logger, logger->filename, logger->fp, logger->level);
	fflush(logger->fp);
}

LOG* log_get() {
	return logger;
}

void log_destroy() {
	logger->level=LOG_NONE;
	fclose(logger->fp);
	free(logger);
}


//void log_msg(int type, char *format, ...)
//{
//	char buffer[256];
//    va_list ap;
//    va_start (ap, format);
//    vsprintf (buffer, format, ap);
//    va_end(ap);
//	fprintf(stdout, "%s:%s:%d ## %d ## %d # %s", __FILE__, __func__, __LINE__, type, getpid(), buffer);
//}

//void *log_init ()
//{
//    static FILE **log_fp;
//    log_fp = (FILE **) malloc (sizeof (FILE *) * LOG_COUNT);
//    memset (log_fp, 0, sizeof (FILE *) * LOG_COUNT);
//    return ((void *) log_fp);
//}


//void log_message (void *logs, int type, char *format, ...)
//{
//    va_list ap;
//    FILE **log_fp = (FILE **) logs;
//
//    if (log_fp !=NULL && log_fp[type] != NULL)
//	{
//	    va_start (ap, format);
//	    vfprintf (log_fp[type], format, ap);
//	    fflush (log_fp[type]);	// this is needed to get the contents logged
//	}
//}

void log_direct (void *logs, int type, FILE * fp)
{
    FILE **log_fp = (FILE **) logs;

    if (fp == NULL)
	{
	    fprintf (stderr,
		     "The file pointer given to log_direct is NULL; No messages would be printed to the file \n");
	}

    log_fp[type] = fp;
}
