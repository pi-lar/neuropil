//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: CC-BY-SA-4.0
//
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

// daemonize a process by doing a double fork
// the approach is more secure because it prevents the daemon from opening
// additional tty sessions. Modified after reading :
// https://lloydrochester.com/post/c/unix-daemon-example/#creating-a-daemon-programmatically
// licensed under the CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/)

enum np_daemon_flags {
  NP_DAEMON_NO_UMASK        = 0x01,
  NP_DAEMON_NO_CHROOT       = 0x02,
  NP_DAEMON_NO_CLOSE_FILES  = 0x04,
  NP_DAEMON_NO_REOPEN_STDIO = 0x08,
};

static uint16_t NP_DAEMON_MAX_FDCLOSE = 8196;

int np_daemonize(int flags) {

  // fork the first time to become a daemon
  switch (fork()) { // become background process
  case -1:          // error when forking
    exit(EXIT_FAILURE);
    break;
  case 0: // successful fork, child
    break;
  default: // successful fork, parent
    exit(EXIT_SUCCESS);
    break;
  }
  if (setsid() == -1) // become leader of new session
    return -1;

  // fork the second time
  switch (fork()) {
  case -1:
    return -1;
  case 0: // successful fork, child
    break;
  default: // successful fork, parent
    exit(EXIT_SUCCESS);
  }

  if (!(flags & NP_DAEMON_NO_UMASK)) umask(0); // clear file creation mode mask

  if (!(flags & NP_DAEMON_NO_CHROOT)) chdir("/"); // change to root directory

  if (!(flags & NP_DAEMON_NO_CLOSE_FILES)) // close all open files
  {
    int  fd    = 0;
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd == -1)
      maxfd = NP_DAEMON_MAX_FDCLOSE; // if we don't know then guess
    for (fd = 0; fd < maxfd; fd++)
      close(fd);
  }

  if (!(flags & NP_DAEMON_NO_REOPEN_STDIO)) {
    // now time to go "dark" -> close stdin and point stdout and stderr to
    // /dev/null
    close(STDIN_FILENO);

    int fd = open("/dev/null", O_RDWR);
    if (fd != STDIN_FILENO) return -1;
    if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO) return -2;
    if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO) return -3;
  }

  return 0;
}