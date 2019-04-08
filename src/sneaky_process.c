/**
 * Author: Prathikshaa Rangarajan
 * Date: March 20, 2019
 * File Name: sneaky_processs.c
 * Description:
 *
 */
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void run_command(const char *command, char *const args[]) {
  pid_t pid_fork, wait_res;
  int wstatus;

  pid_fork = fork();
  if (pid_fork == -1) {
    // fork error
    perror("fork error:");
  } else if (pid_fork == 0) {
    // child
    execv(command, args); // does not return on success
    perror("execv:");
  } else {
    // parent
    wait_res = waitpid(pid_fork, &wstatus, 0);
    if (wait_res == -1) {
      // error waiting for child
      perror("waitpid:");
    }
    return;
  }
}

int main(void) {
  /*-------------------------------1------------------------------*/
  printf("sneaky_process pid = %d\n", getpid());
  /*-------------------------------2------------------------------*/
  // copy /etc/passwd to /tmp/passwd
  char *const command[] = {"/bin/ls", "-l"};
  run_command(command[0], command);

  // add following line to end of tmp/passwd
  // sneakyuser:abc123:2000:2000:sneakyuser:/root:bash

  /*-------------------------------3------------------------------*/
  // load sneaky module using insmod()
  // pass pid to module
  // ref: http://www.tldp.org/LDP/lkmpg/2.6/html/x323.html

  /*-------------------------------4------------------------------*/
  // while(1)
  // take keyboard input until "q"-quit

  // test malicious behavior

  // end while
  /*-------------------------------5------------------------------*/
  // unload sneaky kernel module using rmmod()

  /*-------------------------------6------------------------------*/

  // cp /tmp/passwd to /etc/psswd
}
