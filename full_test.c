#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>

/* Define System Call Numbers */
#define SYS_SET_BAN 334
#define SYS_GET_BAN 335
#define SYS_CHECK_BAN 336
#define SYS_FLIP_BAN 337

/* Helper Macros for colors */
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

void assert_success(long res, const char *msg) {
    if (res < 0) {
        printf(RED "[FAILED] %s (res=%ld, errno=%d)\n" RESET, msg, res, errno);
        exit(1);
    } else {
        printf(GREEN "[OK] %s\n" RESET, msg);
    }
}

void assert_failure(long res, int expected_errno, const char *msg) {
    /* Special handling: if expected_errno is 0, just check for -1 */
    if (res == -1 && (expected_errno == 0 || errno == expected_errno)) {
        printf(GREEN "[OK] %s (Correctly failed)\n" RESET, msg);
    } else {
        printf(RED "[FAILED] %s (Expected errno=%d, got res=%ld, errno=%d)\n" RESET, msg, expected_errno, res, errno);
        exit(1);
    }
}

int main() {
    printf("========== STARTING COMPREHENSIVE KERNEL TEST ==========\n");

    long res;
    int pipefd[2];

    /* ================================================= */
    /* TEST GROUP 1: GETPID              */
    /* ================================================= */

    /* --- TEST 1.0: GETPID Normal Ban --- */
    printf("\n--- 1.0 - Testing GETPID Ban ('g') Normal ---\n");
    syscall(SYS_SET_BAN, 0, 0, 0); 
    
    assert_success(syscall(SYS_SET_BAN, 1, 0, 0), "Banning getpid (1)");
    if (syscall(SYS_GET_BAN, 'g') != 1) { printf(RED "get_ban('g') returned 0!\n" RESET); exit(1); }
    
    /* We tolerate errno not being set for getpid, just check return -1 */
    res = getpid();
    if (res == -1) printf(GREEN "[OK] getpid() blocked.\n" RESET);
    else { printf(RED "[FAILED] getpid() ran! PID=%ld\n" RESET, res); exit(1); }
    
    syscall(SYS_SET_BAN, 0, 0, 0); /* Cleanup */


    /* --- TEST 1.1: GETPID Ban > 1 (Should act as 1) --- */
    printf("\n--- 1.1 - Testing GETPID Ban > 1 (4654) ---\n");
    
    assert_success(syscall(SYS_SET_BAN, 4654, 0, 0), "Banning getpid (4654)");
    if (syscall(SYS_GET_BAN, 'g') != 1) { printf(RED "get_ban('g') returned 0!\n" RESET); exit(1); }
    
    res = getpid();
    if (res == -1) printf(GREEN "[OK] getpid() blocked.\n" RESET);
    else { printf(RED "[FAILED] getpid() ran! PID=%ld\n" RESET, res); exit(1); }
    
    syscall(SYS_SET_BAN, 0, 0, 0); /* Cleanup */


    /* --- TEST 1.2: GETPID Ban < 0 (Should Fail) --- */
    printf("\n--- 1.2 - Testing GETPID Ban < 0 (-424) ---\n");
    
    /* Expect EINVAL because argument is negative */
    assert_failure(syscall(SYS_SET_BAN, -424, 0, 0), EINVAL, "set_ban negative input");
    
    if (syscall(SYS_GET_BAN, 'g') != 0) { printf(RED "get_ban('g') returned 1 (Banned) after failed call!\n" RESET); exit(1); }
    
    res = getpid();
    if (res > 0) printf(GREEN "[OK] getpid() runs normally.\n" RESET);
    else { printf(RED "[FAILED] getpid() is blocked but shouldn't be.\n" RESET); exit(1); }


    /* ================================================= */
    /* TEST GROUP 2: PIPE                */
    /* ================================================= */

    /* --- TEST 2.0: PIPE Normal Ban --- */
    printf("\n--- 2.0 - Testing PIPE Ban ('p') Normal ---\n");
    
    assert_success(syscall(SYS_SET_BAN, 0, 1, 0), "Banning pipe (1)");
    if (syscall(SYS_GET_BAN, 'p') != 1) { printf(RED "get_ban('p') returned 0!\n" RESET); exit(1); }
    
    res = pipe(pipefd);
    assert_failure(res, EPERM, "pipe() blocked");
    
    syscall(SYS_SET_BAN, 0, 0, 0); /* Cleanup */


    /* --- TEST 2.1: PIPE Ban > 1 (Should act as 1) --- */
    printf("\n--- 2.1 - Testing PIPE Ban > 1 (999) ---\n");
    
    assert_success(syscall(SYS_SET_BAN, 0, 999, 0), "Banning pipe (999)");
    if (syscall(SYS_GET_BAN, 'p') != 1) { printf(RED "get_ban('p') returned 0!\n" RESET); exit(1); }
    
    res = pipe(pipefd);
    assert_failure(res, EPERM, "pipe() blocked");
    
    syscall(SYS_SET_BAN, 0, 0, 0); /* Cleanup */


    /* --- TEST 2.2: PIPE Ban < 0 (Should Fail) --- */
    printf("\n--- 2.2 - Testing PIPE Ban < 0 (-5) ---\n");
    
    assert_failure(syscall(SYS_SET_BAN, 0, -5, 0), EINVAL, "set_ban negative input");
    
    res = pipe(pipefd);
    if (res == 0) printf(GREEN "[OK] pipe() runs normally.\n" RESET);
    else { printf(RED "[FAILED] pipe() blocked unexpectedly.\n" RESET); exit(1); }


    /* ================================================= */
    /* TEST GROUP 3: KILL                */
    /* ================================================= */

    /* --- TEST 3.0: KILL Normal Ban --- */
    printf("\n--- 3.0 - Testing KILL Ban ('k') Normal ---\n");
    
    assert_success(syscall(SYS_SET_BAN, 0, 0, 1), "Banning kill (1)");
    if (syscall(SYS_GET_BAN, 'k') != 1) { printf(RED "get_ban('k') returned 0!\n" RESET); exit(1); }
    
    res = kill(getpid(), 0); 
    assert_failure(res, EPERM, "kill() blocked");
    
    syscall(SYS_SET_BAN, 0, 0, 0); /* Cleanup */


    /* --- TEST 3.1: KILL Ban > 1 --- */
    printf("\n--- 3.1 - Testing KILL Ban > 1 (777) ---\n");
    
    assert_success(syscall(SYS_SET_BAN, 0, 0, 777), "Banning kill (777)");
    if (syscall(SYS_GET_BAN, 'k') != 1) { printf(RED "get_ban('k') returned 0!\n" RESET); exit(1); }
    
    res = kill(getpid(), 0); 
    assert_failure(res, EPERM, "kill() blocked");
    
    syscall(SYS_SET_BAN, 0, 0, 0); /* Cleanup */


    /* --- TEST 3.2: KILL Ban < 0 --- */
    printf("\n--- 3.2 - Testing KILL Ban < 0 (-1) ---\n");
    
    assert_failure(syscall(SYS_SET_BAN, 0, 0, -1), EINVAL, "set_ban negative input");
    
    if (kill(getpid(), 0) == 0) printf(GREEN "[OK] kill() runs normally.\n" RESET);
    else { printf(RED "[FAILED] kill() blocked unexpectedly.\n" RESET); exit(1); }


    /* ================================================= */
    /* TEST GROUP 4: INVALID CHAR           */
    /* ================================================= */
    printf("\n--- 4.0 - Testing Invalid Characters ('z') ---\n");

    /* Test get_ban with invalid char */
    assert_failure(syscall(SYS_GET_BAN, 'z'), EINVAL, "get_ban('z') should fail");

    /* Test check_ban with invalid char */
    assert_failure(syscall(SYS_CHECK_BAN, getpid(), 'z'), EINVAL, "check_ban(..., 'z') should fail");

    /* Test flip_ban_branch with invalid char */
    assert_failure(syscall(SYS_FLIP_BAN, 1, 'z'), EINVAL, "flip_ban(..., 'z') should fail");


    /* ================================================= */
    /* TEST GROUP 5: PARENT/CHILD              */
    /* ================================================= */
    printf("\n--- 5.0 - Testing FLIP & CHECK (Parent/Child) ---\n");

    pid_t pid = fork();

    if (pid == 0) {
        /* CHILD PROCESS */
        sleep(1); 
        printf("   [Child] Flipping parent ban on 'g'...\n");
        long flipped = syscall(SYS_FLIP_BAN, 1, 'g');
        if (flipped == 1) {
            printf(GREEN "   [Child] Flip successful.\n" RESET);
            exit(0);
        } else {
            printf(RED "   [Child] Flip failed! res=%ld\n" RESET, flipped);
            exit(1);
        }
    } else {
        /* PARENT PROCESS */
        if (syscall(SYS_GET_BAN, 'g') != 0) { printf(RED "Parent started banned?\n" RESET); exit(1); }

        int status;
        wait(&status);
        if (WEXITSTATUS(status) != 0) { printf(RED "Child process failed logic.\n" RESET); exit(1); }

        long am_i_banned = syscall(SYS_GET_BAN, 'g');
        if (am_i_banned == 1) printf(GREEN "[OK] Parent successfully banned by Child.\n" RESET);
        else { printf(RED "[FAILED] Parent NOT banned.\n" RESET); exit(1); }

        /* Cleanup */
        syscall(SYS_SET_BAN, 0, 0, 0);
    }

    printf("\n========== ALL TESTS PASSED ==========\n");
    return 0;
}