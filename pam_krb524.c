/*
 * pam_krb524.c
 * PAM session management functions for pam_krb524.so
 *
 * Copyright © 2007 Tim Abbott <tabbott@mit.edu> and Anders Kaseorg
 * <andersk@mit.edu>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>	/* snprintf */
#include <string.h>	/* strcmp */
#include <unistd.h>	/* unlink, syslog */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>

#define MAXBUF 256


/*
 * Make up a deterministic name for the Kerberos 4 ticket cache from
 * KRB5CCNAME.
 */
static int
get_krb4_name(pam_handle_t *pamh, const char **cache_name, char *cache_name4, size_t len, int debug)
{
    int n;
    *cache_name = pam_getenv(pamh, "KRB5CCNAME");
    if (*cache_name == NULL) {
	if (debug)
	    syslog(LOG_DEBUG, "pam_krb524: No krb5 cache found");
	return PAM_SESSION_ERR;
    }

    if (strncmp(*cache_name, "FILE:/tmp/krb5cc_", 17) == 0)
	n = snprintf(cache_name4, len, "/tmp/tkt_%s", *cache_name + 17);
    else if (strncmp(*cache_name, "/tmp/krb5cc_", 12) == 0)
	n = snprintf(cache_name4, len, "/tmp/tkt_%s", *cache_name + 12);
    else {
	syslog(LOG_ERR, "pam_krb524: Could not get krb4 name from krb5 name: %s", *cache_name);
	return PAM_SESSION_ERR;
    }
    if (n < 0 || n >= len) {
	syslog(LOG_ERR, "pam_krb524: snprintf failed");
	return PAM_BUF_ERR;
    }
    return PAM_SUCCESS;
}

/*
 * Do the Kerberos 4 ticket getting work, using a name based on the
 * name of the Kerberos 5 ticket cache.  The flags are ignored.
 */
int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                    const char **argv)
{
    int i;
    int pamret;
    struct passwd *pw = NULL;
    uid_t uid;
    gid_t gid;
    int debug = 0;
    int pid;
    const char *user = NULL;
    int n;
    char cache_name4[MAXBUF];
    char cache_env_name4[MAXBUF];
    const char *cache_name;
    int status;

    for (i = 0; i < argc; i++) {
	if (strcmp(argv[i], "debug") == 0)
	    debug = 1;
    }

    /* Get username */
    if ((pamret = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
	return PAM_SERVICE_ERR;
    }

    pw = getpwnam(user);
    if (pw == NULL) {
        return PAM_USER_UNKNOWN;
    }
    uid = pw->pw_uid;
    gid = pw->pw_gid;

    if ((pamret = get_krb4_name(pamh, &cache_name, cache_name4, MAXBUF, debug))
	!= PAM_SUCCESS)
	return pamret;

    if (debug)
	syslog(LOG_DEBUG, "pam_krb524: Got krb4 name: %s", cache_name4);

    n = snprintf(cache_env_name4, MAXBUF, "KRBTKFILE=%s", cache_name4);
    if (n < 0 || n >= MAXBUF) {
	syslog(LOG_ERR, "pam_krb524: snprintf failed");
	return PAM_BUF_ERR;
    }

    if ((pamret = pam_putenv(pamh, cache_env_name4)) != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_krb524: pam_putenv(): %s", pam_strerror(pamh, pamret));
	return PAM_SESSION_ERR;
    }

    if ((pid = fork()) == -1) {
	syslog(LOG_ERR, "pam_krb524: fork(): %s", strerror(errno));
	return PAM_SESSION_ERR;
    }
    if (pid == 0) {
	/* setup the environment */
	char buf[MAXBUF], buf4[MAXBUF];
	char *envi[3] = {buf, buf4, NULL};
	n = snprintf(buf, MAXBUF, "KRB5CCNAME=%s", cache_name);
	if (n < 0 || n >= MAXBUF) {
	    syslog(LOG_ERR, "pam_krb524: snprintf failed");
	    _exit(-1);
	}
	n = snprintf(buf4, MAXBUF, "KRBTKFILE=%s", cache_name4);
	if (n < 0 || n >= MAXBUF) {
	    syslog(LOG_ERR, "pam_krb524: snprintf failed");
	    _exit(-1);
	}

	/* make the forked process have the right real UID for krb524init
	   which is very unhappy with uid != euid. */
	if (setregid(gid, gid) != 0 ||
	    setreuid(uid, uid) != 0) {
	    syslog(LOG_ERR, "pam_krb524: could not set egid and euid");
	    _exit(-1);
	}

	execle("/usr/bin/krb524init", "krb524init", NULL, envi);
	syslog(LOG_ERR, "pam_krb524: execle(): %s", strerror(errno));
	_exit(-1);
    }
    if (waitpid(pid, &status, 0) == -1) {
	syslog(LOG_ERR, "pam_krb524: waitpid(): %s", strerror(errno));
	return PAM_SESSION_ERR;
    }
    if (!WIFEXITED(status)) {
	syslog(LOG_ERR, "pam_krb524: krb524init failed");
	return PAM_SESSION_ERR;
    }
    if (debug)
	syslog(LOG_DEBUG, "pam_krb524: Success: %s", cache_name4);

    return PAM_SUCCESS;
}


/* Terminate session management. */
int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int	i;
    int pamret;
    const char *cache_name;
    char cache_name4[MAXBUF];
    int	debug = 0;

    for (i = 0; i < argc; i++) {
	if (strcmp(argv[i], "debug") == 0)
	    debug = 1;
    }

    if ((pamret = get_krb4_name(pamh, &cache_name, cache_name4, MAXBUF, debug))
	!= PAM_SUCCESS)
	return pamret;

    if (debug)
	syslog(LOG_DEBUG, "pam_krb524: Unlinking %s", cache_name4);
    unlink(cache_name4);
    return PAM_SUCCESS;
}


int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (flags == PAM_ESTABLISH_CRED)
	return pam_sm_open_session(pamh, flags, argc, argv);
    return PAM_SUCCESS;
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}
