/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "ldap.h"

/**
 * $Id$
 * @file sasl.c
 * @brief Functions to perform SASL binds against an LDAP directory.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 The FreeRADIUS Server Project.
 */
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <sasl/sasl.h>

#include <gssapi/gssapi_krb5.h>


static void display_gss_error(int type, OM_uint32 code) {
	OM_uint32 maj, min, ctx = 0;
	gss_buffer_desc status;

	do {
		maj = gss_display_status(&min,
					 code,
					 type,
					 GSS_C_NO_OID,
					 &ctx,
					 &status);
		if (GSS_ERROR(maj)) {
			DEBUG("Bad gss error!");
			break;
		} else {
			DEBUG("%.*s\n", (int) status.length, (char *) status.value);
			gss_release_buffer(&min, &status);
		}
	} while (ctx != 0);
}

static void log_gss_error(const char *prefix, uint32_t maj, uint32_t min)
{
	DEBUG("%s: ", prefix);
	display_gss_error(GSS_C_GSS_CODE, maj);
	display_gss_error(GSS_C_MECH_CODE, min);
}

static void display_gss_name(gss_name_t name) {
	OM_uint32 maj, min;
	gss_buffer_desc output_name_buffer = GSS_C_EMPTY_BUFFER;

	maj = gss_display_name(&min, name, &output_name_buffer, NULL);
	if (GSS_ERROR(maj)) {
		log_gss_error("display_gss_name: failed", maj, min);
		return;
	}

	DEBUG("GSS cache principal: %.*s",
		(int) output_name_buffer.length,
		(char *) output_name_buffer.value);

	gss_release_buffer(&min, &output_name_buffer);
}

/* This fucntion assumes per thread ccache was already set */
int verify_krb5_creds(void);
int verify_krb5_creds(void)
{
	OM_uint32 maj, min, lifetime = 0;
	gss_name_t cache_principal = GSS_C_NO_NAME;

	maj = gss_inquire_cred(&min, GSS_C_NO_CREDENTIAL,
				&cache_principal, &lifetime, NULL, NULL);
	if (GSS_ERROR(maj)) {
		log_gss_error("gss_inquire_cred: cache failed", maj, min);
		return FALSE;
	}

	DEBUG("GSS credentials valid for <%u> seconds", lifetime);

	display_gss_name(cache_principal);
	gss_release_name(&min, &cache_principal);

	return TRUE;
}

gss_cred_id_t acquire_cred_from_cache(const char *ccache);
gss_cred_id_t acquire_cred_from_cache(const char *ccache)
{
	OM_uint32 maj, min;
	gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
	gss_key_value_element_desc store_elm = { "ccache", ccache };
	gss_key_value_set_desc store = { 1, &store_elm };

	maj = gss_acquire_cred_from(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
					GSS_C_NO_OID_SET, GSS_C_INITIATE, &store,
					&creds, NULL, NULL);
	if (GSS_ERROR(maj)) {
		log_gss_error("gss_acquire_cred_from()", maj, min);
		return GSS_C_NO_CREDENTIAL;
	}

	return creds;
}

/** Data passed to the _sasl interact callback.
 *
 */
typedef struct rlm_ldap_sasl_ctx {
	rlm_ldap_t const	*inst;		//!< LDAP instance
	REQUEST			*request;	//!< The current request.

	char const		*identity;	//!< User's DN or identity.
	char const		*password;	//!< Bind password.

	ldap_sasl		*extra;		//!< Extra fields (realm and proxy id).
} rlm_ldap_sasl_ctx_t;

#define do_ldap_option(_option, _name, _value) \
	if (ldap_set_option(handle, _option, _value) != LDAP_OPT_SUCCESS) { \
		ldap_get_option(handle, LDAP_OPT_ERROR_NUMBER, &ldap_errno); \
		LDAP_ERR("Failed setting connection option %s: %s", _name, \
			 (ldap_errno != LDAP_SUCCESS) ? ldap_err2string(ldap_errno) : "Unknown error"); \
	}
/** Callback for ldap_sasl_interactive_bind
 *
 * @param handle used for the SASL bind.
 * @param flags data as provided to ldap_sasl_interactive_bind.
 * @param ctx Our context data, containing the identity, password, realm and various other things.
 * @param sasl_callbacks Array of challenges to provide responses for.
 * @return SASL_OK.
 */
static int _sasl_interact(LDAP *handle, UNUSED unsigned flags, void *ctx, void *sasl_callbacks)
{
	rlm_ldap_sasl_ctx_t	*this = ctx;
	REQUEST			*request = this->request;
	rlm_ldap_t const	*inst = this->inst;
	sasl_interact_t		*cb = sasl_callbacks;
	sasl_interact_t		*cb_p;
	int			ldap_errno = 0;

	gss_cred_id_t creds = acquire_cred_from_cache("/tmp/krb5cc_fr");
	if (creds != GSS_C_NO_CREDENTIAL) {
		DEBUG("WE GOT CREDS !!!");
		verify_krb5_creds();
		do_ldap_option(LDAP_OPT_X_SASL_GSS_CREDS, "SASL_GSS_CREDS", creds);
	}


	for (cb_p = cb; cb_p->id != SASL_CB_LIST_END; cb_p++) {
		MOD_ROPTIONAL(RDEBUG3, DEBUG3, "SASL challenge : %s", cb_p->challenge);
		MOD_ROPTIONAL(RDEBUG3, DEBUG3, "SASL prompt    : %s", cb_p->prompt);

		switch (cb_p->id) {
		case SASL_CB_AUTHNAME:
			cb_p->result = this->identity;
			break;

		case SASL_CB_PASS:
			cb_p->result = this->password;
			break;

		case SASL_CB_USER:
			cb_p->result = this->extra->proxy ? this->extra->proxy : this->identity;
			break;

		case SASL_CB_GETREALM:
			if (this->extra->realm) cb_p->result = this->extra->realm;
			break;

		default:
			break;
		}
		MOD_ROPTIONAL(RDEBUG3, DEBUG3, "SASL result    : %s", cb_p->result ? (char const *)cb_p->result : "");
	}
	return SASL_OK;
}

/** Initiate an LDAP interactive bind
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request, this may be NULL, in which case all debug logging is done with radlog.
 * @param[in] conn to use. May change as this function calls functions which auto re-connect.
 * @param[in] identity of the user.
 * @param[in] password of the user.
 * @param[in] sasl mechanism to use for bind, and additional parameters.
 * @param[out] error message resulting from bind.
 * @param[out] extra information about the error.
 * @return One of the LDAP_PROC_* (#ldap_rcode_t) values.
 */
ldap_rcode_t rlm_ldap_sasl_interactive(rlm_ldap_t const *inst, REQUEST *request,
				       ldap_handle_t *conn, char const *identity,
				       char const *password, ldap_sasl *sasl,
				       char const **error, char **extra)
{
	ldap_rcode_t		status;
	int			ret = 0;
	int			msgid;
	char const		*mech;
	LDAPMessage		*result = NULL;
	rlm_ldap_sasl_ctx_t	sasl_ctx;		/* SASL defaults */

	/* rlm_ldap_result may not be called */
	if (error) *error = NULL;
	if (extra) *extra = NULL;

	sasl_ctx.inst = inst;
	sasl_ctx.request = request;
	sasl_ctx.identity = identity;
	sasl_ctx.password = password;
	sasl_ctx.extra = sasl;

	MOD_ROPTIONAL(RDEBUG2, DEBUG2, "Starting SASL mech(s): %s", sasl->mech);
	for (;;) {
		ret = ldap_sasl_interactive_bind(conn->handle, NULL, sasl->mech,
						 NULL, NULL, LDAP_SASL_AUTOMATIC,
						 _sasl_interact, &sasl_ctx, result,
						 &mech, &msgid);

		/*
		 *	If ldap_sasl_interactive_bind indicates it didn't want
		 *	to continue, then we're done.
		 *
		 *	Calling ldap_result here, results in a timeout in some
		 *	cases, so we need to figure out whether the bind was
		 *	successful without the help of ldap_result.
		 */
		if (ret != LDAP_SASL_BIND_IN_PROGRESS) {
			status = rlm_ldap_result(inst, conn, -1, identity, NULL, error, extra);
			break;		/* Old result gets freed on after exit */
		}

		ldap_msgfree(result);	/* We always need to free the old message */

		/*
		 *	If LDAP parse result indicates there was an error
		 *	then we're done.
		 */
		status = rlm_ldap_result(inst, conn, msgid, identity, &result, error, extra);
		switch (status) {
		case LDAP_PROC_SUCCESS:		/* ldap_sasl_interactive_bind should have indicated success */
		case LDAP_PROC_CONTINUE:
			break;

		default:
			goto done;
		}

		/*
		 *	...otherwise, the bind is still in progress.
		 */
		MOD_ROPTIONAL(RDEBUG3, DEBUG3, "Continuing SASL mech %s...", mech);

		/*
		 *	Write the servers response to the debug log
		 */
		if (((request && RDEBUG_ENABLED3) || DEBUG_ENABLED3) && result) {
			struct berval *srv_cred;

			if ((ldap_parse_sasl_bind_result(conn->handle, result, &srv_cred, 0) == LDAP_SUCCESS) &&
			    (srv_cred != NULL)) {
				char *escaped;

				escaped = fr_aprints(request, srv_cred->bv_val, srv_cred->bv_len, '\0');
				MOD_ROPTIONAL(RDEBUG3, DEBUG3, "SASL response  : %s", escaped);

				talloc_free(escaped);
				ldap_memfree(srv_cred);
			}
		}
	}
done:
	ldap_msgfree(result);

	return status;
}
