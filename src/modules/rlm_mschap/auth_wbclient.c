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

/**
 * $Id$
 * @file auth_wbclient.c
 * @brief NTLM authentication against the wbclient library
 *
 * @copyright 2015  Matthew Newton
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <core/ntstatus.h>

#include "rlm_mschap.h"
#include "mschap.h"
#include "auth_wbclient.h"

#define NT_LENGTH 24

/** Use Winbind to normalise a username
 *
 * @param[in] tctx The talloc context where the result is parented from
 * @param[in] ctx The winbind context
 * @param[in] dom_name The domain of the user
 * @param[in] name The username (without the domain) to be normalised
 * @return The username with the casing according to the Winbind remote server,
 *         or NULL if the username could not be found.
 */
static char *wbclient_normalise_username(TALLOC_CTX *tctx, struct wbcContext *ctx, char const *dom_name, char const *name)
{
	struct wbcDomainSid sid;
	enum wbcSidType name_type;
	wbcErr err;
	char *res_domain = NULL;
	char *res_name = NULL;
	char *res = NULL;

	/* Step 1: Convert a name to a sid */
	err = wbcCtxLookupName(ctx, dom_name, name, &sid, &name_type);
	if (!WBC_ERROR_IS_OK(err))
		return NULL;

	/* Step 2: Convert the sid back to a name */
	err = wbcCtxLookupSid(ctx, &sid, &res_domain, &res_name, &name_type);
	if (!WBC_ERROR_IS_OK(err))
		return NULL;

	MEM(res = talloc_strdup(tctx, res_name));

	wbcFreeMemory(res_domain);
	wbcFreeMemory(res_name);

	return res;
}


/** Perform AD-Group comparison checking
 *
 * @param instance of the rlm_machap module.
 * @param request Current request.
 * @param thing Unknown.
 * @param check Which group to check for user membership.
 * @param check_pairs Unknown.
 * @param reply_pairs Unknown.
 * @return
 *	- 1 on failure (or if the user is not a member).
 *	- 0 on success.
 */
int rlm_mschap_wb_groupcmp(void *instance, REQUEST *request, UNUSED VALUE_PAIR *thing,
				VALUE_PAIR *check, UNUSED VALUE_PAIR *check_pairs,
				UNUSED VALUE_PAIR **reply_pairs)
{
	rlm_mschap_t	*inst = instance;
	VALUE_PAIR	*groups = NULL;
	struct wbcContext *wb_ctx = NULL;
	wbcErr err;
	struct wbcDomainSid sid;
	enum wbcSidType type;
	char *sid_str = NULL;

	RDEBUG("Checking if user is member of AD group \"%s\"", check->vp_strvalue);

	if (check->vp_length == 0) {
		REDEBUG("Cannot do comparison (AD group is empty)");
		return 1;
	}

	wb_ctx = fr_connection_get(inst->wb_pool);
	if (wb_ctx == NULL) {
		RERROR("Unable to get winbind connection from pool");
		return 1;
	}

	/* TODO: Parse domain part from check group (DOM\group), though
	   passing it directly seem to work just fine */

	err = wbcCtxLookupName(wb_ctx, ""/*domain*/, check->vp_strvalue, &sid, &type);

	/* We are done with the context */
	fr_connection_release(inst->wb_pool, wb_ctx);

	if (!WBC_ERROR_IS_OK(err)) {
		REDEBUG2("wbcCtxLookupName() failed for group: %s", check->vp_strvalue);
		REDEBUG2("Error message: %s", wbcErrorString(err));

		return 1;
	}

	err = wbcSidToString(&sid, &sid_str);
	if (!WBC_ERROR_IS_OK(err)) {
		REDEBUG2("Failed to decode group SID, error: %s", wbcErrorString(err));

		return 1;
	}

	RDEBUG("Resolved SID: <%s>, type: <%s>", sid_str, wbcSidTypeString(type));

	// TODO: Cache group name to SID mapping!

	groups = fr_pair_find_by_da(request->config, dict_attrbyname("AD-Group-SID"), TAG_ANY);
	while (groups) {
		if (!strncmp(sid_str, groups->vp_strvalue, groups->vp_length))
		{
			RDEBUG("Found matching group SID: <%s>", sid_str);
			wbcFreeMemory(sid_str);

			return 0;
		}
		RDEBUG("User's group SID: <%s> did not match", groups->vp_strvalue);
		groups = groups->next;
	}

	RDEBUG("Group SID <%s> did not match any of user's SIDs", sid_str);
	wbcFreeMemory(sid_str);

	return 1;
}

/*
 *	Check NTLM authentication direct to winbind via
 *	Samba's libwbclient library
 *
 *	Returns:
 *	 0    success
 *	 -1   auth failure
 *	 -2   failed connecting to AD
 *	 -648 password expired
 */
int do_auth_wbclient(rlm_mschap_t *inst, REQUEST *request,
		     uint8_t const *challenge, uint8_t const *response,
		     uint8_t nthashhash[NT_DIGEST_LENGTH])
{
	int rcode = -1;
	struct wbcContext *wb_ctx = NULL;
	struct wbcAuthUserParams authparams;
	wbcErr err;
	int len;
	struct wbcAuthUserInfo *info = NULL;
	struct wbcAuthErrorInfo *error = NULL;
	char user_name_buf[500];
	char domain_name_buf[500];
	uint8_t resp[NT_LENGTH];

	/*
	 * Clear the auth parameters - this is important, as
	 * there are options that will cause wbcAuthenticateUserEx
	 * to bomb out if not zero.
	 */
	memset(&authparams, 0, sizeof(authparams));

	/*
	 * wb_username must be set for this function to be called
	 */
	rad_assert(inst->wb_username);

	/*
	 * Get the username and domain from the configuration
	 */
	len = tmpl_expand(&authparams.account_name, user_name_buf, sizeof(user_name_buf),
			  request, inst->wb_username, NULL, NULL);
	if (len < 0) {
		REDEBUG2("Unable to expand winbind_username");
		goto done;
	}

	if (inst->wb_domain) {
		len = tmpl_expand(&authparams.domain_name, domain_name_buf, sizeof(domain_name_buf),
				  request, inst->wb_domain, NULL, NULL);
		if (len < 0) {
			REDEBUG2("Unable to expand winbind_domain");
			goto done;
		}
	} else {
		RWDEBUG2("No domain specified; authentication may fail because of this");
	}


	/*
	 * Build the wbcAuthUserParams structure with what we know
	 */
	authparams.level = WBC_AUTH_USER_LEVEL_RESPONSE;
	authparams.password.response.nt_length = NT_LENGTH;

	memcpy(resp, response, NT_LENGTH);
	authparams.password.response.nt_data = resp;

	memcpy(authparams.password.response.challenge, challenge,
	       sizeof(authparams.password.response.challenge));

	authparams.parameter_control |= WBC_MSV1_0_ALLOW_MSVCHAPV2 |
					WBC_MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT |
					WBC_MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT;


	/*
	 * Send auth request across to winbind
	 */
	wb_ctx = fr_connection_get(inst->wb_pool);
	if (wb_ctx == NULL) {
		RERROR("Unable to get winbind connection from pool");
		goto done;
	}

	RDEBUG2("sending authentication request user='%s' domain='%s'", authparams.account_name,
									authparams.domain_name);

	err = wbcCtxAuthenticateUserEx(wb_ctx, &authparams, &info, &error);

	if (err == WBC_ERR_AUTH_ERROR && inst->wb_retry_with_normalised_username) {
		VALUE_PAIR *vp_response, *vp_challenge;
		char *normalised_username = wbclient_normalise_username(request, wb_ctx, authparams.domain_name, authparams.account_name);
		if (normalised_username) {
			RDEBUG2("Starting retry, normalised username %s to %s", authparams.account_name, normalised_username);
			if (strcmp(authparams.account_name, normalised_username) != 0) {
				authparams.account_name = normalised_username;

				/* Set PW_MS_CHAP_USER_NAME */
				if (!fr_pair_make(request->packet, &request->packet->vps, "MS-CHAP-User-Name", normalised_username, T_OP_SET)) {
					RERROR("Failed creating MS-CHAP-User-Name");
					goto normalised_username_retry_failure;
				}

				RDEBUG2("retrying authentication request user='%s' domain='%s'", authparams.account_name,
												authparams.domain_name);

				/* Recalculate hash */
				if (!(vp_challenge = fr_pair_find_by_num(request->packet->vps, PW_MSCHAP_CHALLENGE, VENDORPEC_MICROSOFT, TAG_ANY))) {
					RERROR("Unable to get MS-CHAP-Challenge");
					goto normalised_username_retry_failure;
				}
				if (!(vp_response = fr_pair_find_by_num(request->packet->vps, PW_MSCHAP2_RESPONSE, VENDORPEC_MICROSOFT, TAG_ANY))) {
					RERROR("Unable to get MS-CHAP2-Response");
					goto normalised_username_retry_failure;
				}
				mschap_challenge_hash(vp_response->vp_octets + 2,
									vp_challenge->vp_octets,
									normalised_username,
									authparams.password.response.challenge);

				err = wbcCtxAuthenticateUserEx(wb_ctx, &authparams, &info, &error);
			}
normalised_username_retry_failure:
			talloc_free(normalised_username);
		}
	}

	fr_connection_release(inst->wb_pool, wb_ctx);

	/*
	 * Try and give some useful feedback on what happened. There are only
	 * a few errors that can actually be returned from wbcCtxAuthenticateUserEx.
	 */
	switch (err) {
	case WBC_ERR_SUCCESS:
		rcode = 0;
		RDEBUG2("Authenticated successfully");

		/* TODO: save more info on request */
		RDEBUG2("User: %s, UPN: %s logon-server: %s",
			info->account_name, info->user_principal, info->logon_server);

		RDEBUG2("Number of user's SIDs: %u", info->num_sids);

		/* Note: sids[0] = user, sids[1] = primary group */
		for(unsigned i = 0; i < info->num_sids; ++i) {
			REQUEST *outer = request->parent ?: request;

			char *sid_str = NULL;
			wbcErr ret = wbcSidToString(&info->sids[i].sid, &sid_str);
			if (!WBC_ERROR_IS_OK(ret))
			{
				RDEBUG2("Failed to decode SID num [%u]", i);
			}
			else if (fr_pair_make(outer, &outer->config, "AD-Group-SID", sid_str, T_OP_ADD))
			{
				RDEBUG2("SID [%s] was added to outer config list", sid_str);
			}
			else
			{
				RDEBUG2("Failed adding SID [%s] to outer config list", sid_str);
			}
			wbcFreeMemory(sid_str);
		}
		/* Grab the nthashhash from the result */
		memcpy(nthashhash, info->user_session_key, NT_DIGEST_LENGTH);
		break;
	case WBC_ERR_WINBIND_NOT_AVAILABLE:
		rcode = -2;
		RERROR("Unable to contact winbind!");
		RDEBUG2("Check that winbind is running and that FreeRADIUS has");
		RDEBUG2("permission to connect to the winbind privileged socket.");
		break;
	case WBC_ERR_DOMAIN_NOT_FOUND:
		REDEBUG2("Domain not found");
		break;
	case WBC_ERR_AUTH_ERROR:
		if (!error) {
			REDEBUG2("Authentication failed");
			break;
		}

		/*
		 * The password needs to be changed, so set rcode appropriately.
		 */
		if (error->nt_status == NT_STATUS_PASSWORD_EXPIRED ||
		    error->nt_status == NT_STATUS_PASSWORD_MUST_CHANGE) {
			rcode = -648;
		}

		/*
		 * Return the NT_STATUS human readable error string, if there is one.
		 */
		if (error->display_string) {
			REDEBUG2("%s [0x%X]", error->display_string, error->nt_status);
		} else {
			REDEBUG2("Authentication failed [0x%X]", error->nt_status);
		}
		break;
	default:
		/*
		 * Only errors left are 
		 *   WBC_ERR_INVALID_PARAM
		 *   WBC_ERR_NO_MEMORY
		 * neither of which are particularly likely.
		 */
		rcode = -2;
		if (error && error->display_string) {
			REDEBUG2("libwbclient error: wbcErr %d (%s)", err, error->display_string);
		} else {
			REDEBUG2("libwbclient error: wbcErr %d", err);
		}
		break;
	}


done:
	if (info) wbcFreeMemory(info);
	if (error) wbcFreeMemory(error);

	return rcode;
}

