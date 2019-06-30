#include "config.h"

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cache/cache_varnishd.h>
#include <cache/cache_filter.h>
#include <vcl.h>


#include "vcc_sec_if.h"
#include "vsa.h"
#include "vre.h"
#include "vsb.h"


static enum vfp_status v_matchproto_(vfp_init_f)
vfp_modsec_init(struct vfp_ctx *ctx, struct vfp_entry *ent);
static void v_matchproto_(vfp_fini_f)
vfp_modsec_fini(struct vfp_ctx *ctx, struct vfp_entry *ent);
static enum vfp_status v_matchproto_(vfp_pull_f)
vfp_modsec_pull(struct vfp_ctx *ctx, struct vfp_entry *ent, void *ptr,
	    ssize_t *lenp);
int process_intervention (const struct vrt_ctx *ctx, Transaction *t);


struct vmod_sec_sec {
	unsigned	magic;	// same magic as vmod obj | below
#define VMOD_SEC_SEC_MAGIC_BITS	0x07a91234
	ModSecurity *modsec;
	Rules *rules_set;
};


void vmod_sec_log_callback(void *ref, const void *message) {
	VSL(SLT_Error, 0, "[vmodsec] - Logger");
	VSL(SLT_Error, 0, "%s", (const char *)message);
}

void vmod_modsec_free(void *vmod_priv){
	free((void *)((struct vfp *)vmod_priv)->name);
	free(vmod_priv);
}

int event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e event) {
	return (0);
	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(priv);
	struct vfp *vfp_modsec;

	switch (event) {
		case VCL_EVENT_LOAD:
		case VCL_EVENT_WARM:
			vfp_modsec = malloc(sizeof(struct vfp));
			vfp_modsec->name = malloc(sizeof("modsec"));
			vfp_modsec->name = "modsec";
			vfp_modsec->init = vfp_modsec_init;
			vfp_modsec->pull = vfp_modsec_pull;
			vfp_modsec->fini = vfp_modsec_fini;
			vfp_modsec->priv1 = priv;
			priv->priv = vfp_modsec;
			priv->free = vmod_modsec_free;
			VRT_AddVFP(ctx, vfp_modsec);
			return (0);

		case VCL_EVENT_COLD:
		case VCL_EVENT_DISCARD:
			VRT_RemoveVFP(ctx, priv->priv);
			return (0);
	}
	NEEDLESS(return (0));
}

/*
 * Initialising structure for modsec object
 */
VCL_VOID
vmod_sec__init(VRT_CTX, struct vmod_sec_sec **vpp,
    const char *vcl_name) {

	struct vmod_sec_sec *vp;		
	ModSecurity *modsec;
	Rules *rules_set;
	int error;

	(void)vcl_name;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(vpp);
	AZ(*vpp);

	VSL(SLT_Error, 0, "[vmodsec] - object [%s] initialized using modsecurity %s",
	    vcl_name, MODSECURITY_VERSION);

	modsec = msc_init();
	msc_set_connector_info(modsec, PACKAGE_STRING);
	rules_set = msc_create_rules_set();

	msc_set_log_cb(modsec, vmod_sec_log_callback);
	ALLOC_OBJ(vp, VMOD_SEC_SEC_MAGIC_BITS);
	AN(vp);
	*vpp=vp;
	vp->modsec = modsec;
	vp->rules_set = rules_set;
}

/*
 * Cleaning up after me
 */
VCL_VOID
vmod_sec__fini(struct vmod_sec_sec **vpp) {
	struct vmod_sec_sec *vp;

	AN(*vpp);
	vp = *vpp;
	*vpp = NULL;
	CHECK_OBJ_NOTNULL(vp, VMOD_SEC_SEC_MAGIC_BITS);
	msc_rules_cleanup(vp->rules_set);
	msc_cleanup(vp->modsec);
	FREE_OBJ(vp);
}

VCL_INT vmod_sec_add_remote_rules(VRT_CTX, struct vmod_sec_sec *vp,
    VCL_STRING key, VCL_STRING main_rules_uri) {
	Rules *rules_set;
	int ret;
    const char *error = NULL;

	VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Try to load the rules", main_rules_uri);
	CHECK_OBJ_NOTNULL(vp, VMOD_SEC_SEC_MAGIC_BITS);
	rules_set = msc_create_rules_set();
    ret = msc_rules_add_remote(rules_set, key, main_rules_uri, &error);
    if (ret < 0) {
        VSL(SLT_Error, 0, "[vmodsec] - Problems loading the rules --\n");
        VSL(SLT_Error, 0, "%s\n", error);
		return -1;
    }
	VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Loaded the rules", main_rules_uri);
	VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Merging rules in main rule set", main_rules_uri);
	ret = msc_rules_merge(vp->rules_set, rules_set, &error);
    if (ret < 0) {
        VSL(SLT_Error, 0, "[vmodsec] - Problems merging the rules --\n");
        VSL(SLT_Error, 0, "%s\n", error);
		return -1;
    }
	VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Merged rules", main_rules_uri);
	return 0;
}

VCL_INT vmod_sec_add_rules(VRT_CTX, struct vmod_sec_sec *vp,
    VCL_STRING main_rules_uri) {
	Rules *rules_set;
	int ret;
    const char *error = NULL;

	VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Try to load the rules", main_rules_uri);
	CHECK_OBJ_NOTNULL(vp, VMOD_SEC_SEC_MAGIC_BITS);
	rules_set = msc_create_rules_set();
    ret = msc_rules_add_file(rules_set, main_rules_uri, &error);
    if (ret < 0) {
        VSL(SLT_Error, 0, "[vmodsec] - Problems loading the rules --\n");
        VSL(SLT_Error, 0, "%s\n", error);
		return -1;
    }
	VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Loaded the rules", main_rules_uri);
	VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Merging rules in main rule set", main_rules_uri);
	ret = msc_rules_merge(vp->rules_set, rules_set, &error);
    if (ret < 0) {
        VSL(SLT_Error, 0, "[vmodsec] - Problems merging the rules --\n");
        VSL(SLT_Error, 0, "%s\n", error);
		return -1;
    }
	VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Merged rules", main_rules_uri);
	return 0;
}

VCL_INT vmod_sec_dump_rules(VRT_CTX, struct vmod_sec_sec *vp) {
	CHECK_OBJ_NOTNULL(vp, VMOD_SEC_SEC_MAGIC_BITS);
	msc_rules_dump(vp->rules_set);
}

VCL_INT vmod_sec_new_conn(VRT_CTX,
    struct vmod_sec_sec *vp, struct vmod_priv *priv, VCL_STRING client_ip, VCL_INT client_port,
    VCL_STRING server_ip, VCL_INT server_port) {
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	if (priv->priv == NULL) {
		priv->priv = msc_new_transaction(vp->modsec, vp->rules_set, priv);
		priv->free = (void *)(void *)msc_transaction_cleanup;
	}
	msc_process_connection((Transaction *)(priv->priv), client_ip, client_port, server_ip, server_port);
	VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Started processing Transaction for [%s:%ld] with server [%s:%ld]", client_ip, client_port, server_ip, server_port);
	msc_process_logging((Transaction *)(priv->priv));
	process_intervention(ctx, (Transaction *)(priv->priv));
	return 0;
}

char *ltrim(char *str, const char *seps)
{
    size_t totrim;
    if (seps == NULL) {
        seps = "\t\n\v\f\r ";
    }
    totrim = strspn(str, seps);
    if (totrim > 0) {
        size_t len = strlen(str);
        if (totrim == len) {
            str[0] = '\0';
        }
        else {
            memmove(str, str + totrim, len + 1 - totrim);
        }
    }
    return str;
}

VCL_INT vmod_sec_process_url(VRT_CTX,
	struct vmod_sec_sec *vp, struct vmod_priv *priv, 
	VCL_STRING req_url, VCL_STRING protocol, VCL_STRING http_version) {
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	if (priv->priv == NULL) {
		VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - connection has not been started, closing");
		return -1;
	}
	/* This will be used to Initialise the original URL */
	msc_process_uri((Transaction *)(priv->priv), req_url, protocol, http_version);
	VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Processing URI : [%s] on protocol [%s] with version [%s]", req_url, protocol, http_version);
	VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Checking intevention");
	process_intervention(ctx, (Transaction *)(priv->priv));
	VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Processing Request Logging");
	msc_process_logging((Transaction *)(priv->priv));

	/* Handling headers */
	unsigned u;
	const struct http *hp = ctx->req->http;
	VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Found %d headers, Start at %d, need to ingest %d headers", hp->nhd, HTTP_HDR_FIRST, hp->nhd - HTTP_HDR_FIRST);
	char *headerName = malloc(8192);
	char *headerValue = malloc(8192);

	for (u = HTTP_HDR_FIRST; u < hp->nhd; u++) {
		Tcheck(hp->hd[u]);
		const char *header = hp->hd[u].b;
		long int hlen = strlen(header);
		int pos = (strchr(header, ':')-header);
		// XXX: use a workspace (in priv?)
		if (pos < 0 || pos > 8191 || hlen-pos > 8191) {
			continue;
		}
		/* Copy headers */
		strncpy(headerName, header, pos);
		headerName[pos]='\0';
		strncpy(headerValue, &header[pos+1], hlen-pos-1);
		headerValue[hlen-pos-1]='\0';
		ltrim(headerValue, " "); // TODO Check RFC to confirm [WS] is the only valid
		msc_add_request_header((Transaction *)(priv->priv), headerName, headerValue);
		VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Additional header provided %s: %s", headerName, headerValue);
	}
	free(headerName);
	free(headerValue);
	VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Processing Request Headers");
	msc_process_request_headers((Transaction *)(priv->priv));
	VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Processing Request Logging");
	msc_process_logging((Transaction *)(priv->priv));
	VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Checking intevention");
	process_intervention(ctx, (Transaction *)(priv->priv));
	return (0);
}

static int
vmod_sec_read_request_body(void *priv, int flush, const void *ptr, ssize_t len)
{

	AN(priv);
	(void)flush;
	int ret;
	ret = (msc_append_request_body(((Transaction *)((struct vmod_priv *)priv)->priv), ptr, len)) == 1? 0 : -1;
	VSL(SLT_Debug, 0, "[vmodsec] - Reading request body [%ld] read, [%d] ret", len, ret);
	return ret;

}


VCL_INT vmod_sec_do_process_request_body(VRT_CTX,
    struct vmod_sec_sec *vp, struct vmod_priv *priv) {
		CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
		CHECK_OBJ_NOTNULL(ctx->req, REQ_MAGIC);
		AN(ctx->vsl);

		if (priv->priv == NULL) {
			VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - connection has not been started, closing");
			return -1;
		}
		const struct http *hp = ctx->req->http;
		if (ctx->req->req_body_status != REQ_BODY_CACHED) {
			VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Unbuffered req.body");
			return -1;
		}

		int ret;

		ret = VRB_Iterate(ctx->req, vmod_sec_read_request_body, priv);

		VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Body Iteration Done");

		if (ret < 0) {
			VSL(SLT_Error, ctx->sp->vxid, "[vmodsec] - Iteration on req.body didn't succeed. %d", ret);

			return -1;
		}

		VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Processing Request Body");
		msc_process_request_body((Transaction *)(priv->priv));
		msc_process_logging((Transaction *)(priv->priv));
		process_intervention(ctx, (Transaction *)(priv->priv));
		return 0;
	}


VCL_INT vmod_sec_process_response(VRT_CTX,
    struct vmod_sec_sec *vp, struct vmod_priv *priv) {
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	if (priv->priv == NULL) {
		VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - connection has not been started, closing");
		return -1;
	}
	/* Handling headers */
	unsigned u;
	const struct http *hp = ctx->req->resp;
	VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Processing Response Headers");
	VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Found %d headers, Start at %d, need to ingest %d headers", hp->nhd, HTTP_HDR_FIRST, hp->nhd - HTTP_HDR_FIRST);

	char *headerName = malloc(8192);
	char *headerValue = malloc(8192);

	for (u = HTTP_HDR_FIRST; u < hp->nhd; u++) {
		Tcheck(hp->hd[u]);
		const char *header = hp->hd[u].b;
		long int hlen = strlen(header);
		int pos = (strchr(header, ':')-header);
		// XXX: use a workspace (in priv?)
		if (pos < 0 || pos > 8191 || hlen-pos > 8191) {
			continue;
		}
		/* Copy headers */
		strncpy(headerName, header, pos);
		headerName[pos]='\0';
		strncpy(headerValue, &header[pos+1], hlen-pos-1);
		headerValue[hlen-pos-1]='\0';
		ltrim(headerValue, " "); // TODO Check RFC to confirm [WS] is the only valid PS : will be faster to use a single copy instead of ltrim
		msc_add_response_header((Transaction *)(priv->priv), headerName, headerValue);
		VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Additional response header provided %s: %s", headerName, headerValue);
	}
	free(headerName);
	free(headerValue);
	msc_process_response_headers((Transaction *)(priv->priv), ctx->req->resp->status, "HTTP 1.1"); // Fixme get protocol dynamic
	msc_process_logging((Transaction *)(priv->priv));
	process_intervention(ctx, (Transaction *)(priv->priv));
	return 0;
}

static int
vmod_sec_read_response_body(void *priv, int flush, const void *ptr, ssize_t len)
{

	AN(priv);
	(void)flush;
	int ret;
	ret = (msc_append_response_body(((Transaction *)((struct vmod_priv *)priv)->priv), ptr, len)) == 1? 0 : -1;
	VSL(SLT_Debug, 0, "[vmodsec] - Reading response body [%ld] read, [%d] ret", len, ret);
	return ret;

}

VCL_INT vmod_sec_do_process_response_body(VRT_CTX,
    struct vmod_sec_sec *vp, struct vmod_priv *priv) {
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(ctx->req, REQ_MAGIC);
	AN(ctx->vsl);

	if (priv->priv == NULL) {
		VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - connection has not been started, closing");
		return -1;
	}

	int ret;
	// int ObjIterate(struct worker *, struct objcore *, void *priv, objiterate_f *func, int final);
	// Final must be kept to 0 otherwise, we do lose the process
	ret = ObjIterate(ctx->req->wrk, ctx->req->objcore, priv, vmod_sec_read_response_body, 0);

	VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Body Iteration Done");

	if (ret < 0) {
		VSL(SLT_Error, ctx->sp->vxid, "[vmodsec] - Iteration on resp.body didn't succeed. %d", ret);

		return -1;
	}

	VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Processing Response Body");
	msc_process_response_body((Transaction *)(priv->priv));
	msc_process_logging((Transaction *)(priv->priv));
	process_intervention(ctx, (Transaction *)(priv->priv));
	return 0;
}

static enum vfp_status v_matchproto_(vfp_init_f)
vfp_modsec_init(struct vfp_ctx *ctx, struct vfp_entry *ent)
{
	return (VFP_OK);
}

static void v_matchproto_(vfp_fini_f)
vfp_modsec_fini(struct vfp_ctx *ctx, struct vfp_entry *ent)
{

}

static enum vfp_status v_matchproto_(vfp_pull_f)
vfp_modsec_pull(struct vfp_ctx *ctx, struct vfp_entry *ent, void *ptr,
	    ssize_t *lenp)
{
	return (VFP_OK);
}

int process_intervention (const struct vrt_ctx *ctx, Transaction *t)
{
    ModSecurityIntervention intervention;
    intervention.status = 0;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;

    int z = msc_intervention(t, &intervention);

    if (z == 0)
    {
		VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Intervention Unnecessary");
        return 0;
    }

    if (intervention.log == NULL)
    {
        intervention.log = "(no log message was specified)";
    }

    if (intervention.status == 301 || intervention.status == 302
        ||intervention.status == 303 || intervention.status == 307)
    {
        if (intervention.url != NULL)
        {
        } else {
			intervention.url = "same";
		}
    }
	VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Intervention : st %d disrupt %d url [%s] log [%s] ", intervention.status, intervention.disruptive, intervention.url, intervention.log);

    if (intervention.status != 0)
    {
        return intervention.status;
    }

    return 0;
}