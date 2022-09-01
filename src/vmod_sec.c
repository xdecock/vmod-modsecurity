#include "config.h"

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules.h"

#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#include <cache/cache_varnishd.h>
#include <cache/cache_filter.h>
#include <vcl.h>

#include "vsa.h"
#include "vre.h"
#include "vsb.h"
#include "vcc_sec_if.h"

/*
 * This structure is the one backing the MODSecurity Object
 */
struct VPFX(sec_sec)
{
    unsigned magic; // same magic as vmod obj | below
#define VMOD_SEC_SEC_MAGIC_BITS 0x07a91234
    ModSecurity *modsec;
    Rules *rules_set;
};

/* Not yet implemented */
#define VMODSEC_TRANS_STATE_INIT = 1;
#define VMODSEC_TRANS_STATE_REQHEAD = 2;
#define VMODSEC_TRANS_STATE_REQBODY = 3;
#define VMODSEC_TRANS_STATE_RESPSTATUS = 4;
#define VMODSEC_TRANS_STATE_RESPHEAD = 5;
#define VMODSEC_TRANS_STATE_RESPBODY = 6;

/* Transaction / Intervention Object basically, attached to the top request */
struct vmod_sec_struct_trans_int {
    Transaction *trans;
    ModSecurityIntervention intervention;
};

static enum vfp_status v_matchproto_(vfp_init_f)
    vfp_modsec_init(VRT_CTX, struct vfp_ctx *vfp_context, struct vfp_entry *ent);
static void v_matchproto_(vfp_fini_f)
    vfp_modsec_fini(struct vfp_ctx *vfp_context, struct vfp_entry *ent);
static enum vfp_status v_matchproto_(vfp_pull_f)
    vfp_modsec_pull(struct vfp_ctx *ctx, struct vfp_entry *ent, void *ptr,
                    ssize_t *lenp);
static int process_intervention(struct vmod_sec_struct_trans_int *transInt);

/*
 * Modsecurity logging callback
 */
void vmod_sec_log_callback(void *ref, const void *message)
{
    VSL(SLT_Error, 0, "[vmodsec] - Logger -- ");
    VSL(SLT_Error, 0, "%s", (const char *)message);
}

/*
 * Frees the 
vmod_sec_sec structure 
 */
void v_matchproto_(vmod_priv_fini_f)
    vmod_modsec_vfp_priv_fini(VRT_CTX, void *vmod_priv)
{
    free((void *)((struct vfp *)vmod_priv)->name);
    free(vmod_priv);
}

/*
 * Called when the vmod is loaded
 */
int vmod_event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e event)
{
    return (0);
    ASSERT_CLI();
    CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
    AN(priv);
    struct vfp *vfp_modsec;
    static const struct vmod_priv_methods vmod_modsec_vfp_methods[1] = {{
            .magic = VMOD_PRIV_METHODS_MAGIC,
            .type = "vmod_modsec_vfp_priv_fini",
            .fini = vmod_modsec_vfp_priv_fini
        }};

    switch (event)
    {
    case VCL_EVENT_LOAD:
    case VCL_EVENT_WARM:
        /* Registers a varnish fetch processor */
        /* @todo implement the logic */
        // Freed throug vmod_modsec_vfp_priv_fini
        vfp_modsec = malloc(sizeof(struct vfp));
        vfp_modsec->name = malloc(sizeof("modsec"));
        vfp_modsec->name = "modsec";
        vfp_modsec->init = vfp_modsec_init;
        vfp_modsec->pull = vfp_modsec_pull;
        vfp_modsec->fini = vfp_modsec_fini;
        vfp_modsec->priv1 = priv;
        priv->priv = vfp_modsec;
        priv->methods = vmod_modsec_vfp_methods;
        VRT_AddVFP(ctx, vfp_modsec);
        return (0);

    case VCL_EVENT_COLD:
    case VCL_EVENT_DISCARD:
        /* Remove a varnish fetch processor */
        VRT_RemoveVFP(ctx, priv->priv);
        return (0);
    }
    NEEDLESS(return (0));
}

/*
 * Initialising structure for modsec object
 * @todo limit object creation to init?
 */
VCL_VOID v_matchproto_(td_sec_sec__init)
    vmod_sec__init(VRT_CTX, struct VPFX(sec_sec) **vpp,
                   const char *vcl_name)
{
    struct VPFX(sec_sec) *vp;
    ModSecurity *modsec;
    Rules *rules_set;
    int error;
    (void)vcl_name;

    /* Sanity check */
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
    *vpp = vp;
    vp->modsec = modsec;
    vp->rules_set = rules_set;
}

/*
 * Cleaning up after me
 */
VCL_VOID v_matchproto_(td_sec_sec__fini)
    vmod_sec__fini(struct VPFX(sec_sec) **vpp)
{
    /* Init variables */
    struct VPFX(sec_sec) *vp;
    AN(*vpp);
    vp = *vpp;
    *vpp = NULL;
    /* sanity checks */
    CHECK_OBJ_NOTNULL(vp, VMOD_SEC_SEC_MAGIC_BITS);
    /* Free modsecurity resources */
    msc_rules_cleanup(vp->rules_set);
    msc_cleanup(vp->modsec);
    FREE_OBJ(vp);
}

// TODO See if we can do a macro betweek add_rule & add_rules
/*
 * This allows you to add a single rule to a modsec ruleset
 * @todo limit rules to init?
 */
VCL_INT v_matchproto_(td_sec_sec_add_rule)
    vmod_sec_add_rule(VRT_CTX, struct VPFX(sec_sec) *vp,
                      VCL_STRING rule)
{
    Rules *rules_set;
    int ret;
    const char *error = NULL;
    VSL(SLT_Debug, 0, "[vmodsec] - [%s] - VCL provided rule", rule);
    CHECK_OBJ_NOTNULL(vp, VMOD_SEC_SEC_MAGIC_BITS);
    rules_set = msc_create_rules_set();
    ret = msc_rules_add(rules_set, rule, &error);
    if (ret < 0)
    {
        msc_rules_cleanup(rules_set); // Avoid memleak
        VSL(SLT_Error, 0, "[vmodsec] - Problems loading the VCL provided rule --\n");
        VSL(SLT_Error, 0, "%s\n", error);
        return -1;
    }
    VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Loaded the VCL provided rule", rule);
    VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Merging rules in main rule set", rule);
    ret = msc_rules_merge(vp->rules_set, rules_set, &error);
    msc_rules_cleanup(rules_set); // Avoid memleak
    if (ret < 0)
    {
        VSL(SLT_Error, 0, "[vmodsec] - Problems merging the VCL provided rule --\n");
        VSL(SLT_Error, 0, "%s\n", error);
        return -1;
    }
    VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Merged VCL provided rule", rule);
    return 0;
}

/*
 * This allows you to add a single rule file to a modsec ruleset either from disk or http(s)
 * @todo limit rules to init?
 */
VCL_INT v_matchproto_(td_sec_sec_add_rules)
    vmod_sec_add_rules(VRT_CTX, struct VPFX(sec_sec) *vp, struct VARGS(sec_add_rules) *args)
{
    Rules *rules_set;
    int ret;
    const char *error = NULL;

    VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Try to load the rules", args->rules_path);
    CHECK_OBJ_NOTNULL(vp, VMOD_SEC_SEC_MAGIC_BITS);
    rules_set = msc_create_rules_set();
    if (args->valid_key)
    {
        ret = msc_rules_add_remote(rules_set, args->key, args->rules_path, &error);
    }
    else
    {
        ret = msc_rules_add_file(rules_set, args->rules_path, &error);
    }
    if (ret < 0)
    {
        msc_rules_cleanup(rules_set); // Avoid memleak
        VSL(SLT_Error, 0, "[vmodsec] - Problems loading the rules --\n");
        VSL(SLT_Error, 0, "%s\n", error);
        return -1;
    }
    VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Loaded the rules", args->rules_path);
    VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Merging rules in main rule set", args->rules_path);
    ret = msc_rules_merge(vp->rules_set, rules_set, &error);
    msc_rules_cleanup(rules_set); // Avoid memleak
    if (ret < 0)
    {
        VSL(SLT_Error, 0, "[vmodsec] - Problems merging the rules --\n");
        VSL(SLT_Error, 0, "%s\n", error);
        return -1;
    }
    VSL(SLT_Debug, 0, "[vmodsec] - [%s] - Merged rules", args->rules_path);
    return 0;
}

/*
 * Debug code to dump rules to stdout (crappy, remove?)
 */
VCL_INT v_matchproto_(td_sec_sec_dump_rules)
    vmod_sec_dump_rules(VRT_CTX, struct VPFX(sec_sec) *vp)
{
    CHECK_OBJ_NOTNULL(vp, VMOD_SEC_SEC_MAGIC_BITS);
    msc_rules_dump(vp->rules_set);
}

/*
 * free the transaction
 */
void v_matchproto_(vmod_priv_fini_f)
    vmod_sec_cleanup_transaction(VRT_CTX, void *ptr)
{
    struct vmod_sec_struct_trans_int *transInt;
    transInt = (struct vmod_sec_struct_trans_int *)ptr;
    // Log before cleanup
    msc_process_logging((transInt->trans));
    // Free vmod_priv
    msc_transaction_cleanup((transInt->trans));
    free(transInt);
}

/*
 * Create a transaction, assign a connection, and eat the headers
 * @todo limit to vcl_recv?
 */
VCL_INT v_matchproto_(td_sec_sec_new_conn)
    vmod_sec_new_conn(VRT_CTX, struct VPFX(sec_sec) *vp,
                      struct VARGS(sec_new_conn) *args)
{
    CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
    struct vmod_sec_struct_trans_int *transInt;
    if (args->arg1->priv == NULL)
    {
        static const struct vmod_priv_methods vmod_sec_free_tx_methods[1] = {{
            .magic = VMOD_PRIV_METHODS_MAGIC,
            .type = "vmod_sec_cleanup_transaction",
            .fini = vmod_sec_cleanup_transaction
        }};
        /* Freed by varnish on "end of use by calling vmod_sec_cleanup_transaction" */
        transInt = malloc(sizeof(struct vmod_sec_struct_trans_int));

        /* Init intervention */
        transInt->intervention.status = 200;
        transInt->intervention.pause = 0;
        transInt->intervention.url = NULL;
        transInt->intervention.log = NULL;
        transInt->intervention.disruptive = 0;

        if (args->valid_transaction_id)
        {
            // Freed before end of if
            char *transaction_id = malloc(strlen(args->transaction_id));
            strcpy(transaction_id, args->transaction_id);
            transInt->trans = msc_new_transaction_with_id(
                vp->modsec, vp->rules_set, transaction_id, args->arg1);
            free(transaction_id);
        }
        else
        {
            transInt->trans = msc_new_transaction(
                vp->modsec, vp->rules_set, args->arg1);
        }
        args->arg1->priv = transInt;
        args->arg1->methods = vmod_sec_free_tx_methods;
    }
    msc_process_connection(transInt->trans,
                           args->client_ip, args->client_port,
                           args->server_ip, args->server_port);
    VSL(SLT_Debug, ctx->sp->vxid,
        "[vmodsec] - Started processing Transaction for [%s:%ld] with server [%s:%ld]",
        args->client_ip, args->client_port, args->server_ip, args->server_port);

    process_intervention(transInt);
    return 0;
}

/*
 * Handle the Method, url, http_version
 * @todo limit to vcl_recv?
 */
VCL_INT v_matchproto_(td_sec_sec_process_url)
    vmod_sec_process_url(VRT_CTX,
                         struct VPFX(sec_sec) *vp, struct vmod_priv *priv,
                         VCL_STRING req_url, VCL_STRING protocol, VCL_STRING http_version)
{
    CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
    if (priv->priv == NULL)
    {
        VSL(SLT_Error, ctx->sp->vxid, "[vmodsec] - connection has not been started, closing");
        return -1;
    }
    struct vmod_sec_struct_trans_int *transInt = (struct vmod_sec_struct_trans_int *)priv->priv;
    /* This will be used to Initialise the original URL */
    msc_process_uri(transInt->trans, req_url, protocol, http_version);
    VSL(SLT_Debug, ctx->sp->vxid,
        "[vmodsec] - Processing URI : [%s] on protocol [%s] with version [%s]",
        req_url, protocol, http_version);
    process_intervention(transInt);

    /* Handling headers */
    unsigned u;
    const struct http *hp = ctx->req->http;
#ifdef VMOD_SEC_DEBUG
    VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Found %d headers, Start at %d, need to ingest %d headers", hp->nhd, HTTP_HDR_FIRST, hp->nhd - HTTP_HDR_FIRST);
#endif
    // Freed after loop
    char *headerName = malloc(8192);
    char *headerValue = malloc(8192);

    for (u = HTTP_HDR_FIRST; u < hp->nhd; u++)
    {
        Tcheck(hp->hd[u]);
        const char *header = hp->hd[u].b;
        long int hlen = strlen(header);
        int pos = (strchr(header, ':') - header);
        // XXX: use a workspace (in priv?)
        if (pos < 0 || pos > 8191 || hlen - pos > 8191)
        {
            continue;
        }
        /* Copy headers */
        strncpy(headerName, header, pos);
        headerName[pos] = '\0';
        // Find spaces
        pos += 1 /* : */ + strspn(&header[pos + 1], " \r\n\t"); // LWS = [CRLF] 1*( SP | HT ) chr(9,10,13,32)
        strncpy(headerValue, &header[pos], hlen - pos);
        headerValue[hlen - pos] = '\0';
        msc_add_request_header(transInt->trans, headerName, headerValue);
#ifdef VMOD_SEC_DEBUG
        VSL(SLT_Debug, ctx->sp->vxid,
            "[vmodsec] - Additional header provided %s: %s", headerName, headerValue);
#endif
    }
    free(headerName);
    free(headerValue);
#ifdef VMOD_SEC_DEBUG
    VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Processing Request Headers");
#endif
    msc_process_request_headers(transInt->trans);
    process_intervention(transInt);
    return (0);
}

/* Iterate over the object (to read body) */
static int v_matchproto_(objiterate_f)
    vmod_sec_read_request_body(void *priv, unsigned int flush, const void *ptr, ssize_t len)
{

    AN(priv);
    (void)flush;
    int ret;
    struct vmod_sec_struct_trans_int *transInt = (struct vmod_sec_struct_trans_int *)((struct vmod_priv *)priv)->priv;
    ret = (msc_append_request_body(transInt->trans, ptr, len)) == 1 ? 0 : -1;
#ifdef VMOD_SEC_DEBUG
    VSL(SLT_Debug, 0, "[vmodsec] - Reading request body [%ld] read, [%d] ret", len, ret);
#endif
    return ret;
}

/* 
 * Process the request body
 * If capture_body is set to false, it only trigger the "process_body"
 */
VCL_INT v_matchproto_(td_sec_sec_do_process_request_body)
    vmod_sec_do_process_request_body(VRT_CTX,
                                     struct VPFX(sec_sec) *vp, struct vmod_priv *priv, VCL_BOOL capture_body)
{
    CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
    CHECK_OBJ_NOTNULL(ctx->req, REQ_MAGIC);
    AN(ctx->vsl);
    if (priv->priv == NULL)
    {
        VSL(SLT_Debug, ctx->sp->vxid,
            "[vmodsec] - connection has not been started, closing");
        return -1;
    }
    struct vmod_sec_struct_trans_int *transInt = (struct vmod_sec_struct_trans_int *)priv->priv;
    VSL(SLT_Debug, 0, "[vmodsec] - Reading request body ? %d", capture_body);
    if (capture_body == 1)
    {
        const struct http *hp = ctx->req->http;
        if (ctx->req->req_body_status != BS_CACHED)
        {
            VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Unbuffered req.body");
            return -1;
        }

        int ret;

        ret = VRB_Iterate(ctx->req->wrk, ctx->req->vsl, ctx->req, vmod_sec_read_request_body, priv);

        VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Body Iteration Done");

        if (ret < 0)
        {
            VSL(SLT_Error, ctx->sp->vxid,
                "[vmodsec] - Iteration on req.body didn't succeed. %d", ret);

            return -1;
        }

        VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Processing Request Body");
    }

    msc_process_request_body(transInt->trans);
    process_intervention(transInt);
    return 0;
}

/*
 * Process the response header
 */
VCL_INT v_matchproto_(td_sec_sec_process_response)
    vmod_sec_process_response(VRT_CTX,
                              struct VPFX(sec_sec) *vp, struct vmod_priv *priv, VCL_STRING protocol)
{
    CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
    if (priv->priv == NULL)
    {
        VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - connection has not been started, closing");
        return -1;
    }
    struct vmod_sec_struct_trans_int *transInt = (struct vmod_sec_struct_trans_int *)priv->priv;

    /* Handling headers */
    unsigned u;
    const struct http *hp = ctx->req->resp;
#ifdef VMOD_SEC_DEBUG
    VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Processing Response Headers");
    VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Found %d headers, Start at %d, need to ingest %d headers",
        hp->nhd, HTTP_HDR_FIRST, hp->nhd - HTTP_HDR_FIRST);
#endif
    // freed after loop
    char *headerName = malloc(8192);
    char *headerValue = malloc(8192);

    for (u = HTTP_HDR_FIRST; u < hp->nhd; u++)
    {
        Tcheck(hp->hd[u]);
        const char *header = hp->hd[u].b;
        long int hlen = strlen(header);
        int pos = (strchr(header, ':') - header);
        // XXX: use a workspace (in priv?)
        if (pos < 0 || pos > 8191 || hlen - pos > 8191)
        {
            continue;
        }
        /* Copy headers */
        strncpy(headerName, header, pos);
        headerName[pos] = '\0';
        // Find spaces
        pos += 1 /* : */ + strspn(&header[pos + 1], " \r\n\t"); // LWS = [CRLF] 1*( SP | HT ) chr(9,10,13,32)
        strncpy(headerValue, &header[pos], hlen - pos);
        headerValue[hlen - pos] = '\0';
        msc_add_response_header(transInt->trans, headerName, headerValue);
#ifdef VMOD_SEC_DEBUG
        VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Additional response header provided %s: %s",
            headerName, headerValue);
#endif
    }
    free(headerName);
    free(headerValue);
    msc_process_response_headers(transInt->trans, ctx->req->resp->status, protocol);
    process_intervention(transInt);
    return 0;
}

/*
 * Iterate over object to treat the response body
 */
static int v_matchproto_(objiterate_f)
    vmod_sec_read_response_body(void *priv, unsigned int flush, const void *ptr, ssize_t len)
{

    AN(priv);
    (void)flush;
    int ret;
    struct vmod_sec_struct_trans_int *transInt = (struct vmod_sec_struct_trans_int *)((struct vmod_priv *)priv)->priv;
    ret = (msc_append_response_body(transInt->trans, ptr, len)) == 1 ? 0 : -1;
    VSL(SLT_Debug, 0, "[vmodsec] - Reading response body [%ld] read, [%d] ret", len, ret);
    return ret;
}

/*
 * This method does treat the body (if needed) or just trigger the process_response_body
 */
VCL_INT v_matchproto_(td_sec_sec_do_process_response_body)
    vmod_sec_do_process_response_body(VRT_CTX,
                                      struct VPFX(sec_sec) *vp, struct vmod_priv *priv, VCL_BOOL capture_body)
{
    CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
    CHECK_OBJ_NOTNULL(ctx->req, REQ_MAGIC);
    AN(ctx->vsl);

    if (priv->priv == NULL)
    {
        VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - connection has not been started, closing");
        return -1;
    }
    struct vmod_sec_struct_trans_int *transInt = (struct vmod_sec_struct_trans_int *)priv->priv;
    if (capture_body == 1)
    {
        int ret;
        // int ObjIterate(struct worker *, struct objcore *, void *priv, objiterate_f *func, int final);
        // Final must be kept to 0 otherwise, we do lose the process
        ret = ObjIterate(ctx->req->wrk, ctx->req->objcore, priv, vmod_sec_read_response_body, 0);

        VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Body Iteration Done");

        if (ret < 0)
        {
            VSL(SLT_Error, ctx->sp->vxid,
                "[vmodsec] - Iteration on resp.body didn't succeed. %d", ret);

            return -1;
        }

        VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - Processing Response Body");
    }
    msc_process_response_body(transInt->trans);
    process_intervention(transInt);
    return 0;
}

/* Initialize the Varnish Fetch Processor */
static enum vfp_status v_matchproto_(vfp_init_f)
    vfp_modsec_init(VRT_CTX, struct vfp_ctx *vfp_context, struct vfp_entry *ent)
{
    return (VFP_OK);
}

/* Closes the Varnish Fetch Processor */
static void v_matchproto_(vfp_fini_f)
    vfp_modsec_fini(struct vfp_ctx *vfp_context, struct vfp_entry *ent)
{
}

/* Varnish Fetch Processor Main loop */
static enum vfp_status v_matchproto_(vfp_pull_f)
    vfp_modsec_pull(struct vfp_ctx *vfp_context, struct vfp_entry *ent, void *ptr,
                    ssize_t *lenp)
{
    return (VFP_OK);
}

/* Handle the Intervention Code */
static int process_intervention(struct vmod_sec_struct_trans_int *transInt)
{
    int z = msc_intervention(transInt->trans, &transInt->intervention);
    return z;
}

/* Method to close the session, will simply kill the connection */
VCL_INT v_matchproto_(td_sec_sec_conn_close)
    vmod_sec_conn_close(VRT_CTX,
                        struct VPFX(sec_sec) *vp, struct vmod_priv *priv)
{
    CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
    CHECK_OBJ_NOTNULL(ctx->req, REQ_MAGIC);
    ctx->req->restarts = cache_param->max_restarts;
    Req_Fail(ctx->req, SC_RX_JUNK);
    return 0;
}

/* This will check if we need to disrupt the actual flow of execution (modsecurity wants to act) */
VCL_BOOL v_matchproto_(td_sec_sec_intervention_getDisrupt)
    vmod_sec_intervention_getDisrupt(VRT_CTX,
                                     struct VPFX(sec_sec) *vp, struct vmod_priv *priv)
{
    CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
    CHECK_OBJ_NOTNULL(ctx->req, REQ_MAGIC);
    AN(ctx->vsl);

    if (priv->priv == NULL)
    {
        VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - connection has not been started, closing");
        return -1;
    }
    struct vmod_sec_struct_trans_int *transInt = (struct vmod_sec_struct_trans_int *)priv->priv;
    return transInt->intervention.disruptive;
}

/* This will return the http status code modsecurity wants to run */
VCL_INT v_matchproto_(td_sec_sec_intervention_getStatus)
    vmod_sec_intervention_getStatus(VRT_CTX,
                                    struct VPFX(sec_sec) *vp, struct vmod_priv *priv)
{
    CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
    CHECK_OBJ_NOTNULL(ctx->req, REQ_MAGIC);
    AN(ctx->vsl);

    if (priv->priv == NULL)
    {
        VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - connection has not been started, closing");
        return -1;
    }
    struct vmod_sec_struct_trans_int *transInt = (struct vmod_sec_struct_trans_int *)priv->priv;
    return transInt->intervention.status;
}

/* This will return the url modsecurity wants to redirect to */
VCL_STRING v_matchproto_(td_sec_sec_intervention_getUrl)
    vmod_sec_intervention_getUrl(VRT_CTX,
                                 struct VPFX(sec_sec) *vp, struct vmod_priv *priv)
{
    CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
    CHECK_OBJ_NOTNULL(ctx->req, REQ_MAGIC);
    AN(ctx->vsl);

    if (priv->priv == NULL)
    {
        VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - connection has not been started, closing");
        return "";
    }
    struct vmod_sec_struct_trans_int *transInt = (struct vmod_sec_struct_trans_int *)priv->priv;
    return transInt->intervention.url;
}

/* This will return the time modsecurity wants to delay the response */
VCL_DURATION v_matchproto_(td_sec_sec_intervention_getPause)
    vmod_sec_intervention_getPause(VRT_CTX,
                                   struct VPFX(sec_sec) *vp, struct vmod_priv *priv)
{
    CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
    CHECK_OBJ_NOTNULL(ctx->req, REQ_MAGIC);
    AN(ctx->vsl);

    if (priv->priv == NULL)
    {
        VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - connection has not been started, closing");
        return 0.0;
    }
    double duration = 0.0;
    struct vmod_sec_struct_trans_int *transInt = (struct vmod_sec_struct_trans_int *)priv->priv;
    duration = transInt->intervention.pause / 1000;
    return duration;
}

/* This will return the string modsecurity wants to log */
VCL_STRING v_matchproto_(td_sec_sec_intervention_getLog)
    vmod_sec_intervention_getLog(VRT_CTX,
                                 struct VPFX(sec_sec) *vp, struct vmod_priv *priv)
{
    CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
    CHECK_OBJ_NOTNULL(ctx->req, REQ_MAGIC);
    AN(ctx->vsl);

    if (priv->priv == NULL)
    {
        VSL(SLT_Debug, ctx->sp->vxid, "[vmodsec] - connection has not been started, closing");
        return "";
    }
    struct vmod_sec_struct_trans_int *transInt = (struct vmod_sec_struct_trans_int *)priv->priv;
    return transInt->intervention.log;
}

VCL_STRING v_matchproto_(td_sec_sec_version)
    vmod_sec_version(VRT_CTX, struct VPFX(sec_sec) *vp){
        return MODSECURITY_VERSION;
    }
