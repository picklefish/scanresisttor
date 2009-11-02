#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <mod_ssl.h>
#include <mod_proxy.h>
#include <apr_poll.h>

//#include "ssl_private.h"
#include "apr_buckets_simple.c"
//#include "http_request.c"

/*
 * The default value for config directives
 */
#ifndef DEFAULT_MODTOR_PASSWORD
#define DEFAULT_MODTOR_PASSWORD "password=pancake"//"tor://password=pancake"
#endif

#ifndef DEFAULT_MODTOR_PORT
#define DEFAULT_MODTOR_PORT 44114//12312//443
#endif



static const char tor_io_filter[] = "Tor Filter";


/*
 * This module
 */
module AP_MODULE_DECLARE_DATA tor_module;

/*
 * This modules per-server configuration structure.
 */
typedef struct {
	char *mod_tor_password;
	apr_port_t mod_tor_port;
} modtor_config;


//Stuff for per connection -- used to decided if someone is authenticated
#define myTorConnConfig(c) \
(TorConnRec *)ap_get_module_config(c->conn_config, &tor_module)
#define myTorConnConfigSet(c, val) \
ap_set_module_config(c->conn_config, &tor_module, val)


/*
 * apache2_to_tor_sock -
 * The socket which connects tor and apache on the local machine
 * It is a client socket for apache. Setup in init and closed on pool cleanup.
 */
typedef struct {
    int isAuthenticated;
    server_rec *server;
    apr_socket_t *apache2_to_tor_sock;
} TorConnRec;





static modtor_config *s_cfg = NULL;



















/*static request_rec *tor_create_outbound_req(request_rec *r) {

	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "proxy: Tor: tor_create_outbound_req INSIDE");
    int access_status;
    request_rec *new;

    if (ap_is_recursion_limit_exceeded(r)) {
        ap_die(HTTP_INTERNAL_SERVER_ERROR, r);
        return NULL;
    }

	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "proxy: Tor: pcalloc");
    new = (request_rec *) apr_pcalloc(r->pool, sizeof(request_rec));

    new->connection = r->connection;
    new->server     = r->server;
    new->pool       = r->pool;*/

    /*
     * A whole lot of this really ought to be shared with http_protocol.c...
     * another missing cleanup.  It's particularly inappropriate to be
     * setting header_only, etc., here.
     */

    /*new->method          = r->method;
    new->method_number   = r->method_number;
    new->allowed_methods = ap_make_method_list(new->pool, 2);
    //ap_parse_uri(new, new_uri);

    new->request_config = ap_create_request_config(r->pool);

    new->per_dir_config = r->server->lookup_defaults;

    //i THINK we want to remove these, as this should be a normal request
    //-shane
    new->prev = r;
    r->next   = new;

	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "proxy: Tor: create request");*/
    /* Must have prev and next pointers set before calling create_request
     * hook.
     */
    /*ap_run_create_request(new);

	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "proxy: Tor: done create request");*/
    /* Inherit the rest of the protocol info... */

   /* new->the_request = r->the_request;

    new->allowed         = r->allowed;

    new->status          = r->status;
    new->assbackwards    = r->assbackwards;
    new->header_only     = r->header_only;
    new->protocol        = r->protocol;
    new->proto_num       = r->proto_num;
    new->hostname        = r->hostname;
    new->request_time    = r->request_time;
    new->main            = r->main;

    new->headers_in      = r->headers_in;
    new->headers_out     = apr_table_make(r->pool, 12);
    new->err_headers_out = r->err_headers_out;
    new->subprocess_env  = rename_original_env(r->pool, r->subprocess_env);
    new->notes           = apr_table_make(r->pool, 5);
    new->allowed_methods = ap_make_method_list(new->pool, 2);

    new->htaccess        = r->htaccess;
    new->no_cache        = r->no_cache;
    new->expecting_100   = r->expecting_100;
    new->no_local_copy   = r->no_local_copy;
    new->read_length     = r->read_length;    */ /* We can only read it once */
    /*new->vlist_validator = r->vlist_validator;

    new->proto_output_filters  = r->proto_output_filters;
    new->proto_input_filters   = r->proto_input_filters;*/

    /*
     * I THINK this should add the SSL output filters we need... -shane
     */
    /*new->output_filters  = NULL;
    new->input_filters   = r->output_filters;

    //if (new->main) {
        /* Add back the subrequest filter, which we lost when
         * we set output_filters to include only the protocol
         * output filters from the original request.
         */
        //ap_add_output_filter_handle(ap_subreq_core_filter_handle,
        //                            NULL, new, new->connection);
    //}

    //update_r_in_filters(new->input_filters, r, new);
    //update_r_in_filters(new->output_filters, r, new);

    //apr_table_setn(new->subprocess_env, "REDIRECT_STATUS",
                   //apr_itoa(r->pool, r->status));*/


    /*
     * XXX: hmm.  This is because mod_setenvif and mod_unique_id really need
     * to do their thing on internal redirects as well.  Perhaps this is a
     * misnamed function.
     */
    //we don't need to do this I THINK... -shane
    //if ((access_status = ap_run_post_read_request(new))) {
    //    ap_die(access_status, new);
    //    return NULL;
    //}

	/*ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "proxy: Tor: all done with creating outbound rec");

    return new;
}*/

/*
 * Copied from http_request...
 */
/*static apr_table_t *rename_original_env(apr_pool_t *p, apr_table_t *t)
{
    const apr_array_header_t *env_arr = apr_table_elts(t);
    const apr_table_entry_t *elts = (const apr_table_entry_t *) env_arr->elts;
    apr_table_t *new = apr_table_make(p, env_arr->nalloc);
    int i;

    for (i = 0; i < env_arr->nelts; ++i) {
        if (!elts[i].key)
            continue;
        apr_table_setn(new, apr_pstrcat(p, "REDIRECT_", elts[i].key, NULL),
                  elts[i].val);
    }

    return new;
}*/





/*
 * Create a request and send it to the client so that SSL will be taken care of in the outbound filters
 */
/*static apr_status_t tor_send_response(const void * buf, int offset, int nbytes, request_rec *r){
	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "proxy: Tor: tor_send_response");
	//Create a new request with the data so that apache will
	//take care of the SSL decryption
	request_rec *new = tor_create_outbound_req(r);
	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "proxy: Tor: tor_create_outbound_req");
	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "proxy: Tor: process rec");
	ap_set_content_type(new, r->content_type);//Who knows what should really go here...-shane
	//ap_set_content_type(new, "text/html");

	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "proxy: Tor: writing");
	ap_rwrite(buf + offset, nbytes, new);

	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "proxy: Tor: ap_process request");
	apr_status_t access_status = ap_process_request_internal(new);
	if (access_status == OK) {
		if ((access_status = ap_invoke_handler(new)) != 0) {
			ap_die(access_status, new);
			return -1;
		}
		ap_finalize_request_protocol(new);
	}
	else {
		ap_die(access_status, new);
	}
	//rv = apr_socket_send(client_socket, buffer + o, &nbytes);

	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "proxy: Tor: returning ok");
	return OK;
}
*/












/*
 * Cleanup/close apache to Tor socket on shutdown
 */

static apr_status_t close_tor_socket(void *sock_to_close)
{
	apr_socket_t * sock = (apr_socket_t*) sock_to_close;
	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
	"mod_tor: Closing Tor Socket");
	fflush(stderr);

	if(sock){
		apr_socket_close(sock);
	}

	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
	"mod_tor: Closed Tor Socket");
    return APR_SUCCESS;
}



/*
 * Initialize data and create the tor socket
 */

static int
tor_init(apr_pool_t * config_pool, apr_pool_t * plog, apr_pool_t * ptemp,
           server_rec * main_server){

        apr_pool_t *p = config_pool;


        // Get the modules configuration
        s_cfg = ap_get_module_config(main_server->module_config, &tor_module);
        //Do I need to clean this up?

        return OK;

}







static TorConnRec *tor_init_connection_ctx(conn_rec *c)
{
    TorConnRec *torconn = myTorConnConfig(c);

    if (torconn) {
        return torconn;
    }

    torconn = apr_pcalloc(c->pool, sizeof(*torconn));

    torconn->isAuthenticated = 0;

    torconn->server = c->base_server;

    torconn->apache2_to_tor_sock = NULL;

    myTorConnConfigSet(c, torconn);

    return torconn;
}



static int tor_init_connection_tor_socket(conn_rec *c, TorConnRec *torconn){
           /*
                * Set up the socket between apache and Tor
                */

                apr_status_t rv, err;
                apr_sockaddr_t *localsa;
                if ((rv = apr_sockaddr_info_get(&localsa, "localhost", APR_UNSPEC,
                                                                s_cfg->mod_tor_port, 0, c->pool)) != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, c->base_server,
                                        "mod_tor: Init: Failed to get local socket address");
                        return -1;//replace with actual err# later
                }

                if ((rv = apr_socket_create(&(torconn->apache2_to_tor_sock), localsa->family,
                                                                  SOCK_STREAM, 0, c->pool)) != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, c->base_server,
                                        "mod_tor: Init: Failed to create socket to tor.");
                        return -1;//replace with actual err# later
                }

                /*//Set up socket options if we need to...

                if ((rv = apr_socket_timeout_set(apache2_to_tor_sock, 30)) != APR_SUCCESS) {
                  apr_socket_close(sock);
                  return OK;
                }
                rv = apr_socket_opt_set(apache2_to_tor_sock, APR_SO_RCVBUF, 256);
                rv = apr_socket_opt_set(apache2_to_tor_sock, APR_TCP_NODELAY, 1);
                rv = apr_socket_opt_set(apache2_to_tor_sock, APR_SO_NONBLOCK, 1);
                */

                rv = apr_socket_opt_set(torconn->apache2_to_tor_sock, APR_SO_KEEPALIVE, 1);
                if ( rv != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, c->base_server,
                                        "mod_tor: Init: Failed to set keep alive", (int)s_cfg->mod_tor_port);
                  apr_socket_close(torconn->apache2_to_tor_sock);
                  return -1;//replace with actual err# later
                }

                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, c->base_server,
                                "mod_tor: Before Connect %d", (int)s_cfg->mod_tor_port);
                rv = apr_socket_connect(torconn->apache2_to_tor_sock, localsa);
                ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, c->base_server,
                                "mod_tor: After Connect %d", (int)s_cfg->mod_tor_port);

                if ( rv != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, c->base_server,
                                        "mod_tor: Init: Failed to connect to tor socket at port %d", (int)s_cfg->mod_tor_port);
                  apr_socket_close(torconn->apache2_to_tor_sock);
                  return -1;//replace with actual err# later
                }

                /*
                 * Register a cleanup to close the socket.
                 * XXX:Make sure I'm cleaning up correctly with apache2_to_tor_sock
                 */
                apr_pool_cleanup_register(c->pool, torconn->apache2_to_tor_sock,
                                                                        close_tor_socket, apr_pool_cleanup_null);
                return APR_SUCCESS;
}




static int tor_hook_pre_connection(conn_rec *c, void *csd)
{
    TorConnRec *torconn = myTorConnConfig(c);

    /*
     * Create Tor context
     */
    if (!torconn) {
        torconn = tor_init_connection_ctx(c);
    }

    return APR_SUCCESS;//tor_init_tor_connection(c);
}



















/*
 * right after SSL filter
 */
int tor_io_filter_input(ap_filter_t *f,
						apr_bucket_brigade *bb,
						ap_input_mode_t mode,
						apr_read_type_e block,
						apr_off_t readbytes)
{

	apr_size_t i, o, nbytes;
	char buffer[HUGE_STRING_LEN];
	char *buf;
	apr_status_t err, rv;
    TorConnRec *torconn = myTorConnConfig(f->c);

	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "proxy: Tor: HAIIIIIIIIIII");

    if (torconn && !(torconn->isAuthenticated)) {
            return DECLINED;
    }

	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "proxy: Tor: Authenticated and removing from filters to send to Tor");

    //This is where we would pass the data to Tor
    //Get the decrypted data from the last bucket ssl just created this...
    simple_bucket_read(APR_BRIGADE_LAST(bb), &buf, &nbytes, block );

    if(nbytes >= HUGE_STRING_LEN){
    	//freak out?
    }

    //Send the data to tor
	if (rv == APR_SUCCESS) {
		o = 0;
		i = nbytes;
		while(i > 0)
		{
			nbytes = i;
	/* This is a comment from mod_proxy_connect
	* This is just plain wrong.  No module should ever write directly
	* to the client.  For now, this works, but this is high on my list of
	* things to fix.  The correct line is:
	* if ((nbytes = ap_rwrite(buffer + o, nbytes, r)) < 0)
	* rbb
	*/
			rv = apr_socket_send(torconn->apache2_to_tor_sock, buffer + o, &nbytes);

			if (rv != APR_SUCCESS)
				break;
			o += nbytes;
			i -= nbytes;
		}
	}
	//End the input filter chain just in case
	//XXX: Makesure this is the right way to do this...
	f->next = NULL;
	//f->frec->next = NULL;
	f->r->input_filters = NULL;
	f->r->output_filters = NULL;
    return OK;
}










/*
 * This handles the HTTPS query string password,
 * and authenticates the user if they send the correct password
 */

static int tor_handler(request_rec *r, proxy_worker *worker,
					   proxy_server_conf *conf,
					   char *url, const char *proxyname,
					   apr_port_t proxyport) {

  TorConnRec *torconn = myTorConnConfig(r->connection);

  if (torconn && torconn->isAuthenticated) {
	 //If the server is already authenticated silently kill requests
	 //Clear the output filters
	 r->output_filters = NULL;
	 r->connection->output_filters = NULL;
     return OK;
  }

  if (!r->handler || strcasecmp(r->handler, "tor") != 0) {
    //r->handler wasn't "tor"
	return DECLINED;
  }

  if (r->method_number != M_GET) {
	  // Wasn't a GET request, no need to look at it
	 return DECLINED;
  }

  /*//IS THE CONNECTION HTTPS?
  if ((APR_RETRIEVE_OPTIONAL_FN(ssl_is_https))(r->connection) == 0){
	//the connection isn't HTTPS
	return DECLINED;
  }*/

  //Compare the querystring
  if (!r->args) {
	  // No query string sent
	  return DECLINED;
  }
  if( strncmp(r->args, s_cfg->mod_tor_password, strlen(s_cfg->mod_tor_password) ) != 0 ){
	  //the query string did not match the configuration password
	  return DECLINED;
  }

  /* OK, we're happy with this request, so we'll return the response. */

	if(torconn){
		torconn->isAuthenticated = 1;
		tor_init_connection_tor_socket(r->connection,torconn);
	}
	else{
		return DECLINED;
	}


	apr_pool_t *p = r->pool;
	conn_rec *c = r->connection;
	apr_socket_t *apache2_to_tor_sock;
	apr_size_t i, o, nbytes;
	char buffer[HUGE_STRING_LEN];
	apr_status_t err, rv;
	apr_socket_t *client_socket = ap_get_module_config(r->connection->conn_config, &core_module);
	apr_socket_t *tor_socket = torconn->apache2_to_tor_sock;
	apr_pollset_t *pollset;
	apr_pollfd_t pollfd;
	const apr_pollfd_t *signalled;
	apr_int32_t pollcnt, pi;
	apr_int16_t pollevent;





	//CHANGE ALL OF THE NULL'S in ap_log_error back to r->server
	//and APLOG_STARTUP to APLOG_DEBUG


	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
		 "proxy: TOR: dot dot dot");




	/*
	 *
	 *
	 * The following code is almost entirely copied from
	 * mod_proxy_connect
	 *
	 *
	 */

	/* we are acting as a tunnel - the output filter stack should
	 * be completely empty, because when we are done here we are done completely.
	 * We add the NULL filter to the stack to do this...
	 */
	//r->output_filters = NULL;
	//r->connection->output_filters = NULL;

	ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
		 "proxy: Tor: Returning 200 OK Status");
	nbytes = apr_snprintf(buffer, sizeof(buffer),
			  "HTTP/1.0 200 Connection Established" CRLF);
	ap_xlate_proto_to_ascii(buffer, nbytes);

	ap_rwrite(buffer, nbytes, r);
	ap_rflush(r);
	//tor_send_response(buffer, 0, nbytes, r);
    //apr_socket_send(client_socket, buffer, &nbytes);

	nbytes = apr_snprintf(buffer, sizeof(buffer),
			  "Proxy-agent: %s" CRLF CRLF, "Mod_Tor");
	ap_xlate_proto_to_ascii(buffer, nbytes);
	ap_rwrite(buffer, nbytes, r);
	ap_rflush(r);
	//tor_send_response(buffer, 0, nbytes, r);
    //apr_socket_send(client_socket, buffer, &nbytes);

	ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
		 "proxy: TOR: setting up poll()");

	/*
	 * Step Four: Handle Data Transfer
	 *
	 * Handle two way transfer of data over the socket (this is a tunnel).
	 */

	/*    r->sent_bodyct = 1;*/

	if ((rv = apr_pollset_create(&pollset, 2, r->pool, 0)) != APR_SUCCESS) {
		apr_socket_close(tor_socket);
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
			"proxy: TOR: error apr_pollset_create()");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* Add client side to the poll */
	pollfd.p = r->pool;
	pollfd.desc_type = APR_POLL_SOCKET;
	pollfd.reqevents = APR_POLLIN;
	//pollfd.desc.s = client_socket;
	pollfd.client_data = NULL;
	//apr_pollset_add(pollset, &pollfd);

	/* Add the server side to the poll */
	pollfd.desc.s = tor_socket;//sock;
	apr_pollset_add(pollset, &pollfd);


	ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
		 "proxy: TOR: finished setting up poll stuffs about to start while loop");


	while (1) { /* Infinite loop until error (one side closes the connection) */
		if ((rv = apr_pollset_poll(pollset, -1, &pollcnt, &signalled)) != APR_SUCCESS) {
			apr_socket_close(tor_socket);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "proxy: Tor: error apr_poll()");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
					 "proxy: Tor: woke from select(), i=%d", pollcnt);

		for (pi = 0; pi < pollcnt; pi++) {
			const apr_pollfd_t *cur = &signalled[pi];

			if (cur->desc.s == tor_socket) {
				pollevent = cur->rtnevents;
				if (pollevent & APR_POLLIN) {
					ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
								 "proxy: TOR: sock was set");
					nbytes = sizeof(buffer);
					rv = apr_socket_recv(tor_socket, buffer, &nbytes);
					if (rv == APR_SUCCESS) {
						o = 0;
						i = nbytes;
						while(i > 0)
						{
							nbytes = i;
	/* This is a comment from mod_proxy_connect
	 * This is just plain wrong.  No module should ever write directly
	 * to the client.  For now, this works, but this is high on my list of
	 * things to fix.  The correct line is:
	 * if ((nbytes = ap_rwrite(buffer + o, nbytes, r)) < 0)
	 * rbb
	 */
							ap_rwrite(buffer, nbytes, r);
							ap_rflush(r);
							//tor_send_response(buffer, o, nbytes, r);

							if (rv != APR_SUCCESS)
								break;
							o += nbytes;
							i -= nbytes;
						}
					}
					else
						break;
				}
				else if ((pollevent & APR_POLLERR) || (pollevent & APR_POLLHUP))
					break;
			}
			else
				break;
		}
		if (rv != APR_SUCCESS) {
			break;
		}
	}

	ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
		 "proxy: Tor: finished with poll() - cleaning up");

	/*
	 * Step Five: Clean Up
	 *
	 * Close the socket and clean up
	 */
	//apr_socket_close(apache2_to_tor_sock);

  /* we return OK to indicate that we have successfully processed
   * the request.  No further processing is required.
   */
  return OK;
}
















































//
// Configuration functions
//

/**
 * This function is called when the "ModTorPassword" configuration directive is parsed.
 */
static const char *set_modtor_password(cmd_parms *parms, void *mconfig, const char *arg)
{
	// get the module configuration (this is the structure created by create_modtut2_config())
	modtor_config *s_cfg = ap_get_module_config(parms->server->module_config, &tor_module);

	// make a duplicate of the argument's value using the command parameters pool.
	s_cfg->mod_tor_password = (char *) arg;

	// success
	return NULL;
}

/**
 * This function is called when the "ModTorPort" configuration directive is parsed.
 */
static const char *set_modtor_port(cmd_parms *parms, void *mconfig, const char *arg)
{
	// get the module configuration (this is the structure created by create_modtut2_config())
	modtor_config *s_cfg = ap_get_module_config(parms->server->module_config, &tor_module);

	// make a duplicate of the argument's value using the command parameters pool.
	s_cfg->mod_tor_port = (apr_port_t) arg;

	// success
	return NULL;
}


/**
 * A declaration of the configuration directives that are supported by this module.
 */
static const command_rec mod_tor_cmds[] =
{
	AP_INIT_TAKE1(
		"ModTorPassword",
		set_modtor_password,
		NULL,
		RSRC_CONF,
		"ModTorPassword <string> -- the password for accessing Tor."
	),
	AP_INIT_TAKE1(
		"ModTorPort",
		set_modtor_port,
		NULL,
		RSRC_CONF,
		"ModTorPort <int> -- the port Tor is on."
	),
	{NULL}
};

/**
 * Creates the per-server configuration records.
 */
static void *create_modtor_config(apr_pool_t *p, server_rec *s)
{
	modtor_config *newcfg;

	// allocate space for the configuration structure from the provided pool p.
	newcfg = (modtor_config *) apr_pcalloc(p, sizeof(modtor_config));

	// set the default value for the password string.
	newcfg->mod_tor_password = DEFAULT_MODTOR_PASSWORD;

	// set the default value for the password string.
	newcfg->mod_tor_port = DEFAULT_MODTOR_PORT;

	// return the new server configuration structure.
	return (void *) newcfg;
}




static void tor_hooks(apr_pool_t *pool) {
  /*Per Connection Hook that sets up the connections state*/
  ap_hook_pre_connection(tor_hook_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
  /* hook tor_init in to apache2 after config */
  ap_hook_post_config(tor_init, NULL, NULL, APR_HOOK_MIDDLE);
  /* hook tor_handler in to apache2 */
  ap_hook_handler(tor_handler, NULL, NULL, APR_HOOK_MIDDLE);

  //SSL happens at +5 so we want to happen at +6
  ap_register_input_filter  (tor_io_filter, tor_io_filter_input,  NULL, AP_FTYPE_CONNECTION + 6);

  /* hook tor_handler in to apache2 PROXY VERSION */
  //proxy_hook_scheme_handler(tor_handler, NULL, NULL, APR_HOOK_MIDDLE);
  /* tor_hook_ReadReq needs the data to be decrypted before sending to tor
   * so run after mod_ssl's post_read_request hook. */
    //static const char *pre_prr[] = { "mod_ssl.c", NULL };
  	  /*Per read request that looks to see if the connection is authenticated*/
  	  //ap_hook_post_read_request(tor_hook_ReadReq, pre_prr, NULL, APR_HOOK_MIDDLE);

}




/*
 * Declare and populate the module's data structure.  The
 * name of this structure ('tor_module') is important - it
 * must match the name of the module.  This structure is the
 * only "glue" between the httpd core and the module.
 */
module AP_MODULE_DECLARE_DATA tor_module =
{
	STANDARD20_MODULE_STUFF, // standard stuff; no need to mess with this.
	NULL, // create per-directory configuration structures - we do not.
	NULL, // merge per-directory - no need to merge if we are not creating anything.
	create_modtor_config, // create per-server configuration structures.
	NULL, // merge per-server
	mod_tor_cmds, // configuration directive handlers
	tor_hooks, // request handlers
};

