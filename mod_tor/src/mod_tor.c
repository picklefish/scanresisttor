#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <mod_ssl.h>
#include <mod_proxy.h>
#include <apr_poll.h>

//#include "ssl_private.h"
#include "apr_buckets_simple.c"

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

    if (torconn && !(torconn->isAuthenticated)) {
            return DECLINED;
    }



    //This is where we would pass the data to Tor
    //Get the decrypted data from the last bucket ssl just created this...
    simple_bucket_read(APR_BRIGADE_LAST(bb), &buffer[0], &nbytes, block );


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
			rv = apr_socket_send(torconn->apache2_to_tor_sock,  + o, &nbytes);

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
	r->output_filters = NULL;
	//r->connection->output_filters = NULL;

	//SSLConnRec *sslconn = NULL;
	//if ((APR_RETRIEVE_OPTIONAL_FN(ssl_is_https))(r->connection) != 0){
	//	sslconn = (SSLConnRec *)ap_get_module_config(c->conn_config, &ssl_module);
	//}

	ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
		 "proxy: Tor: Returning 200 OK Status");
	nbytes = apr_snprintf(buffer, sizeof(buffer),
			  "HTTP/1.0 200 Connection Established" CRLF);
	ap_xlate_proto_to_ascii(buffer, nbytes);
    apr_socket_send(client_socket, buffer, &nbytes);

	nbytes = apr_snprintf(buffer, sizeof(buffer),
			  "Proxy-agent: %s" CRLF CRLF, "Mod_Tor");
	ap_xlate_proto_to_ascii(buffer, nbytes);
	apr_socket_send(client_socket, buffer, &nbytes);

	ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
		 "proxy: TOR: setting up poll()");

	/*
	 * Step Four: Handle Data Transfer
	 *
	 * Handle two way transfer of data over the socket (this is a tunnel).
	 */

	/*    r->sent_bodyct = 1;*/

	if ((rv = apr_pollset_create(&pollset, 2, r->pool, 0)) != APR_SUCCESS) {
		apr_socket_close(apache2_to_tor_sock);
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
	pollfd.desc.s = apache2_to_tor_sock;//sock;
	apr_pollset_add(pollset, &pollfd);


	while (1) { /* Infinite loop until error (one side closes the connection) */
		if ((rv = apr_pollset_poll(pollset, -1, &pollcnt, &signalled)) != APR_SUCCESS) {
			apr_socket_close(apache2_to_tor_sock);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "proxy: Tor: error apr_poll()");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
					 "proxy: Tor: woke from select(), i=%d", pollcnt);

		for (pi = 0; pi < pollcnt; pi++) {
			const apr_pollfd_t *cur = &signalled[pi];

			if (cur->desc.s == apache2_to_tor_sock) {
				pollevent = cur->rtnevents;
				if (pollevent & APR_POLLIN) {
					ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
								 "proxy: TOR: sock was set");
					nbytes = sizeof(buffer);
					rv = apr_socket_recv(apache2_to_tor_sock, buffer, &nbytes);
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
							rv = apr_socket_send(client_socket, buffer + o, &nbytes);

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
	apr_socket_close(apache2_to_tor_sock);

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

