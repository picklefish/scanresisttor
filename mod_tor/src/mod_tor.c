#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <apr_poll.h>
#include <mod_ssl.h>
//Probably remove this later, the only thing using it are some logging constants
#include <mod_proxy.h>


/*
 * The default value for config directives
 */
#ifndef DEFAULT_MODTOR_PASSWORD
#define DEFAULT_MODTOR_PASSWORD "password=pancake"//"tor://password=pancake"
#endif

#ifndef DEFAULT_MODTOR_PORT
#define DEFAULT_MODTOR_PORT 12312//44114//12312//443
#endif



static const char tor_io_filter[] = "Tor Filter";

/* used for reading input blocks */
#define READ_BLOCKSIZE 2048

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
#if DEBUGGING
	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
				"mod_tor: Closing Tor Socket");
	fflush(stderr);
#endif

	if(sock){
		apr_socket_close(sock);
	}
#if DEBUGGING
	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
				"mod_tor: Closed Tor Socket");
#endif

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

                //Set up socket options if we need to...

                rv = apr_socket_opt_set(torconn->apache2_to_tor_sock, APR_SO_KEEPALIVE, 1);
                if ( rv != APR_SUCCESS) {
                        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, c->base_server,
                                        "mod_tor: Init: Failed to set keep alive", (int)s_cfg->mod_tor_port);
                  apr_socket_close(torconn->apache2_to_tor_sock);
                  return -1;//replace with actual err# later
                }

                rv = apr_socket_connect(torconn->apache2_to_tor_sock, localsa);

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









int tor_read_data_input_filter(ap_filter_t *f, apr_bucket_brigade *bb,
								ap_input_mode_t mode, apr_read_type_e block,
								apr_off_t readbytes){
	request_rec *r = f->r;
	apr_socket_t *client_socket = ap_get_module_config(r->connection->conn_config, &core_module);
	apr_status_t rv;
	char buffer[HUGE_STRING_LEN];
	apr_size_t len;

	len = sizeof(buffer);

		//Read the data off the client socket
	rv = apr_socket_recv(client_socket, buffer, &len);
		//Create the bucket based on the data read in and insert it
	apr_bucket *b = apr_bucket_transient_create(&buffer, len, r->connection->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(bb, b);

	return rv;

}







/*
 * This handles the HTTPS query string password,
 * and authenticates the user if they send the correct password
 */

static int tor_handler(request_rec *r) {

  TorConnRec *torconn = myTorConnConfig(r->connection);

	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "proxy: Tor: STARTING HANDLER");

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

  //IS THE CONNECTION HTTPS?
  if ((APR_RETRIEVE_OPTIONAL_FN(ssl_is_https))(r->connection) == 0){
	//the connection isn't HTTPS
	return DECLINED;
  }

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
		if(tor_init_connection_tor_socket(r->connection,torconn) != APR_SUCCESS){
			ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
					  "proxy: Tor: Cannot connect to socket to Tor process...");
			return DECLINED; //Possibly return an error since this means Tor isn't
							 //accepting sockets
		}
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

	/*
	 * We don't want HTTP filters adding stuff to our data  so we're going to
	 * hop to the SSL input and output filter and remove all the other filters
	 * from the input and output filter lists
	 * XXX: Do i need to do any sort of cleanup on those filter I removed :/
	 */

	ap_add_input_filter("tor_read_data", NULL, r, c);
	ap_filter_t *f;
		//Clear the input filters except for the ssl filter to core filter
	for(f = r->input_filters; f != NULL; f = f->next){
		if(strncmp(f->frec->name, "ssl/tls filter", sizeof("ssl/tls filter")) != 0){
				//Remove all but the SSL/TLS filter for now...
			ap_remove_input_filter(f);
		}
	}

#ifdef DEBUGGING
	for(f = r->input_filters; f != NULL; f = f->next){
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
				  "proxy: Tor: Input_filters before %s", f->frec->name);
	}
#endif
		//Create the tor input filter and switch it with the ssl one so it's
		//the lowest on the stack
	f = ap_add_input_filter("tor_read_data", NULL, r, c);
	r->input_filters->next = f;
	r->input_filters->frec->next = f->frec;
	f->next = NULL;
	f->frec->next = NULL;

#ifdef DEBUGGING
	for(f = r->input_filters; f != NULL; f = f->next){
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
				  "proxy: Tor: Input_filters after %s", f->frec->name);
	}
#endif



		//Clear the output filters except for the ssl filter to core filter
	for(f = r->output_filters; f != NULL; f = f->next){
		if(strncmp(f->frec->name, "ssl/tls filter", sizeof("ssl/tls filter")) != 0){
			ap_remove_input_filter(f);
		}
		else{
				//In output we want to keep the core filter which follows the SSL filter
			    //as it writes to the network correctly, so we break out.
			break;
		}
	}
	if(f == NULL){
		return DECLINED; //For some reason SSL was not on the output filter stack... failure.
	}
	else{
		r->output_filters = f;
	}


	ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
			  "proxy: Tor: Returning 200 OK Status");


	nbytes = apr_snprintf(buffer, sizeof(buffer),
			  "HTTP/1.0 200 Connection Established" CRLF);
	ap_xlate_proto_to_ascii(buffer, nbytes);
	ap_rwrite(buffer, nbytes, r);
	ap_rflush(r);

	nbytes = apr_snprintf(buffer, sizeof(buffer),
			"Proxy-agent: Tor" CRLF CRLF);
	ap_xlate_proto_to_ascii(buffer, nbytes);
	ap_rwrite(buffer, nbytes, r);
	ap_rflush(r);

	/*
	 * Step Four: Handle Data Transfer
	 *
	 * Handle two way transfer of data over the socket (this is a tunnel).
	 */

	/*    r->sent_bodyct = 1;*/
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
			"proxy: TOR: setting up poll()");

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
	pollfd.desc.s = client_socket;
	pollfd.client_data = NULL;
	apr_pollset_add(pollset, &pollfd);

	/* Add the server side to the poll */
	pollfd.desc.s = tor_socket;//sock;
	apr_pollset_add(pollset, &pollfd);

#ifdef DEBUGGING
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
        		"proxy: TOR: finished setting up poll stuffs about to start while loop");
#endif


	while (1) { /* Infinite loop until error (one side closes the connection) */
		if ((rv = apr_pollset_poll(pollset, -1, &pollcnt, &signalled)) != APR_SUCCESS) {
			apr_socket_close(tor_socket);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "proxy: Tor: error apr_poll()");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
#ifdef DEBUGGING
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "proxy: CONNECT: woke from select(), i=%d", pollcnt);
#endif

		for (pi = 0; pi < pollcnt; pi++) {
			const apr_pollfd_t *cur = &signalled[pi];

			if (cur->desc.s == tor_socket) {
				pollevent = cur->rtnevents;
				if (pollevent & APR_POLLIN) {
#ifdef DEBUGGING
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                                 "proxy: CONNECT: sock was set");
#endif
					nbytes = sizeof(buffer);
					rv = apr_socket_recv(tor_socket, buffer, &nbytes);
					if (rv == APR_SUCCESS) {
						o = 0;
						i = nbytes;
						while(i > 0)
						{
							nbytes = i;
	/* This is just plain wrong.  No module should ever write directly
	 * to the client.  For now, this works, but this is high on my list of
	 * things to fix.  The correct line is:
	 * if ((nbytes = ap_rwrite(buffer + o, nbytes, r)) < 0)
	 * rbb
	 */
							ap_rwrite(buffer + o, nbytes, r);
							ap_rflush(r);
							o += nbytes;
							i -= nbytes;
						}
					}
					else{
						ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
									 "proxy: Tor: ERROR RECV FROM TOR_SOCKET", i);
						break;
					}
				}
				else if ((pollevent & APR_POLLERR) || (pollevent & APR_POLLHUP))
					break;
			}
			else if (cur->desc.s == client_socket) {
				pollevent = cur->rtnevents;
				if (pollevent & APR_POLLIN) {
#ifdef DEBUGGING
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                                 "proxy: CONNECT: client was set");
#endif
					nbytes = sizeof(buffer);
					char *str;

						//This creates a buffer and calls my modified input filter stack
						//possibly move this to a function...
					apr_bucket_brigade *bb = apr_brigade_create(r->pool, c->bucket_alloc);
					ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
					apr_bucket *b = APR_BRIGADE_FIRST(bb);
					//strncpy(buffer, (char *)b->data + b->start, b->length);
					str = (char *)b->data + b->start;
					nbytes = b->length;

					if (rv == APR_SUCCESS) {
						o = 0;
						i = nbytes;
#ifdef DEBUGGING
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                                     "proxy: CONNECT: read %d from client", i);
#endif
						while(i > 0)
						{
							nbytes = i;
							rv = apr_socket_send(tor_socket, str + o, &nbytes);
							if (rv != APR_SUCCESS)
								break;
							o += nbytes;
							i -= nbytes;
						}
					}
					else{
						ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
									 "proxy: Tor: omg socket doesn't exist?", i);
						break;
					}
				}
				else if ((pollevent & APR_POLLERR) || (pollevent & APR_POLLHUP)) {
					ap_log_error(APLOG_MARK, APLOG_STARTUP/*APLOG_DEBUG*/, 0, NULL,
								 "proxy: Tor: omg eof?", i);
					rv = APR_EOF;
					break;
				}
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

	/* we are acting as a tunnel - the output filter stack should
	 * be completely empty, because when we are done here we are done completely.
	 * We add the NULL filter to the stack to do this...
	 */
	r->output_filters = NULL;
	r->connection->output_filters = NULL;

		//Close the connection to the client
	close(c);//Not sure if this actually closes the client or not... -shane

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
	s_cfg->mod_tor_port = (apr_port_t) atoi(arg);

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

  /*An input filter I wrote to read raw data off a socket and pass it to SSL before passing it to tor
   *Added to the input filters after authentication*/
  ap_register_input_filter("tor_read_data", tor_read_data_input_filter, NULL, AP_FTYPE_NETWORK) ;

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

