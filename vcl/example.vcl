#
# This is an example VCL file for Varnish.
#
# It does not do anything by default, delegating control to the
# builtin VCL. The builtin VCL is called when there is no explicit
# return statement.
#
# See the VCL chapters in the Users Guide at https://www.varnish-cache.org/docs/
# and https://www.varnish-cache.org/trac/wiki/VCLExamples for more examples.

# Marker to tell the VCL compiler that this VCL has been adapted to the
# new 4.0 format.
vcl 4.0;
import sec;
import std;
import vtc;

# Default backend definition. Set this to point to your content server.
backend default {
    .host = "127.0.0.1";
    .port = "80";
}

sub vcl_init {
	new modsec = sec.sec();
	modsec.add_rules("/usr/share/modsecurity-crs/crs-setup.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-901-INITIALIZATION.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-903.9003-NEXTCLOUD-EXCLUSION-RULES.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-903.9004-DOKUWIKI-EXCLUSION-RULES.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-903.9005-CPANEL-EXCLUSION-RULES.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-910-IP-REPUTATION.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-911-METHOD-ENFORCEMENT.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-912-DOS-PROTECTION.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-913-SCANNER-DETECTION.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-921-PROTOCOL-ATTACK.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/RESPONSE-950-DATA-LEAKAGES.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/RESPONSE-952-DATA-LEAKAGES-JAVA.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/RESPONSE-954-DATA-LEAKAGES-IIS.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/RESPONSE-959-BLOCKING-EVALUATION.conf");
	modsec.add_rules("/usr/share/modsecurity-crs/rules/RESPONSE-980-CORRELATION.conf");
	modsec.add_rules("https://www.modsecurity.org/modsecurity-regression-test-secremoterules.txt", "test");
	modsec.add_rule({"SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 2" "id:950013332,phase:3,pass,nolog,skipAfter:END-RESPONSE-950-DATA-LEAKAGES"});
	modsec.dump_rules();
}

sub handle_intervention {
    if (modsec.intervention_getDisrupt()) {
        std.syslog(9, "Need to mess with ya");
        vtc.sleep(modsec.intervention_getPause());
	set req.http.X-intervention-status = modsec.intervention_getStatus();
	set req.http.X-Intervention-Url = modsec.intervention_getUrl();
	std.log(modsec.intervention_getLog());
	if (req.http.X-intervention-status == "403") {
		modsec.conn_close();
	}
	if (req.http.X-intervention-status ~ "^30.$") {
		return (synth(900, "Intervention"));
	}
    }
}

sub vcl_synth {
    if (resp.status == 900) {
      set resp.http.location = req.http.X-intervention-status;
      set resp.status = std.integer(req.http.X-intervention-status, 302);
      return(deliver);
    }
}

sub vcl_recv {
    modsec.new_conn(client.ip, std.port(client.ip), server.ip, std.port(server.ip));
    call handle_intervention;
    modsec.process_url(req.url, req.method, regsub(req.proto, "^.*/", ""));
    call handle_intervention;
    std.cache_req_body(500KB);
    modsec.do_process_request_body(true);
    call handle_intervention;
#    modsec.conn_reset();

    # Happens before we check if we have this in cache already.
    #
    # Typically you clean up the request here, removing cookies you don't need,
    # rewriting the request, etc.
}

sub vcl_backend_response {
    # Happens after we have read the response headers from the backend.
    #
    # Here you clean the response headers, removing silly Set-Cookie headers
    # and other mistakes your backend does.
}

sub vcl_deliver {
    # Happens when we have all the pieces we need, and are about to send the
    # response to the client.
    #
    # You can do accounting or modifying the final object here.
    modsec.process_response();
    call handle_intervention;
    modsec.do_process_response_body(false);
    call handle_intervention;
}


