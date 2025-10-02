module NJRAT;

#@load frameworks/intel/seen
#@load base/frameworks/intel/files.zeek

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	redef enum Notice::Type += {
		## This notice is generated when a connection is potentially njRAT
		## malware C2.
		C2_Traffic_Observed,
	};

	## An option to enable detailed logs
	const enable_detailed_logs = T &redef;

	## Record type containing the column fields of the NJRAT log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## The direction of this njRAT message.
		is_orig: bool &log &optional;
		## The RAT command, still delimited.
		payload: string &log &optional;
	};

	## Default hook into NJRAT logging.
	global log_njrat: event(rec: Info);

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;
}

event zeek_init() &priority=5
	{
	if ( enable_detailed_logs )
		Log::create_stream(NJRAT::LOG, [ $columns=Info, $ev=log_njrat, $path="njrat",
		    $policy=NJRAT::log_policy ]);
	}

event NJRAT::message(c: connection, is_orig: bool, payload: string)
	{
	local msg = fmt("Potential njRAT C2 between source %s and dest %s with is_orig %s and payload in the sub field.",
	    c$id$orig_h, c$id$resp_h, is_orig);

	if ( enable_detailed_logs )
		{
		local info = Info($ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
		    $payload=payload);

		Log::write(NJRAT::LOG, info);

		NOTICE([ $note=NJRAT::C2_Traffic_Observed, $msg=msg, $sub=payload, $conn=c, $identifier=cat(
		    c$id$orig_h, c$id$resp_h) ]);
		}
	else
		# Do not suppress notices.
		NOTICE([ $note=NJRAT::C2_Traffic_Observed, $msg=msg, $sub=payload, $conn=c ]);
	}


#event zeek_init()
#	{
# Load up our IOCs
# Commenting out since IoCs have a short life.
# Leaving here since it was discussed in a blog.
#	local intel_item = [$indicator="7.tcp.eu.ngrok.io", $indicator_type=Intel::DOMAIN, $meta=[$source="njRAT", $url="https://app.any.run/tasks/72f74893-b9dc-4b1d-9d55-39e0eae86bda/#"]];
#	Intel::insert(intel_item);

#	intel_item = [$indicator="3.68.56.232", $indicator_type=Intel::ADDR, $meta=[$source="njRAT", $url="https://app.any.run/tasks/72f74893-b9dc-4b1d-9d55-39e0eae86bda/#"]];
#	Intel::insert(intel_item);

#	intel_item = [$indicator="3f1a2a27304c02ea6e56bfd81b0bfc4cf8db5040c23f854d09b6728b1803a8b9", $indicator_type=Intel::FILE_HASH, $meta=[$source="njRAT", $url="https://app.any.run/tasks/72f74893-b9dc-4b1d-9d55-39e0eae86bda/#"]];
#	Intel::insert(intel_item);
#	}
