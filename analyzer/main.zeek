module NJRAT;

@load frameworks/intel/seen
@load base/frameworks/intel/files.zeek

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

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
		## The  RAT command, still delimited.
		payload: string &log &optional;
	};

	## Default hook into NJRAT logging.
	global log_njrat: event(rec: Info);
}

redef record connection += {
	njrat: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(NJRAT::LOG, [$columns=Info, $ev=log_njrat, $path="njrat"]);
	}

# Initialize logging state.
hook set_session(c: connection)
	{
	if ( c?$njrat )
		return;

	c$njrat = Info($ts=network_time(), $uid=c$uid, $id=c$id);
	}

function emit_log(c: connection)
	{
	if ( ! c?$njrat )
		return;

	Log::write(NJRAT::LOG, c$njrat);
	delete c$njrat;
	}

event NJRAT::message(c: connection, is_orig: bool, payload: string)
	{
	hook set_session(c);

	c$njrat$payload = payload;
	c$njrat$is_orig = is_orig;

	emit_log(c);
	}

event zeek_init() 
	{
	# Load up our IOCs
	local intel_item = [$indicator="7.tcp.eu.ngrok.io", $indicator_type=Intel::DOMAIN, $meta=[$source="njRAT", $url="https://app.any.run/tasks/72f74893-b9dc-4b1d-9d55-39e0eae86bda/#"]];
	Intel::insert(intel_item);

	intel_item = [$indicator="3.68.56.232", $indicator_type=Intel::ADDR, $meta=[$source="njRAT", $url="https://app.any.run/tasks/72f74893-b9dc-4b1d-9d55-39e0eae86bda/#"]];
	Intel::insert(intel_item);

	intel_item = [$indicator="3f1a2a27304c02ea6e56bfd81b0bfc4cf8db5040c23f854d09b6728b1803a8b9", $indicator_type=Intel::FILE_HASH, $meta=[$source="njRAT", $url="https://app.any.run/tasks/72f74893-b9dc-4b1d-9d55-39e0eae86bda/#"]];
	Intel::insert(intel_item);
	}