module NJRAT;

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

		# TODO: Adapt subsequent fields as needed.

		## Request-side payload.
		request: string &optional &log;
		## Response-side payload.
		reply: string &optional &log;
	};

	## Default hook into NJRAT logging.
	global log_njrat: event(rec: Info);
}

redef record connection += {
	njrat: Info &optional;
};

const ports = {
	# TODO: Replace with actual port(s).
	12345/tcp # adapt port number in njrat.evt accordingly
};

redef likely_server_ports += { ports };

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

# Example event defined in njrat.evt.
event NJRAT::message(c: connection, is_orig: bool, payload: string)
	{
	hook set_session(c);

	local info = c$njrat;
	if ( is_orig )
		info$request = payload;
	else
		info$reply = payload;
	}

event connection_state_remove(c: connection) &priority=-5
	{
	# TODO: For UDP protocols, you may want to do this after every request
	# and/or reply.
	emit_log(c);
	}
