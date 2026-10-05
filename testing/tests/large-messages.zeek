# @TEST-DOC: Only the first 64 KiB of a message is kept; longer messages are truncated, not buffered, and the parser stays in sync for the message that follows.
#
# @TEST-EXEC: python3 ${DIST}/testing/Scripts/gen-trace messages trace.pcap
# @TEST-EXEC: zeek -Cr trace.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output

# Payload sizes sent: 50, 65535, 65536, 65537, 100000, 25. Expect the two
# longest to be cut to 65536 and the final small message to still arrive.
event NJRAT::message(c: connection, is_orig: bool, payload: string)
	{
	print payload[:3], is_orig, |payload|;
	}
