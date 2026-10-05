# @TEST-DOC: An endless run of digits where the length should end must not make the analyzer buffer it.
#
# @TEST-EXEC: python3 ${DIST}/testing/Scripts/gen-trace digit-run trace.pcap 134217728
# @TEST-EXEC: zeek -Cr trace.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: rm -f trace.pcap
# @TEST-EXEC: btest-diff output

# After one valid message the trace carries 128 MiB of digits and no terminator.
# If the analyzer buffered them, memory would grow by at least that much; allow half.
global start_mem: count;

event zeek_init()
	{
	start_mem = get_proc_stats()$mem;
	}

event zeek_done()
	{
	print fmt("memory growth stayed under 64 MiB: %s",
	    get_proc_stats()$mem < start_mem + 64 * 1048576);
	}
