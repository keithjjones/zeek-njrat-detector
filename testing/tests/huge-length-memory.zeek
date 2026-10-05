# @TEST-DOC: A peer that claims an enormous payload length and then streams data must not make the analyzer buffer that data.
#
# @TEST-EXEC: python3 ${DIST}/testing/Scripts/gen-trace huge-len trace.pcap 134217728
# @TEST-EXEC: zeek -Cr trace.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: rm -f trace.pcap
# @TEST-EXEC: btest-diff output

# The trace carries 128 MiB after a message that claims a ~10 GB payload. If the
# analyzer buffered it, memory would grow by at least that much; allow half.
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
