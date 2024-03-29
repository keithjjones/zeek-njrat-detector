# @TEST-DOC: Test Zeek parsing a trace file through the NJRAT analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/njrat.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff njrat.log
# @TEST-EXEC: btest-diff notice.log

# Turn on logs
redef NJRAT::enable_detailed_logs = T;