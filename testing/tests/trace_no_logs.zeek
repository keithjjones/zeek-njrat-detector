# @TEST-DOC: Test Zeek parsing a trace file through the NJRAT analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/njrat.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: test ! -f njrat.log
# @TEST-EXEC: btest-diff notice.log

redef NJRAT::enable_detailed_logs = F;