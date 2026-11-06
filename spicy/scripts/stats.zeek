# -----------------------------------------------------------
#
#  stats.zeek
#
# Write Zeek's own load figures to stats.log (packets seen and dropped, events, memory) so that the load of the
# monitor can be watched next to the TSN logs. The interval can be changed on the command line,
# for example `Stats::report_interval=1min`.
#
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

@load policy/misc/stats

redef Stats::report_interval = 10 secs;
