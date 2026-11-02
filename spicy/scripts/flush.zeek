# -----------------------------------------------------------
#
#  flush.zeek
#
# Optionally flush the logs regularly so that `tail -f` shows them as they happen (live demos).
#
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

module TSN;

export {
	## Flush cb.log, ptp.log, srp.log and tsn_errors.log this often; 0 disables it.
	const log_flush_interval = 0 secs &redef;
}

event flush_logs()
	{
	Log::flush(LOG_CB);
	Log::flush(LOG_PTP);
	Log::flush(LOG_SRP);
	Log::flush(LOG_ERRORS);
	Log::flush(Notice::LOG);
	schedule log_flush_interval { flush_logs() };
	}

event zeek_init() &priority=-5
	{
	if ( log_flush_interval > 0 secs )
		schedule log_flush_interval { flush_logs() };
	}
