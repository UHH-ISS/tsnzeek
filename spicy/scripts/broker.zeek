# -----------------------------------------------------------
#
#  broker.zeek
#
# Connection to the external (Python) IDS.
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# (C) 2024 Ahmed Abdulfattah, Berlin, Germany
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

module TSN;

export {
	## Pause packet processing until the external IDS announces itself with `ids_ready`, so that an offline pcap run
	## does not publish its events before the IDS is listening.
	const wait_for_peer = F &redef;
	## Where Zeek listens for the external IDS (Broker).
	const broker_listen_addr = "127.0.0.1" &redef;
	const broker_listen_port = 9999/tcp &redef;

	## Raised by the external IDS (via Broker) to report a suspected attack.
	global raise_notice: event(msg: string);

	## Sent by the external IDS once it is subscribed; releases `wait_for_peer`.
	global ids_ready: event();

	## Sent by the external IDS when it has consumed everything; ends an offline `wait_for_peer` run.
	global ids_done: event();
}

event raise_notice(msg: string)
	{
	NOTICE([$note=Possible_Attack, $msg=msg]);
	}

event ids_done()
	{
	if ( wait_for_peer )
		terminate();
	}

event zeek_init()
	{
	if ( ! enable_broker )
		return;

	Broker::listen(broker_listen_addr, broker_listen_port);
	Broker::subscribe("/topic/tsn");

	if ( wait_for_peer )
		suspend_processing();
	}

event ids_ready()
	{
	if ( wait_for_peer )
		continue_processing();
	}
