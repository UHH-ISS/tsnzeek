# Data plane: Spicy grammars and Zeek scripts

## Files

| File | Purpose |
| --- | --- |
| `spicy-analyzer/FRER.spicy`, `SRP.spicy`, `PTP.spicy` | grammars of the redundancy tag, enhanced SRP and (g)PTP; the public types are the entry points (`PTPFrame` over Ethernet, `PTPUDPFrame` over UDP) |
| `spicy-analyzer/TSN.evt` | packet analyzers for the ethertypes `0xF1C1` (FRER), `0x22EA` (SRP), `0x88F7` (PTP), a protocol analyzer for PTP over UDP (ports 319 and 320), the exports to Zeek, the event hooks and the `%error` hooks |
| `scripts/register.zeek` | registers the analyzers (also behind a VLAN tag) |
| `scripts/main.zeek` | shared options, the error log and the helper that sends records to the IDS |
| `scripts/cb.zeek`, `ptp.zeek`, `srp.zeek` | log the respective messages and send them to the IDS |
| `scripts/broker.zeek` | the connection to the IDS |
| `scripts/flush.zeek` | optional regular log flush for live demos |

`../build.sh` compiles the grammars to `../build/spicy/tsn.hlto`; Zeek finds it through `ZEEK_SPICY_MODULE_PATH`, so
`zeek -r x.pcap spicy/scripts` is the whole invocation.

## Logs

| Log | One row per | Notes |
| --- | --- | --- |
| `cb.log` | FRER frame | sequence number and the reserved field |
| `ptp.log` | PTP message | the header (transportSpecific, domain, flags, sequenceId, ...) and the fields of the message type; PTP over UDP rows also carry `uid`, `src_port`, `dst_port` and IP addresses in `src`/`dst` |
| `srp.log` | Talker or Listener Enhanced message | stream, traffic specification, status, interfaces |
| `tsn_errors.log` | malformed frame | which protocol and why: truncated fields, wrong lengths, missing or duplicate TLVs, reserved PTP message types, `messageLength` that does not match the frame |
| `notice.log` | alert of the IDS | `TSN::Possible_Attack` |

PTP tolerates Ethernet padding and suffix TLVs; over UDP any octet beyond `messageLength` is reported.

## Options

Set on the command line, e.g. `TSN::enable_broker=F`:

| Option | Default | Effect |
| --- | --- | --- |
| `TSN::enable_broker` | `T` | listen for the IDS on `127.0.0.1:9999` and send it the messages; disable for plain pcap runs |
| `TSN::wait_for_peer` | `F` | pause until the IDS announces itself (`ids_ready`) and end the run when it is done (`ids_done`); for offline runs with the IDS |
| `TSN::log_flush_interval` | `0 secs` | flush the logs this often, so that `tail -f` shows them as they are written |

## Known gaps

- The Spicy UDP analyzer stops parsing a flow after its first parse error, so one malformed PTP datagram blinds the
  analyzer for that 4-tuple until the connection times out. Length problems are still reported (they are not parse errors).

## Trying a grammar on its own

```sh
printf '\x0f\n\x02\x08\x00\x00\x00\x00\x00\x00\x00\x00\x10\x05\x11\x03\x00\x00\x00' | /opt/zeek/bin/spicy-driver -d spicy-analyzer/SRP.spicy
```

Frames to try can be forged with the Scapy layers in [`../scapy/`](../scapy/README.md).
