package jp.ken1ma.pg_select_pcap

import java.net.InetAddress

import org.pcap4j.core.Pcaps
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode
import org.pcap4j.core.BpfProgram.BpfCompileMode
import org.pcap4j.core.PacketListener
import org.pcap4j.packet.{Packet, EthernetPacket, IpV4Packet, TcpPacket}
//import org.pcap4j.util.NifSelector

import org.slf4j.LoggerFactory

class Main

object Main extends App {
	val log = LoggerFactory.getLogger(classOf[Main])

	if (args.size != 2) {
		System.err.println("args: nif serverAddr")
		System.exit(1)
	}
	val nifName = args(0)
	val serverAddr = InetAddress.getByName(args(1))

	val snapLen = 65536
	val readTimeout = 10 // ms

	val encoding = "UTF-8"

	//val nif = new NifSelector().selectNetworkInterface // select interactively
	val nif = Pcaps.getDevByName(nifName)

	log.info(s"opening ${nif.getName}${Option(nif.getDescription).map(" (" + _ + ")").getOrElse("")}")
	val handle = nif.openLive(snapLen, PromiscuousMode.PROMISCUOUS, readTimeout)

	val filter = s"dst host ${serverAddr.getHostAddress}"
	log.info(s"filter = $filter")
	handle.setFilter(filter, BpfCompileMode.OPTIMIZE)
	handle.loop(-1, // infinite
			new PacketListener {
				def gotPacket(packet: Packet) = packet match {
					case ethPacket: EthernetPacket => ethPacket.getPayload match {
						case ipPacket: IpV4Packet =>
							val ipHeader = ipPacket.getHeader
							val (srcAddr, dstAddr) = (ipHeader.getSrcAddr, ipHeader.getDstAddr) // they are unsigned short
							ipPacket.getPayload match {
								case tcpPacket: TcpPacket =>
									val tcpPayload = tcpPacket.getPayload
									if (tcpPayload != null) {
										val tcpHeader = tcpPacket.getHeader
										val (srcPort, dstPort) = (tcpHeader.getSrcPort.value & 0xffff, tcpHeader.getDstPort.value & 0xffff) // they are unsigned short
										//log.info(s"${srcAddr.getHostAddress}:$srcPort -> ${dstAddr.getHostAddress}:$dstPort")
										//println(HexDump.dump(tcpPacket.getPayload.getRawData))

										val data = tcpPacket.getPayload.getRawData

										// v3 (org.postgresql.core.v3.QueryExecutorImpl.sendParse)
										if (data(0) == 'P') {
											var i = 5 // just after encodedSize

											// skip encodedStatementName
											while (data(i) != 0)
												i += 1
											i += 1

											// get query
											val queryStart = i
											while (data(i) != 0)
												i += 1
											i += 1
											val queryEnd = i

											val query = new String(data, queryStart, queryEnd - queryStart, "UTF-8")
											println(s"query = $query")

										// v2 (org.postgresql.core.v2.QueryExecutorImpl.sendQuery)
										} else if (data(0) == 'Q') {
											val dataLen = data(1) << 24 | data(2) << 16 | data(3) << 8 | data(4)
											val queryLen = dataLen - 4 - 1 // exclude the dataLen and null char at the last
											val query = new String(data, 5, queryLen, encoding)
											println(s"query = $query")
										}
									}

								case packet =>
									log.warn(s"non TcpPacket: ${packet.getClass.getName}")
							}

						case _ => // ignore ArpPacket, IcmpV4CommonPacket, etc
					}

					case packet =>
						log.warn(s"non EthernetPacket: ${packet.getClass.getName}")
				}
			}
	)
}
