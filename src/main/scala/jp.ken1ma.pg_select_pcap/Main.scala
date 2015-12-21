package jp.ken1ma.pg_select_pcap

import java.net.InetAddress

import org.pcap4j.core.Pcaps
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode
import org.pcap4j.core.BpfProgram.BpfCompileMode
import org.pcap4j.core.PacketListener
import org.pcap4j.packet.{Packet, EthernetPacket, IpV4Packet, TcpPacket}
//import org.pcap4j.util.NifSelector

//import org.postgresql.core.Oid

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
										val sessionKey = PgSession.Key(srcAddr, srcPort, dstAddr, dstPort)
										val data = tcpPacket.getPayload.getRawData
										log.debug(s"$sessionKey ${data.size} bytes")
										//print(util.HexDump.toString(data))

										val session = PgSession.getSession(sessionKey)
										session.sent(data)

										session.messages.foreach { message =>
											message.typ match {
												// simple query
												// org.postgresql.core.v2.QueryExecutorImpl.sendQuery
												// org.postgresql.core.v3.QueryExecutorImpl.startCopy
												case 'Q' =>
													val query = message.nextUtf8StringUntilZero

													log.info(s"simple query: $query")

												// extended query
												// org.postgresql.core.v3.QueryExecutorImpl.sendParse
												case 'P' => // parse
													val statementName = message.nextUtf8StringUntilZero
													val query = message.nextUtf8StringUntilZero
													val numParams = message.nextInt2
													val paramTypeOids = (0 until numParams).map(_ => message.nextInt4)
													log.debug(s"parse $statementName: $query: ${paramTypeOids.mkString(", ")}")
													session.parses += (statementName -> PgParse(statementName, query, paramTypeOids))

												// org.postgresql.core.v3.QueryExecutorImpl.sendBind
												case 'B' => // bind
													val portalName = message.nextUtf8StringUntilZero
													val statementName = message.nextUtf8StringUntilZero

													val numParamFormatCodes = message.nextInt2
													val paramFormatCodes = (0 until numParamFormatCodes).map(_ => message.nextInt2)

													val numParamValues = message.nextInt2
													if (numParamValues != numParamFormatCodes)
														log.warn(s"numParamValues is $numParamValues while numParamFormatCodes is $numParamFormatCodes")
													val paramValues = (0 until numParamValues).map { index =>
														val paramSize = message.nextInt4
														if (paramSize == -1) // the magic size
															null

														else if (index < paramFormatCodes.size && paramFormatCodes(index) == 0) // text
															new String(message.nextBytes(paramSize).toArray, "UTF-8")

														else { // binary
															if (paramFormatCodes(index) != 1)
																log.warn(s"paramFormatCode is ${paramFormatCodes(index)}")
															paramSize match {
																case 1 => message.nextInt1
																case 2 => message.nextInt2
																case 4 => message.nextInt4
																case size => message.nextBytes(size)
															}
														}
													}

													session.parses.get(statementName) match {
														case Some(parse) =>
															def toText(value: Any) = value match {
																case null => "null"
																case text: String => "'" + text + "'"
																case array: Array[_] => "E'\\" + array.asInstanceOf[Array[Byte]].map(x => f"$x%02x").mkString(" ") + "'"
																case other => other.toString
															}
															log.info(s"extended query: ${parse.query}: ${paramValues.map(toText(_)).mkString(", ")}")

														case None =>
															log.debug(s"unknown statementName: $statementName")
													}

												// discard other message types
												case _ =>
											}
										}
										session.messages.clear
									}

								case packet => // ignore UdpPacket
							}

						case _ => // ignore ArpPacket, IcmpV4CommonPacket, etc
					}

					case _ => // ignore non EthernetPacket
				}
			}
	)
}
