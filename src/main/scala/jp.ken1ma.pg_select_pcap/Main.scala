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
										log.debug(s"${srcAddr.getHostAddress}:$srcPort -> ${dstAddr.getHostAddress}:$dstPort")
										//print(util.HexDump.toString(tcpPacket.getPayload.getRawData))

										val data = tcpPacket.getPayload.getRawData

										// v3 (org.postgresql.core.v3.QueryExecutorImpl.sendParse)
										if (data(0) == 'P') {
											var i = 1

											// messageSize
											val messageSize = data(i) << 24 | data(i + 1) << 16 | data(i + 2) << 8 | data(i + 3)
											i += 4
											log.debug(s"messageSize = $messageSize")

											// skip encodedStatementName
											while (data(i) != 0)
												i += 1
											i += 1

											// get query string in UTF-8
											val queryStart = i
											while (data(i) != 0)
												i += 1
											i += 1
											val queryEnd = i
											val query = new String(data, queryStart, queryEnd - queryStart, "UTF-8")
											log.info(s"query (v3) = $query")

											// get number of parameters
											val numParams = data(i) << 8 | data(i + 1)
											i += 2
											log.debug(s"numParams = $numParams")

											// (org.postgresql.core.v3.QueryExecutorImpl.sendBind)
											if (numParams > 0) {
												// get parameter type OIDs
												val paramTypeOids = new Array[Int](numParams)
												for (j <- 0 until numParams) {
													paramTypeOids(j) = data(i) << 24 | data(i + 1) << 16 | data(i + 2) << 8 | data(i + 3)
													i += 4
												}
												log.debug(s"paramTypeOids = ${paramTypeOids.mkString(", ")}")

												if (data(i) == 'B') {
													i += 1
													log.debug("bind")

													// messageSize
													val messageSizeBind = data(i) << 24 | data(i + 1) << 16 | data(i + 2) << 8 | data(i + 3)
													i += 4
													log.debug(s"messageSize = $messageSizeBind")

													// skip destination portal name
													while (data(i) != 0)
														i += 1
													i += 1

													// skip encodedStatementName
													while (data(i) != 0)
														i += 1
													i += 1

													val numFormatCodes = data(i) << 8 | data(i + 1)
													i += 2
													if (numFormatCodes != numParams)
														throw new Exception(s"number of parameter format codes differ between query and bind: $numFormatCodes, $numParams")

													// get parameter formats
													val paramFormatCodes = new Array[Int](numParams)
													for (j <- 0 until numParams) {
														paramFormatCodes(j) = data(i) << 8 | data(i + 1)
														i += 2
													}
													log.debug(s"paramFormatCodes = ${paramFormatCodes.mkString(", ")}")

													val numParamValues = data(i) << 8 | data(i + 1)
													i += 2
													if (numParamValues != numParams)
														throw new Exception(s"number of parameter values differ between query and bind: $numParamValues, $numParams")

													for (j <- 0 until numParams) {
														val paramSize = data(i) << 24 | data(i + 1) << 16 | data(i + 2) << 8 | data(i + 3)
														i += 4

														if (paramSize == -1)
															log.info(s"param $j: null")

														else {
															val paramValue = new Array[Byte](paramSize)
															for (k <- 0 until paramSize)
																paramValue(k) = data(i + k)
															i += paramSize

															if (paramFormatCodes(j) == 0) // text
																log.info(s"param $j: " + new String(paramValue, "UTF-8"))

															else if (paramFormatCodes(j) == 1) { // binary
																if (paramSize == 1)
																	log.info(s"param $j: " + (paramValue(0) & 0xff)) // TODO: how about singed?

																else if (paramSize == 2)
																	log.info(s"param $j: " + (paramValue(0) << 8 | paramValue(1)))

																else if (paramSize == 4)
																	log.info(s"param $j: " + (paramValue(0) << 24 | paramValue(1) << 16 | paramValue(2) << 8 | paramValue(3)))

																else
																	log.warn(s"unsupported binary parameter size: ${paramSize}")

															} else
																log.warn(s"unknown parameter format code: ${paramFormatCodes(j)}")
														}
													}



												} else
													log.warn("expected binds but got: " + data(i).toChar)
											}

										// v2 (org.postgresql.core.v2.QueryExecutorImpl.sendQuery)
										// org.postgresql.core.v3.QueryExecutorImpl.startCopy
										} else if (data(0) == 'Q') {
											val dataLen = data(1) << 24 | data(2) << 16 | data(3) << 8 | data(4)
											val queryLen = dataLen - 4 - 1 // exclude the dataLen and null char at the last
											val query = new String(data, 5, queryLen, encoding)
											log.warn(s"query (v2) = $query")
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
