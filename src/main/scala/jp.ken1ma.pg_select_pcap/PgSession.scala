package jp.ken1ma.pg_select_pcap

import scala.collection.mutable.{Buffer, ListBuffer, HashMap}
import java.net.InetAddress

/** Holds state of a session */
class PgSession(key: PgSession.Key) {
	import PgMessage.toInt4

	/*
		Unless we can capture the startup message in a session,
		we cannot determine the message boundaries reliably.

		We guess the message boundaries
		assuming they coincides with the packet boundary.

		We have observed that 'P' and 'B' messages are combined
		into a single packet on Mac OS X 10.11.2
	*/
	protected var guessMessageBoundaries = true

	protected val buf = Buffer[Byte]() // packets are buffered until a message is complete

	val messages = new ListBuffer[PgMessage]() // FIFO
	val parses = new HashMap[String, PgParse]() // the key is statementName

	/** Feeds a packet sent to the server */
	def sent(packetData: Seq[Byte]) {
		buf ++= packetData

		if (guessMessageBoundaries) {
			// see if it is a startup message
			if (buf.size >= 4) {
				val size = toInt4(buf(0), buf(1), buf(2), buf(3))
				if (size == buf.size) {
					messages += new PgMessage('?', size, buf.slice(4, size))
					buf.clear
					guessMessageBoundaries = false
				}
			}

			// see if it is a non-startup message
			if (guessMessageBoundaries) {
				if (buf.size >= 5) {
					val typ = buf(0).toChar
					val size = toInt4(buf(1), buf(2), buf(3), buf(4))
					if (1 + size == buf.size) {
						messages += new PgMessage(typ, size, buf.slice(1 + 4, 1 + size))
						buf.remove(0, 1 + size)
						guessMessageBoundaries = false
					}
				}
			}

			// TODO: we might have more than one message in a packet
		}

		// TODO: we might have started capturing in the middle of a message

		// TODO: remove a session at session close

		if (!guessMessageBoundaries) {
			while (buf.size >= 5 && 1 + toInt4(buf(1), buf(2), buf(3), buf(4)) <= buf.size) {
				val typ = buf(0).toChar
				val size = toInt4(buf(1), buf(2), buf(3), buf(4))

				if (buf.size >= 1 + size) { // size is the length of a message except the first byte
					messages += new PgMessage(typ, size, buf.slice(1 + 4, 1 + size))
					buf.remove(0, 1 + size)
				}
			}
		}
	}
}

object PgSession {
	/** Identifies a session */
	case class Key(srcAddr: InetAddress, srcPort: Int, dstAddr: InetAddress, dstPort: Int) {
		override def toString = s"${srcAddr.getHostAddress}:$srcPort -> ${dstAddr.getHostAddress}:$dstPort"
	}

	protected val sessions = HashMap[Key, PgSession]()

	def getSession(key: Key) = {
		sessions.getOrElse(key, {
			val session = new PgSession(key)
			sessions += key -> session
			session
		})
	}
}

/** Represents a message transmitted in a session */
class PgMessage(
		val typ: Char, // first byte identifies the type
		val size: Long, // next four bytes specify the length (excluding the first byte)
		val data: Seq[Byte]) {
	import PgMessage._

	var offset = 0

	def nextInt1 = {
		val value = toInt1(data(offset))
		offset += 1
		value
	}

	def nextInt2 = {
		val value = toInt2(data(offset), data(offset + 1))
		offset += 2
		value
	}

	def nextInt4 = {
		val value = toInt4(data(offset), data(offset + 1), data(offset + 2), data(offset + 3))
		offset += 4
		value
	}

	def nextBytes(size: Int) = {
		val slice = data.slice(offset, offset + size)
		offset += size
		slice
	}

	def nextBytesUntilZero = {
		var endOffset = offset
		while (endOffset < size && data(endOffset) != 0)
			endOffset += 1
		val slice = data.slice(offset, endOffset)
		offset = endOffset + 1
		slice
	}

	def nextUtf8StringUntilZero = new String(nextBytesUntilZero.toArray, "UTF-8")
}

object PgMessage {
	def toInt1(b0: Byte) = b0 & 0xff
	def toInt2(b0: Byte, b1: Byte) = (b0 & 0xff) << 8 | (b1 & 0xff)
	def toInt4(b0: Byte, b1: Byte, b2: Byte, b3: Byte) = (b0 & 0xff) << 24 | (b1 & 0xff) << 16 | (b2 & 0xff) << 8 | (b3 & 0xff)
}

case class PgParse(
		statementName: String,
		query: String,
		paramTypeOids: Seq[Int]) {
}
