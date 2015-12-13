package jp.ken1ma.pg_select_pcap
package util

object HexDump {
	def toString(data: Array[Byte]) = {
		val sb = new StringBuilder

		var i = 0
		data.foreach { bt =>
			// line header
			if (i % 16 == 0)
				sb ++= f"$i%04x  "
			else
				sb += ' '

			// byte value
			sb ++= f"$bt%02x"

			// line footer
			if (i % 16 == 15) {
				sb ++= "  "
				for (j <- i - 15 to i)
					sb += toChar(data(j))
				sb += '\n'
			}

			i += 1
		}

		// line footer of the last line
		if (data.size % 16 > 0) {
			for (j <- data.size % 16 until 16)
				sb ++= "   "
			sb ++= "  "
			for (j <- data.size / 16 * 16 until data.size)
				sb += toChar(data(j))
			sb += '\n'
		}

		sb.toString
	}

	def toChar(bt: Byte) = if (bt >= 0x20 && bt <= 0x7e) bt.toChar else '.'
}
