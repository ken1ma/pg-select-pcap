package jp.ken1ma.pg_select_pcap
package util

object HexDump {
	def toString(data: Array[Byte]) = {
		val sb = new StringBuilder

		var i = 0
		data.foreach { bt =>
			if (i % 16 == 0)
				sb ++= f"$i%04x  "
			else
				sb += ' '

			sb ++= f"$bt%02x"

			if (i % 16 == 15) {
				sb ++= "  "
				for (j <- i - 15 to i)
					sb += (if (data(j) >= 0x20 && data(j) <= 0x7e) data(j).toChar else '.')
				sb += '\n'
			}

			i += 1
		}


		if (data.size % 16 > 0) {
			for (j <- data.size % 16 until 16)
				sb ++= "   "
			sb ++= "  "
			for (j <- data.size / 16 * 16 until data.size)
				sb += (if (data(j) >= 0x20 && data(j) <= 0x7e) data(j).toChar else '.')
			sb += '\n'
		}

		sb.toString
	}
}
