package jp.ken1ma.pg_select_pcap

import java.util.Properties
import java.sql._

import org.scalatest.FunSuite

class NoParamsTest extends FunSuite {
	val host = "192.168.1.11"
	val db = "pcap_test_db"
	val user = "pcap_test_user"
	val password = "pcap_test_user"

	var con: Connection = _

	override def withFixture(test: NoArgTest) = {
		val props = new Properties
		props.setProperty("user", user);
		props.setProperty("password", password);
		con = DriverManager.getConnection(s"jdbc:postgresql://$host/$db", props)
		def execute(sql: String) {
			val s = con.createStatement
			try {
				s.execute(sql)
			} finally {
				s.close
			}
		}
		try {
			execute("CREATE TABLE t0(id integer, name text)")
			super.withFixture(test)
		} finally {
			execute("DROP TABLE T0");
			con.close
		}
	}

/*
	test("Statement.execute") {
		val s = con.createStatement
		try {
			s.execute("select * from T0")
		} finally {
			s.close
		}
	}

	test("PreparedStatement.executeQuery") {
		val ps = con.prepareStatement("select * from T0")
		try {
			ps.executeQuery
		} finally {
			ps.close
		}
	}
*/

	test("PreparedStatement.executeQuery with parameters") {
		val ps = con.prepareStatement("select * from T0 where (id = ? or id = ?) and (name = ? or name = ?)")
		ps.setInt(1, 3)
		ps.setInt(2, 1025)
		ps.setString(3, "foo")
		ps.setString(4, "bar")
		try {
			ps.executeQuery
		} finally {
			ps.close
		}
	}
}
