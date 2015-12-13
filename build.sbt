lazy val root = (project in file(".")).
  settings(
    name := "pg-select-pcap",
    version := "0.1",
    scalaVersion := "2.11.7",
    libraryDependencies ++= Seq(
      "org.pcap4j" % "pcap4j-core" % "1.6.1",
      "org.pcap4j" % "pcap4j-packetfactory-static" % "1.6.1",
      //"org.pcap4j" % "pcap4j-packetfactory-propertiesbased" % "1.6.1",
      "ch.qos.logback" % "logback-classic" % "1.1.3"
    )
  )
