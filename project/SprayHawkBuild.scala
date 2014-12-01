import sbt._
import Keys._

object BuildDependencies {
  val SPRAY_VERSION = "1.3.1"

  val sprayRouting = "io.spray"             %% "spray-routing"  % SPRAY_VERSION
  val sprayCan = "io.spray"                 %% "spray-can"      % SPRAY_VERSION
  val sprayIo = "io.spray"                  %% "spray-io"       % SPRAY_VERSION
  val scalaXml = "org.scala-lang.modules"   %% "scala-xml"      % "1.0.2"
  val akkaActor = "com.typesafe.akka"       %% "akka-actor"     % "2.3.6"
}

object BuildSettings {
  import BuildDependencies._

  val SCALA_VERSION = "2.11.4"
  val APP_VERSION = "0.1"

  lazy val commonSettings = Seq(
    scalaVersion        := SCALA_VERSION,
    version             := APP_VERSION,
    resolvers           ++= Seq(
      "Spray Repository"      at "http://repo.spray.io",
      "Typesafe Repository"   at "http://repo.typesafe.com/typesafe/releases/"
    )
  )

  lazy val libSettings = Seq(
    libraryDependencies ++= Seq(
      sprayRouting
    )
  )

  lazy val serverSettings = Seq(
    libraryDependencies ++= Seq(
      sprayRouting,
      sprayCan,
      sprayIo,
      akkaActor,
      scalaXml
    )
  )
}


object SprayHawkBuild extends Build {
  import BuildSettings._

  lazy val main = Project(
    id = "spray-hawk",
    base = file(".")
  )
    .aggregate(client, server, lib)
    .settings(commonSettings: _*)

  lazy val lib = Project(
    id = "spray-hawk-lib",
    base = file("lib")
  )
    .settings(commonSettings: _*)
    .settings(libSettings: _*)

  lazy val server = Project(
    id = "spray-hawk-server",
    base = file("server")
  )
    .dependsOn(lib)
    .settings(commonSettings: _*)
    .settings(serverSettings: _*)

  lazy val client = Project(
    id = "spray-hawk-client",
    base = file("client")
  )
    .dependsOn(lib)
    .settings(commonSettings: _*)
    .settings(commonSettings: _*)
}