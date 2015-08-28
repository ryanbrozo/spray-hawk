import sbt._
import Keys._

object BuildDependencies {
  val SPRAY_VERSION = "1.3.1"

  val sprayRouting =    "io.spray"                      %% "spray-routing"      % SPRAY_VERSION
  val sprayCan =        "io.spray"                      %% "spray-can"          % SPRAY_VERSION
  val sprayIo =         "io.spray"                      %% "spray-io"           % SPRAY_VERSION
  val sprayClient =     "io.spray"                      %% "spray-client"       % SPRAY_VERSION
  val sprayHttp =       "io.spray"                      %% "spray-http"         % SPRAY_VERSION
  val sprayHttpX =      "io.spray"                      %% "spray-httpx"        % SPRAY_VERSION
  val sprayUtil =       "io.spray"                      %% "spray-util"         % SPRAY_VERSION
  val sprayCaching =    "io.spray"                      %% "spray-caching"      % SPRAY_VERSION
  val sprayTestKit =    "io.spray"                      %% "spray-testkit"      % SPRAY_VERSION   % "test"
  val scalaLogging =    "com.typesafe.scala-logging"    %% "scala-logging"      % "3.1.0"
  val logback =         "ch.qos.logback"                %  "logback-classic"    % "1.0.13"
  val scalaXml =        "org.scala-lang.modules"        %% "scala-xml"          % "1.0.2"
  val scalaz =          "org.scalaz"                    %% "scalaz-core"        % "7.1.3"
  val akkaActor =       "com.typesafe.akka"             %% "akka-actor"         % "2.3.6"
  val specs2 =          "org.specs2"                    %% "specs2-core"        % "2.4.13"        % "test"
}

object BuildSettings {
  import BuildDependencies._

  val SCALA_VERSION = "2.11.4"
  val APP_VERSION = "0.3"

  lazy val commonSettings = Seq(
    organization        := "com.ryanbrozo",
    scalaVersion        := SCALA_VERSION,
    version             := APP_VERSION,
    resolvers           ++= Seq(
      "Spray Repository"      at "http://repo.spray.io",
      "Typesafe Repository"   at "http://repo.typesafe.com/typesafe/releases/"
    )
  )

  lazy val libSettings = Seq(
    libraryDependencies ++= Seq(
      scalaz,
      sprayRouting,
      sprayCaching,
      akkaActor,
      scalaLogging,
      logback,
      sprayTestKit,
      specs2
    ),
    autoAPIMappings := true,
    scalacOptions in Test ++= Seq("-Yrangepos", "-deprecation")
  )

  lazy val serverSettings = Seq(
    libraryDependencies ++= Seq(
      sprayRouting,
      sprayCan,
      sprayIo,
      scalaLogging,
      logback,
      akkaActor,
      scalaXml
    )
  )

  lazy val clientSettings = Seq(
    libraryDependencies ++= Seq(
      sprayClient,
      sprayCan,
      sprayHttp,
      sprayHttpX,
      sprayUtil,
      akkaActor
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
    .settings(clientSettings: _*)
}