package com.ryanbrozo.spray.hawk

import akka.actor.ActorSystem
import spray.routing.SimpleRoutingApp

/**
 * HawkDemoApp.scala
 *
 * Created by rye on 12/1/14 1:27 PM.
 */
object HawkServer extends App with SimpleRoutingApp {
  implicit val system = ActorSystem("my-system")

  startServer(interface = "localhost", port = 8080) {
    path("hello") {
      get {
        complete {
          <h1>Say hello to spray</h1>
        }
      }
    }
  }
}
