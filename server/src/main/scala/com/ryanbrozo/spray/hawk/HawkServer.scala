package com.ryanbrozo.spray.hawk

import akka.actor.ActorSystem
import spray.routing.SimpleRoutingApp

import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global

/**
 * Spray server that demonstrates Hawk authentication. You can access it via http://localhost:8080/secured
 *
 */
object HawkServer extends App with SimpleRoutingApp {
  implicit val system = ActorSystem("my-system")

  /**
   * Our User model. This needs to extend the HawkUser trait for our UserCredentialsRetriever
   * to work
   */
  case class User(name: String, id: String, key: String, algorithm: MacAlgorithms.Value) extends HawkUser

  /**
   * Our user credentials retriever. Currently it returns 'Bob' along with his hawk credentials
   */
  val userCredentialsRetriever = { id: String =>
    Future.successful {
      if (id == "dh37fgj492je") Some(User("Bob", id, "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", MacAlgorithms.HmacSHA256))
      else None
    }
  }

  val hawkAuthenticator = HawkAuthenticator("hawk-test", userCredentialsRetriever)

  startServer(interface = "localhost", port = 8080) {
    path("secured") {
      authenticate(hawkAuthenticator) { user =>
        get {
          complete {
            s"Welcome to spray, ${user.name}!"
          }
        }
      }
    }
  }
}
