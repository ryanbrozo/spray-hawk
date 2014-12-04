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
   * Our Hawk credentials retriever. Currently it returns the hawk credentials
   * of one user with id 'dh37fgj492je'
   */
  val hawkCredentialsRetriever = { id: String =>
    Future.successful {
      if (id == "dh37fgj492je") Some(HawkCredentials(id, "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", MacAlgorithms.HmacSHA256))
      else None
    }
  }

  /**
   * Our user entity retriever. Given an authenticated Hawk id, we
   * return a corresponding user entity.
   */
  val userCredentialsRetriever = { idOption: Option[String] =>
    Future.successful {
      idOption flatMap { id =>
        if (id == "dh37fgj492je") Some("Bob") else None
      }
    }
  }

  val hawkAuthenticator = HawkAuthenticator("hawk-test", hawkCredentialsRetriever, userCredentialsRetriever)

  startServer(interface = "localhost", port = 8080) {
    path("secured") {
      authenticate(hawkAuthenticator) { user =>
        get {
          complete {
            s"Welcome to spray, $user!"
          }
        }
      }
    }
  }
}
