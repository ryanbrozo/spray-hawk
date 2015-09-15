package com.ryanbrozo.spray.hawk

import akka.actor.ActorSystem
import spray.http.HttpHeaders.RawHeader
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
  case class User(name: String, key: String, algorithm: HawkHashAlgorithms) extends HawkUser

  /**
   * Our user credentials retriever. Currently it returns 'Bob' along with his hawk credentials
   */
  val userCredentialsRetriever: UserRetriever[User] = { id =>
    Future.successful {
      if (id == "dh37fgj492je") Some(User("Bob", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", HawkSHA256))
      else None
    }
  }

  val hawkAuthenticator = HawkAuthenticator("hawk-test", userCredentialsRetriever)

  startServer(interface = "localhost", port = 8080) {
    host("test") {
      respondWithHeader(RawHeader("test", "test")) {
        path("secured") {
          authenticate(hawkAuthenticator) { user =>
            get {
              complete {
                s"Welcome to spray, ${user.name}!"
              }
            } ~
              post {
                entity(as[String]) { body =>
                  complete {
                    s"Welcome to spray, ${user.name}! Your post body was: $body"
                  }
                }
              }
          }
        }
      }
    }
  }
}
