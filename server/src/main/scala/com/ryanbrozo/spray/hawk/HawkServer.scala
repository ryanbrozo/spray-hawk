package com.ryanbrozo.spray.hawk

import akka.actor.ActorSystem
import spray.routing.SimpleRoutingApp

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

/**
 * Spray server that demonstrates Hawk authentication. You can access it via http://localhost:8080/secured
 *
 */
object HawkServer extends App
  with SimpleRoutingApp
  with HawkRouteDirectives {
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
      if (id == "dh37fgj492je") Some(User("Bob", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", HawkHashAlgorithms.HawkSHA256))
      else None
    }
  }

  val hawkAuthenticator = HawkAuthenticator("hawk-test", userCredentialsRetriever)

  startServer(interface = "localhost", port = 8080) {
    // Add Server-Authorization header for response payload validation
    withHawkServerAuthHeader(userCredentialsRetriever) {
      path("secured") {
        handleRejections(hawkRejectionHandler) {
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
