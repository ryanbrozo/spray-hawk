/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Ryan C. Brozo
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.ryanbrozo.spray.hawk

import org.specs2.mutable.Specification
import spray.http.HttpHeaders._
import spray.http.{HttpChallenge, ContentType, GenericHttpCredentials, StatusCodes}
import spray.routing.AuthenticationFailedRejection.{CredentialsMissing, CredentialsRejected}
import spray.routing._
import spray.testkit.Specs2RouteTest

import scala.compat.Platform
import scala.concurrent.Future
import scala.concurrent.duration._

class HawkAuthenticatorSpec
  extends Specification
  with Specs2RouteTest
  with Directives
  with HttpService
  with HawkRouteDirectives {

  implicit val routeTestTimeout = RouteTestTimeout(FiniteDuration(60, SECONDS))

  /**
   * Our user model, which implements HawkUser
   */
  case class User(name: String, id: String, key: String, algorithm: HawkHashAlgorithms) extends HawkUser

  /**
   * Constant moment in time. Used to isolate time-independent features of the protocol 
   */
  val defaultTime = 1353832234L
  
  /**
   * Constant time to isolate tests that are agnostic to time skew 
   * @return Constant moment in time (1353832234L)
   */
  def defaultTimeGenerator: TimeStamp = defaultTime

  /**
   * Default actor system to be used by tests 
   * @return
   */
  def actorRefFactory = system

  /**
   * Hawk user to be used in tests
   */
  val hawkUser = User("Bob", "dh37fgj492je", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", HawkSHA256)

  /**
   * Test Realm 
   */
  val realm = "testRealm"

  /**
   * A UserRetriever that always does not authenticate
   */
  val userRetrieverDontAuth: UserRetriever[User] = { _ => Future.successful(None) }

  /**
   * A UserRetriever that always authenticates
   */
  val userRetrieverDoAuth: UserRetriever[User] = { _ => Future.successful(Some(hawkUser)) }

  /**
   * A UserRetriever that always throws an exception
   */
  val userRetrieverThrowException: UserRetriever[User] = { _ => throw new Exception("Cannot retrieve a user") }
  
  /**
   * A Hawk authenticator which always does not authenticates. Timestamp generator is not relevant since this 
   * authenticator always fails
   */
  val hawkDontAuth = HawkAuthenticator[User](realm, userRetrieverDontAuth)

  /**
   * A Hawk authenticator which always authenticates but does not depend on the current time
   */
  val hawkDoAuthTimeAgnostic = HawkAuthenticator[User](defaultTimeGenerator _)(realm, userRetrieverDoAuth)

  /**
   * A Hawk authenticator which throws an exception
   */
  val hawkDoAuthWithException = HawkAuthenticator[User](defaultTimeGenerator _)(realm, userRetrieverThrowException)

  /**
   * A Hawk authenticator which always authenticates but checks for validity of nonces
   */
  val hawkDoAuthTimeAgnosticValidatesNonce = HawkAuthenticator[User](
    defaultTimeGenerator _, Util.cachingNonceValidator _)(realm,
  { _ =>
    Future.successful(Some(hawkUser))
  })

  /**
   * Expected challenge header when requesst is rejected
   */
  val challengeHeaders = `WWW-Authenticate`(HttpChallenge("Hawk", realm, Map.empty)) :: Nil


  /**
   * Expected challenge header when request is rejected because of timestamp
   */
  val challengeHeadersWithTimestamp = `WWW-Authenticate`(HttpChallenge("Hawk", realm, Map(
    "ts" → defaultTime.toString,
    "tsm" -> "2mw1eh/qXzl0wJZ/E6XvBhRMEJN7L3j8AyMA8eItEb0=",
    "error" -> "Stale timestamp"
  ))) :: Nil

  /**
   * Example payload
   */
  val hawkPayload = HawkPayload("Thank you for flying Hawk".getBytes("UTF-8"), "text/plain", HashAlgorithms.SHA256)


  /**
   * Hawk HTTP authentication headers, represented as Spray's [[GenericHttpCredentials]]
   */
  val hawkCredentials_GET_withPort = GenericHttpCredentials("Hawk", Map(
    "id" -> "dh37fgj492je",
    "ts" -> defaultTime.toString,
    "nonce" -> "j4h3g2",
    "ext" -> "some-app-ext-data",
    "mac" -> "6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=")
  )

  val hawkCredentials_GET_withPort_timestamp_left_of_timeframe = GenericHttpCredentials("Hawk", Map(
    "id" -> "dh37fgj492je",
    "ts" -> (defaultTime - 61000).toString, // 1353832234 - 61 secs (61000 millis)
    "nonce" -> "j4h3g2",
    "ext" -> "some-app-ext-data",
    "mac" -> "TsmGb+yKA6tXvQsBOGobUoBJoy8U7cHXJm/ZybG2Xuc=")
  )

  val hawkCredentials_GET_withPort_timestamp_right_of_timeframe = GenericHttpCredentials("Hawk", Map(
    "id" -> "dh37fgj492je",
    "ts" -> (defaultTime + 61000).toString, // 1353832234 + 61 secs (61000 millis)
    "nonce" -> "j4h3g2",
    "ext" -> "some-app-ext-data",
    "mac" -> "AB5kPX4S2RSWIrYgw4R5IMVeLco3y2nFBZfMyZd1Pfc=")
  )

  val hawkCredentials_POST_withPort = GenericHttpCredentials("Hawk", Map(
    "id" -> "dh37fgj492je",
    "ts" -> defaultTime.toString,
    "nonce" -> "j4h3g2",
    "ext" -> "some-app-ext-data",
    "mac" -> "56wgBMHr4oIwA/dGZspMm6Zk4rnf3aiwwVeL0VtWoGo=")
  )

  val hawkCredentials_POST_withPortWithPayload = GenericHttpCredentials("Hawk", Map(
    "id" -> "dh37fgj492je",
    "ts" -> defaultTime.toString,
    "nonce" -> "j4h3g2",
    "hash" -> "Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=",
    "ext" -> "some-app-ext-data",
    "mac" -> "aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw=")
  )

  val hawkCredentials_GET_withoutPort = GenericHttpCredentials("Hawk", Map(
    "id" -> "dh37fgj492je",
    "ts" -> defaultTime.toString,
    "nonce" -> "j4h3g2",
    "ext" -> "some-app-ext-data",
    "mac" -> "fmzTiKheFFqAeWWoVIt6vIflByB9X8TeYQjCdvq9bf4=")
  )




  "the 'authenticate(HawkAuthenticator)' directive" should {
    "reject requests without Authorization header with an AuthenticationRequiredRejection" in {
      Get() ~> {
        authenticate(hawkDontAuth) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === AuthenticationFailedRejection(CredentialsMissing, challengeHeaders)
      }
    }
    "reject unauthenticated requests with Authorization header with an AuthorizationFailedRejection" in {
      Get("http://www.example.com:8000/abc") ~> Authorization(hawkCredentials_GET_withPort) ~>
        authenticate(hawkDontAuth) { user =>
          complete(user.name)
        } ~> check {
        rejection === AuthenticationFailedRejection(CredentialsRejected, challengeHeaders)
      }
    }
    "reject incorrect mac in Authorization header with an AuthorizationFailedRejection" in {
      Get("http://www.example.com:8000/abc") ~> Authorization(hawkCredentials_GET_withPort) ~> {
        authenticate(hawkDoAuthTimeAgnostic) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === AuthenticationFailedRejection(CredentialsRejected, challengeHeaders)
      }
    }
    "extract the object representing the user identity created by successful authentication" in {
      Get("http://example.com:8000/resource/1?b=1&a=2") ~> Authorization(hawkCredentials_GET_withPort) ~> {
        authenticate(hawkDoAuthTimeAgnostic) { user =>
          complete(user.name)
        }
      } ~> check {
        responseAs[String] === "Bob"
      }
    }
    "extract the object representing the user identity created by successful authentication " +
      "in a POST request (without payload validation)" in {
      Post("http://example.com:8000/resource/1?b=1&a=2", "Thank you for flying Hawk") ~>
        `Content-Type`(ContentType(spray.http.MediaTypes.`text/plain`)) ~>
        Authorization(hawkCredentials_POST_withPort) ~> {
        authenticate(hawkDoAuthTimeAgnostic) { user =>
          complete(user.name)
        }
      } ~> check {
        responseAs[String] === "Bob"
      }
    }
    "reject unauthenticated requests having a validated MAC but with wrong payload hash" in {
      Post("http://example.com:8000/resource/1?b=1&a=2", "Thank you for flying Hawkz") ~>
        `Content-Type`(ContentType(spray.http.MediaTypes.`text/plain`)) ~>
        Authorization(hawkCredentials_POST_withPortWithPayload) ~> {
        authenticate(hawkDoAuthTimeAgnostic) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === AuthenticationFailedRejection(CredentialsRejected, challengeHeaders)
      }
    }
    "reject requests with client timestamps less than the allowable server timeframe" in {
      Get("http://www.example.com:8000/abc") ~> Authorization(hawkCredentials_GET_withPort_timestamp_left_of_timeframe) ~> {
        authenticate(hawkDoAuthTimeAgnostic) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === AuthenticationFailedRejection(CredentialsRejected, challengeHeadersWithTimestamp)
      }
    }
    "reject requests with client timestamps more than the allowable server timeframe" in {
      Get("http://www.example.com:8000/abc") ~> Authorization(hawkCredentials_GET_withPort_timestamp_right_of_timeframe) ~> {
        authenticate(hawkDoAuthTimeAgnostic) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === AuthenticationFailedRejection(CredentialsRejected, challengeHeadersWithTimestamp)
      }
    }
    "extract the object representing the user identity created by successful authentication in a POST request (with payload validation)" in {
      Post("http://example.com:8000/resource/1?b=1&a=2", "Thank you for flying Hawk") ~>
        `Content-Type`(ContentType(spray.http.MediaTypes.`text/plain`)) ~>
        Authorization(hawkCredentials_POST_withPortWithPayload) ~> {
        authenticate(hawkDoAuthTimeAgnostic) { user =>
          complete(user.name)
        }
      } ~> check {
        responseAs[String] === "Bob"
        header("Server-Authorization") === None
      }
    }
    "produce a valid Server-Authorization header" in {
      Post("http://example.com:8000/resource/1?b=1&a=2", "Thank you for flying Hawk") ~>
        `Content-Type`(ContentType(spray.http.MediaTypes.`text/plain`)) ~>
        Authorization(hawkCredentials_POST_withPortWithPayload) ~> {
        withHawkServerAuthHeader(userRetrieverDoAuth) {
          authenticate(hawkDoAuthTimeAgnostic) { user =>
            complete(user.name)
          }
        }
      } ~> check {
        responseAs[String] === "Bob"
        header("Server-Authorization") ===
          RawHeader("Server-Authorization", """Hawk mac="MZ9KSUZgulMSfu1EGCIULjCbqor09PfF83fXKDLE+bI=", hash="adQztfXWuBrabtDCkK9innCGU4dCILx6ecq+b6JjUbc=", ext="server"""")
      }
    }

    "properly handle exceptions thrown in its inner route" in {
      object TestException extends spray.util.SingletonException
      Get("http://example.com:8000/resource/1?b=1&a=2") ~> Authorization(hawkCredentials_GET_withPort) ~> {
        handleExceptions(ExceptionHandler.default) {
          authenticate(hawkDoAuthTimeAgnostic) { _ => throw TestException}
        }
      } ~> check {
        status === StatusCodes.InternalServerError
      }
    }
    "properly handle X-Forwarded-Proto header in case it is set" in {
      Get("https://example.com/resource/1?b=1&a=2") ~> Authorization(hawkCredentials_GET_withoutPort) ~>
        RawHeader("X-Forwarded-Proto", "http") ~> {
        authenticate(hawkDoAuthTimeAgnostic) { user =>
          complete(user.name)
        }
      } ~> check {
        responseAs[String] === "Bob"
      }
    }
    "reject requests when an exception is encountered while retrieving a user" in {
      Get("http://example.com:8000/resource/1?b=1&a=2") ~> Authorization(hawkCredentials_GET_withPort) ~> {
        authenticate(hawkDoAuthWithException) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === AuthenticationFailedRejection(CredentialsRejected, challengeHeaders)
      }
    }
    "reject requests when nonce is non-unique" in {
      Get("http://example.com:8000/resource/1?b=1&a=2") ~> Authorization(hawkCredentials_GET_withPort) ~> {
        authenticate(hawkDoAuthTimeAgnosticValidatesNonce) { user =>
          complete(user.name)
        }
      } ~> check {
        responseAs[String] === "Bob"
      }
      Get("http://example.com:8000/resource/1?b=1&a=2") ~> Authorization(hawkCredentials_GET_withPort) ~> {
        authenticate(hawkDoAuthTimeAgnosticValidatesNonce) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === AuthenticationFailedRejection(CredentialsRejected, challengeHeaders)
      }
    }
  }

}
