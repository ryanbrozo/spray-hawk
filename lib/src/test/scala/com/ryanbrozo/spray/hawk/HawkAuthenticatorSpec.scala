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
import spray.http.{ContentType, GenericHttpCredentials, StatusCodes}
import spray.routing.AuthenticationFailedRejection.{CredentialsMissing, CredentialsRejected}
import spray.routing._
import spray.testkit.Specs2RouteTest

import scala.concurrent.Future
import scala.concurrent.duration._

class HawkAuthenticatorSpec
  extends Specification
  with Specs2RouteTest
  with Directives
  with HttpService {

  implicit val routeTestTimeout = RouteTestTimeout(FiniteDuration(60, SECONDS))

  /**
   * Our user model, which implements HawkUser
   */
  case class User(name: String, id: String, key: String, algorithm: HawkHashAlgorithms) extends HawkUser

  def actorRefFactory = system // connect the DSL to the test ActorSystem

  val hawkUser = User("Bob", "dh37fgj492je", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", HawkSHA256)

  /**
   * A Hawk authenticator which always does not authenticates
   */
  val hawkDontAuth = HawkAuthenticator[User]("testRealm",
  { _ =>
    Future.successful(None)
  })

  /**
   * A Hawk authenticator which always authenticates
   */
  val hawkDoAuth = HawkAuthenticator[User]("testRealm",
  { _ =>
    Future.successful(Some(hawkUser))
  })

  /**
   * Example payload
   */
  val hawkPayload = HawkPayload("Thank you for flying Hawk".getBytes("UTF-8"), "text/plain", HashAlgorithms.SHA256)

  /**
   * Hawk HTTP authentication headers, represented as Spray's [[GenericHttpCredentials]]
   */
  val hawkCredentials_GET_withPort = GenericHttpCredentials("Hawk", Map(
    "id" -> "dh37fgj492je",
    "ts" -> "1353832234",
    "nonce" -> "j4h3g2",
    "ext" -> "some-app-ext-data",
    "mac" -> "6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=")
  )

  val hawkCredentials_POST_withPort = GenericHttpCredentials("Hawk", Map(
    "id" -> "dh37fgj492je",
    "ts" -> "1353832234",
    "nonce" -> "j4h3g2",
    "ext" -> "some-app-ext-data",
    "mac" -> "56wgBMHr4oIwA/dGZspMm6Zk4rnf3aiwwVeL0VtWoGo=")
  )

  val hawkCredentials_POST_withPortWithPayload = GenericHttpCredentials("Hawk", Map(
    "id" -> "dh37fgj492je",
    "ts" -> "1353832234",
    "nonce" -> "j4h3g2",
    "hash" -> "Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=",
    "ext" -> "some-app-ext-data",
    "mac" -> "aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw=")
  )

  val hawkCredentials_GET_withoutPort = GenericHttpCredentials("Hawk", Map(
    "id" -> "dh37fgj492je",
    "ts" -> "1353832234",
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
        rejection === AuthenticationFailedRejection(CredentialsMissing, hawkDontAuth.getChallengeHeaders(null))
      }
    }
    "reject unauthenticated requests with Authorization header with an AuthorizationFailedRejection" in {
      Get("http://www.example.com:8000/abc") ~> Authorization(hawkCredentials_GET_withPort) ~> {
        authenticate(hawkDontAuth) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === AuthenticationFailedRejection(CredentialsRejected, hawkDontAuth.getChallengeHeaders(null))
      }
    }
    "reject incorrect mac in Authorization header with an AuthorizationFailedRejection" in {
      Get("http://www.example.com:8000/abc") ~> Authorization(hawkCredentials_GET_withPort) ~> {
        authenticate(hawkDoAuth) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === AuthenticationFailedRejection(CredentialsRejected, hawkDoAuth.getChallengeHeaders(null))
      }
    }
    "extract the object representing the user identity created by successful authentication" in {
      Get("http://example.com:8000/resource/1?b=1&a=2") ~> Authorization(hawkCredentials_GET_withPort) ~> {
        authenticate(hawkDoAuth) { user =>
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
        authenticate(hawkDoAuth) { user =>
          complete(user.name)
        }
      } ~> check {
        responseAs[String] === "Bob"
      }
    }
    "extract the object representing the user identity created by successful authentication " +
      "in a POST request (with payload validation)" in {
      Post("http://example.com:8000/resource/1?b=1&a=2", "Thank you for flying Hawk") ~>
        `Content-Type`(ContentType(spray.http.MediaTypes.`text/plain`)) ~>
        Authorization(hawkCredentials_POST_withPortWithPayload) ~> {
        authenticate(hawkDoAuth) { user =>
          complete(user.name)
        }
      } ~> check {
        responseAs[String] === "Bob"
      }
    }
    "properly handle exceptions thrown in its inner route" in {
      object TestException extends spray.util.SingletonException
      Get("http://example.com:8000/resource/1?b=1&a=2") ~> Authorization(hawkCredentials_GET_withPort) ~> {
        handleExceptions(ExceptionHandler.default) {
          authenticate(hawkDoAuth) { _ ⇒ throw TestException}
        }
      } ~> check {
        status === StatusCodes.InternalServerError
      }
    }
    "properly handle X-Forwarded-Proto header in case it is set" in {
      Get("https://example.com/resource/1?b=1&a=2") ~> Authorization(hawkCredentials_GET_withoutPort) ~>
        RawHeader("X-Forwarded-Proto", "http") ~> {
        authenticate(hawkDoAuth) { user =>
          complete(user.name)
        }
      } ~> check {
        responseAs[String] === "Bob"
      }
    }
  }

}
