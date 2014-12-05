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
import spray.http.HttpHeaders.{Authorization, RawHeader}
import spray.http.{GenericHttpCredentials, StatusCodes}
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

  case class User(name: String, id: String, key: String, algorithm: MacAlgorithms.Value) extends HawkUser

  def actorRefFactory = system // connect the DSL to the test ActorSystem

  val hawkUser = User("Bob", "dh37fgj492je", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", MacAlgorithms.HmacSHA256)

  val hawkDontAuth = HawkAuthenticator[User]("testRealm",
  { _ =>
    Future.successful(None)
  })

  val hawkDoAuth = HawkAuthenticator[User]("testRealm",
  { _ =>
    Future.successful(Some(hawkUser))
  })

  val hawkCredentialsWithPort = GenericHttpCredentials("Hawk", Map(
    "id" -> "dh37fgj492je", "ts" -> "1353832234", "nonce" -> "j4h3g2", "ext" -> "some-app-ext-data", "mac" -> "6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="))

  val hawkCredentialsWithoutPort = GenericHttpCredentials("Hawk", Map(
    "id" -> "dh37fgj492je", "ts" -> "1353832234", "nonce" -> "j4h3g2", "ext" -> "some-app-ext-data", "mac" -> "fmzTiKheFFqAeWWoVIt6vIflByB9X8TeYQjCdvq9bf4="))

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
      Get("http://www.example.com:8000/abc") ~> Authorization(hawkCredentialsWithPort) ~> {
        authenticate(hawkDontAuth) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === AuthenticationFailedRejection(CredentialsRejected, hawkDontAuth.getChallengeHeaders(null))
      }
    }
    "reject incorrect mac in Authorization header with an AuthorizationFailedRejection" in {
      Get("http://www.example.com:8000/abc") ~> Authorization(hawkCredentialsWithPort) ~> {
        authenticate(hawkDoAuth) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === AuthenticationFailedRejection(CredentialsRejected, hawkDoAuth.getChallengeHeaders(null))
      }
    }
    "extract the object representing the user identity created by successful authentication" in {
      Get("http://example.com:8000/resource/1?b=1&a=2") ~> Authorization(hawkCredentialsWithPort) ~> {
        authenticate(hawkDoAuth) { user =>
          complete(user.name)
        }
      } ~> check {
        entityAs[String] === "Bob"
      }
    }
    "properly handle exceptions thrown in its inner route" in {
      object TestException extends spray.util.SingletonException
      Get("http://example.com:8000/resource/1?b=1&a=2") ~> Authorization(hawkCredentialsWithPort) ~> {
        handleExceptions(ExceptionHandler.default) {
          authenticate(hawkDoAuth) { _ ⇒ throw TestException}
        }
      } ~> check {
        status === StatusCodes.InternalServerError
      }
    }
    "properly handle X-Forwarded-Proto header in case it is set" in {
      Get("https://example.com/resource/1?b=1&a=2") ~> Authorization(hawkCredentialsWithoutPort) ~>
        RawHeader("X-Forwarded-Proto", "http") ~> {
        authenticate(hawkDoAuth) { user =>
          complete(user.name)
        }
      } ~> check {
        entityAs[String] === "Bob"
      }
    }
  }

}
