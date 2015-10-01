/*
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Ryan C. Brozo
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
 *
 */

package com.ryanbrozo.spray.hawk

import org.specs2.mutable.Specification
import spray.http.{HttpHeader, GenericHttpCredentials, HttpChallenge}
import spray.http.HttpHeaders.`WWW-Authenticate`
import spray.routing.{HttpService, Directives}
import spray.testkit.Specs2RouteTest

import scala.concurrent.Future
import scala.concurrent.duration._

/**
 * Common code for HawkAuthenticator tests
 */
abstract class HawkSpec
  extends Specification
  with Specs2RouteTest
  with Directives
  with HttpService {

  object TestException extends spray.util.SingletonException

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
  val hawkUser = User("Bob", "dh37fgj492je", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", HawkHashAlgorithms.HawkSHA256)

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
  val userRetrieverThrowException: UserRetriever[User] = { _ => throw TestException }

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
   * Produces a WWW-Authenticate header
   * @param params Map of additional attributes to be added to the WWW-Authenticate header
   * @return WWW-Authenticate header
   */
  def produceWwwAuthHeader(params: Map[String, String]): List[HttpHeader] = {
    `WWW-Authenticate`(HttpChallenge("Hawk", realm, params)) :: Nil
  }

  /**
   * Produce a WWW-Authenticate header with additional error attribute
   * @param error Error string
   */
  def produceWwwAuthHeader(error: String): List[HttpHeader] = produceWwwAuthHeader(Map("error" -> error))

  def produceHawkRejection(hawkError: HawkError): HawkRejection = {
    HawkRejection(hawkError, produceWwwAuthHeader(hawkError.message))
  }

  val challengeHeaders = produceWwwAuthHeader(Map.empty[String, String])

  /**
   * Expected challenge header when request is rejected because of timestamp
   */
  val challengeHeadersWithTimestamp = produceWwwAuthHeader(Map(
    "ts" → defaultTime.toString,
    "tsm" -> "2mw1eh/qXzl0wJZ/E6XvBhRMEJN7L3j8AyMA8eItEb0=",
    "error" -> "Stale timestamp"
  ))

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

  val invalidHawkCredentialsScheme = GenericHttpCredentials("Hawkz", Map(
    "id" -> "dh37fgj492je",
    "ts" -> defaultTime.toString,
    "nonce" -> "j4h3g2",
    "ext" -> "some-app-ext-data",
    "mac" -> "6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=")
  )

}
