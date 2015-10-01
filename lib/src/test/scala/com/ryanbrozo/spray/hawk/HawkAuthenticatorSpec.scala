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

import com.ryanbrozo.spray.hawk.HawkError._
import spray.http.HttpHeaders._
import spray.http._
import spray.routing._

class HawkAuthenticatorSpec
  extends HawkSpec {

  "The 'authenticate(HawkAuthenticator)' directive" should {
    "reject requests without Authorization header with an AuthenticationRequiredRejection" in {
      Get() ~> {
        authenticate(hawkDontAuth) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === produceHawkRejection(CredentialsMissingError)
      }
    }
    "reject unauthenticated requests with Authorization header with an AuthorizationFailedRejection" in {
      Get("http://www.example.com:8000/abc") ~> Authorization(hawkCredentials_GET_withPort) ~>
        authenticate(hawkDontAuth) { user =>
          complete(user.name)
        } ~> check {
        rejection === produceHawkRejection(InvalidCredentialsError)
      }
    }
    "reject incorrect mac in Authorization header with an AuthorizationFailedRejection" in {
      Get("http://www.example.com:8000/abc") ~> Authorization(hawkCredentials_GET_withPort) ~> {
        authenticate(hawkDoAuthTimeAgnostic) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === produceHawkRejection(InvalidMacError)
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

    "reject unauthenticated requests with invalid Authorization header scheme with an AuthorizationFailedRejection" in {
      Get("http://example.com:8000/resource/1?b=1&a=2") ~> Authorization(invalidHawkCredentialsScheme) ~> {
        authenticate(hawkDoAuthTimeAgnostic) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === produceHawkRejection(CredentialsMissingError)
      }
    }

    "properly handle exceptions thrown in its inner route" in {
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
        rejection === produceHawkRejection(UserRetrievalError(TestException))
      }
    }
  }
}
