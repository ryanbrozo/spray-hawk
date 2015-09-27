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

import spray.http.BasicHttpCredentials
import spray.http.HttpHeaders.Authorization
import spray.routing.AuthenticationFailedRejection
import spray.routing.AuthenticationFailedRejection.CredentialsRejected

/**
 * BewitSpec.scala rye on 9/25/15.
 */
class BewitSpec
  extends HawkSpec {

  "The 'authenticate(HawkAuthenticator)' directive" should {
    "properly authenticate if authentication information is encoded in a bewit" in {
      Get("http://example.com:8000/resource/1?b=1&a=2&bewit=ZGgzN2ZnajQ5MmplXDEzNTM4MzYyMzRcZ2tIRXZVU3VWVis5aEEzcnd6R2hadDM3RnlVZk5xdnNacHQzMHNoUGZFcz1cc3ByYXktaGF3aw%3D%3D") ~> {
        authenticate(hawkDoAuthTimeAgnostic) { user =>
          complete(user.name)
        }
      } ~> check {
        responseAs[String] === "Bob"
      }
    }
    "reject the request if both Hawk Authorization header and bewit parameter are present" in {
      Get("http://example.com:8000/resource/1?b=1&a=2&bewit=ZGgzN2ZnajQ5MmplXDEzNTM4MzYyMzRcZ2tIRXZVU3VWVis5aEEzcnd6R2hadDM3RnlVZk5xdnNacHQzMHNoUGZFcz1cc3ByYXktaGF3aw%3D%3D") ~>
        Authorization(hawkCredentials_GET_withPort) ~> {
        authenticate(hawkDoAuthTimeAgnostic) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === AuthenticationFailedRejection(CredentialsRejected, challengeHeaders)
      }
    }
    "properly authenticate if both bewit is and an Authentication header with scheme other than Hawk is present" in {
      Get("http://example.com:8000/resource/1?b=1&a=2&bewit=ZGgzN2ZnajQ5MmplXDEzNTM4MzYyMzRcZ2tIRXZVU3VWVis5aEEzcnd6R2hadDM3RnlVZk5xdnNacHQzMHNoUGZFcz1cc3ByYXktaGF3aw%3D%3D") ~>
        Authorization(BasicHttpCredentials("someuser", "somepassword")) ~> {
        authenticate(hawkDoAuthTimeAgnostic) { user =>
          complete(user.name)
        }
      } ~> check {
        responseAs[String] === "Bob"
      }
    }
    //TODO: More tests for bewit
  }
}
