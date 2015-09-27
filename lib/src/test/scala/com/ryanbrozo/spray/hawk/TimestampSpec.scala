/*
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

import spray.http.HttpHeaders.Authorization
import spray.routing.AuthenticationFailedRejection
import spray.routing.AuthenticationFailedRejection.CredentialsRejected

/**
 * TimestampSpec.scala
 *
 * Created by rye on 9/27/15.
 */
class TimestampSpec
  extends HawkSpec {

  "The 'authenticate(HawkAuthenticator)' directive" should {
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
  }
}
