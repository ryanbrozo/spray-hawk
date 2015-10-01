/*
 *
 *  * The MIT License (MIT)
 *  *
 *  * Copyright (c) 2015 Ryan C. Brozo
 *  *
 *  * Permission is hereby granted, free of charge, to any person obtaining a copy
 *  * of this software and associated documentation files (the "Software"), to deal
 *  * in the Software without restriction, including without limitation the rights
 *  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  * copies of the Software, and to permit persons to whom the Software is
 *  * furnished to do so, subject to the following conditions:
 *  *
 *  * The above copyright notice and this permission notice shall be included in all
 *  * copies or substantial portions of the Software.
 *  *
 *  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  * SOFTWARE.
 *
 */

package com.ryanbrozo.spray.hawk

import com.ryanbrozo.spray.hawk.HawkError._
import spray.http.ContentType
import spray.http.HttpHeaders.{Authorization, `Content-Type`}

/**
 * PayloadValidationSpec.scala
 *
 * Created by rye on 9/27/15.
 */
class PayloadValidationSpec
  extends HawkSpec {

  "The 'authenticate(HawkAuthenticator)' directive" should {
    "reject unauthenticated requests having a validated MAC but with wrong payload hash" in {
      Post("http://example.com:8000/resource/1?b=1&a=2", "Thank you for flying Hawkz") ~>
        `Content-Type`(ContentType(spray.http.MediaTypes.`text/plain`)) ~>
        Authorization(hawkCredentials_POST_withPortWithPayload) ~> {
        authenticate(hawkDoAuthTimeAgnostic) { user =>
          complete(user.name)
        }
      } ~> check {
        rejection === produceHawkRejection(InvalidPayloadHashError)
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
  }
}
