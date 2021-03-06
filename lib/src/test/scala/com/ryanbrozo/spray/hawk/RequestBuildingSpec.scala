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
import spray.http.HttpHeaders.RawHeader
import spray.http._

/**
 * RequestBuildingSpec.scala * Created by rye on 12/4/14 6:32 PM.
 */
class RequestBuildingSpec extends Specification with HawkRequestBuilding {

  val hawkCreds = HawkCredentials("dh37fgj492je", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", HawkHashAlgorithms.HawkSHA256)

  "The HawkRequestBuilding trait" should {
    "be able to add the correct Hawk Authorization header" in {
      Get("http://example.com:8000/resource/1?b=1&a=2") ~> addHawkCredentials(() => 1353832234, () => "j4h3g2", "some-app-ext-data")(hawkCreds, withPayloadValidation = false) ===
        HttpRequest(uri = Uri("http://example.com:8000/resource/1?b=1&a=2"),
          headers = List(RawHeader("Authorization", """Hawk id="dh37fgj492je", ts="1353832234", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=", nonce="j4h3g2", ext="some-app-ext-data"""")))
    }

    "be able to add the correct Hawk Authorization header (with payload validation)" in {
      Post("http://example.com:8000/resource/1?b=1&a=2", "Thank you for flying Hawk") ~> addHawkCredentials(() => 1353832234, () => "j4h3g2", "some-app-ext-data")(hawkCreds, withPayloadValidation = true) ===
        HttpRequest(uri = Uri("http://example.com:8000/resource/1?b=1&a=2"),
          headers = List(RawHeader("Authorization", """Hawk id="dh37fgj492je", ts="1353832234", mac="aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw=", nonce="j4h3g2", hash="Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=", ext="some-app-ext-data"""")),
          method = HttpMethods.POST,
          entity = HttpEntity(ContentTypes.`text/plain(UTF-8)`, "Thank you for flying Hawk")
        )
    }
  }

}
