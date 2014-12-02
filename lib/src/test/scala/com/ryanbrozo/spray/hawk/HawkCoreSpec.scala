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

import org.specs2.mutable._
import HawkParameters._

/**
 * HawkCoreSpec.scala
 *
 * Created by rye on 12/1/14 6:23 PM.
 */
class HawkCoreSpec extends Specification {

  val credentials = HawkCredentials("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",Algorithms.HmacSHA256)

  "Hawk algorithm implementation" should {
    "return a valid normalized string" in {
      val options = Map(
        Method -> "GET",
        Uri -> "/resource/something",
        Host -> "example.com",
        Port -> "8080",
        Ts -> "1357747017",
        Nonce -> "k3k4j5"
      )
      Hawk(credentials, options).normalized must beEqualTo("hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\n\n")
    }

    "return a valid normalized string (ext)" in {
      val options = Map(
        Method -> "GET",
        Uri -> "/resource/something",
        Host -> "example.com",
        Port -> "8080",
        Ts -> "1357747017",
        Nonce -> "k3k4j5",
        Ext -> "this is some app data"
      )
      Hawk(credentials, options).normalized must beEqualTo("hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\nthis is some app data\n")
    }

    "return a valid normalized string (payload + ext)" in {
      val options = Map(
        Method -> "GET",
        Uri -> "/resource/something",
        Host -> "example.com",
        Port -> "8080",
        Ts -> "1357747017",
        Nonce -> "k3k4j5",
        Ext -> "this is some app data",
        Hash -> "U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE="
      )
      Hawk(credentials, options).normalized must beEqualTo("hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\nU4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=\nthis is some app data\n")
    }

    "produce the correct MAC in given example from Hawk readme" in {
      val options = Map(
        Method -> "GET",
        Uri -> "/resource/1?b=1&a=2",
        Host -> "example.com",
        Port -> "8000",
        Ts -> "1353832234",
        Nonce -> "j4h3g2",
        Ext -> "some-app-ext-data"
      )
      Hawk(credentials, options).mac must beEqualTo("6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=")
    }

    "produce the correct MAC in given example with payload validation from Hawk readme" in {
      val options = Map(
        Method -> "POST",
        Uri -> "/resource/1?b=1&a=2",
        Host -> "example.com",
        Port -> "8000",
        Ts -> "1353832234",
        Nonce -> "j4h3g2",
        Ext -> "some-app-ext-data",
        Hash -> "Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY="
      )
      Hawk(credentials, options).mac must beEqualTo("aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw=")
    }
  }
}
