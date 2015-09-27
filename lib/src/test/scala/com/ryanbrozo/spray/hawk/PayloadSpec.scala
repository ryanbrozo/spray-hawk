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

/**
 * PayloadSpecla
 *
 * Created by rye on 12/2/14.
 */
class PayloadSpec extends Specification {

  "Hawk payload implementation" should {
    "produce the correct normalized string in given example with payload validation from Hawk readme" in {
      HawkPayload("Thank you for flying Hawk".getBytes("UTF-8"), "text/plain", HashAlgorithms.SHA256)
        ._normalized must beEqualTo(
        """hawk.1.payload
          |text/plain
          |Thank you for flying Hawk
          |""".stripMargin)
    }
    "produce the correct MAC in given example with payload validation from Hawk readme" in {
      HawkPayload("Thank you for flying Hawk".getBytes("UTF-8"), "text/plain", HashAlgorithms.SHA256)
        .hash must beEqualTo("Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=")
    }
  }
}
