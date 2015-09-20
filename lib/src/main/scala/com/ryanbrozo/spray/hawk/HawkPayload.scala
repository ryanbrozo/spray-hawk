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

import java.security.MessageDigest

import org.parboiled.common.Base64

/**
 * Class that represents a payload that is used for computing a Hawk header
 * with payload validation
 *
 * @param payload Actual payload
 * @param contentType Content-Type of the payload
 * @param algorithm Hashing algorithm to use
 */
private[hawk] case class HawkPayload(payload: Array[Byte], contentType: String, algorithm: HashAlgorithms.Value) {

  /**
   * Normalized request string
   */
  private[hawk] lazy val normalized: String = {
    s"""${HEADER_NAME.toLowerCase}.$HEADER_VERSION.payload
     |${contentType.toLowerCase}
     |${new String(payload, "UTF-8")}
     |""".stripMargin
  }

  /**
   * Calculated hashed payload header
   */
  lazy val hash: String = {
    val digest = MessageDigest.getInstance(algorithm.toString)
    Base64.rfc2045().encodeToString(digest.digest(normalized.getBytes("UTF-8")), false)
  }
}