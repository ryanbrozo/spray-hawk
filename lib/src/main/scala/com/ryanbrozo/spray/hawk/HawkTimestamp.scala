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

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import org.parboiled.common.Base64

/**
 * Class that represents a Hawk timestamp MAC and is used when the server to send timestamp
 * information to the client. The current server timestamp (ts) and its MAC digest (tsm) calculated
 * using the same client credentials are sent when a client tries to authenticate and its timestamp
 * parameter does not fall within the server's allowable window
 *
 * Created by rye on 2/6/15.
 */
private[hawk] case class HawkTimestamp(ts: Long, credentials: HawkUser) {

  /**
   * Normalized string that will be used for calculating the MAC
   */
  private lazy val normalized: String = {
    s"""${HEADER_NAME.toLowerCase}.$HEADER_VERSION.ts
      |$ts
      |""".stripMargin
  }

  /**
   * Calculated MAC
   */
  lazy val mac: String = {
    val mac = Mac.getInstance(credentials.algorithm.hmacAlgo.toString)
    mac.init(new SecretKeySpec(credentials.key.getBytes("UTF-8"), credentials.algorithm.hmacAlgo.toString))
    Base64.rfc2045().encodeToString(mac.doFinal(normalized.getBytes("UTF-8")), false)
  }
}
