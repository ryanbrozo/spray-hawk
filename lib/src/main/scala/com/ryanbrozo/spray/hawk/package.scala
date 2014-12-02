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

package com.ryanbrozo.spray

package object hawk {

  /**
   * Hawk Version
   */
  val HEADER_VERSION = 1

  /**
   * List of supported MAC algorithms. Passed as parameter
   * to javax.crypto.Mac.getInstance()
   */
  object MacAlgorithms extends Enumeration {
    val HmacMD5, HmacSHA1, HmacSHA256 = Value
  }

  /**
   * List of supported hash algorithms. Passed as parameter
   * to java.security.MessageDigest.getInstance()
   */
  object HashAlgorithms extends Enumeration {
    val MD5 = Value("MD5")
    val SHA1 = Value("SHA-1")
    val SHA256 = Value("SHA-256")
  }

  /**
   * Case class representing a principal's Hawk credentials
   *
   * @param id Key identifier
   * @param key Key that will be used for calculating the MAC
   * @param algorithm Specific algorithm for calculating the MAC. Should be
   *                  one of [[com.ryanbrozo.spray.hawk.MacAlgorithms]]
   */
  case class HawkCredentials(id: String, key: String, algorithm: MacAlgorithms.Value)

  /**
   * List of parameters used for calculating MAC of a request
   */
  object HawkParameters extends Enumeration {
    val Method, Uri, Host, Port, Ts, Nonce, Ext, App, Dlg = Value
  }

  type HawkOptions = Map[HawkParameters.Value, String]

}
