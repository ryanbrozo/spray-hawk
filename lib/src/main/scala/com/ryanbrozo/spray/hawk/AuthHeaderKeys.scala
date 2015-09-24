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

/**
 * List of parameters used in Authorization header supplied in a client request
 */
private[hawk] object AuthHeaderKeys extends Enumeration {
  /**
   * User identifier
   */
  val Id = Value("id")

  /**
   * Current timestamp
   */
  val Ts = Value("ts")

  /**
   * Cryptographic nonce
   */
  val Nonce = Value("nonce")

  /**
   * Application-specific data
   */
  val Ext = Value("ext")

  /**
   * Application Id
   */
  val App = Value("app")

  /**
   * Delegated by application id (Oz), requires App. If payload validation is used, [[Hash]] should be supplied
   */
  val Dlg = Value("dlg")

  /**
   * Computed MAC of the request
   */
  val Mac = Value("mac")

  /**
   * Hash of payload as described [[https://github.com/hueniverse/hawk#payload-validation here]]
   */
  val Hash = Value("hash")
}
