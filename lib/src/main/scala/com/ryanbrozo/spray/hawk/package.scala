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

import scala.concurrent.Future

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
    val HmacSHA1, HmacSHA256 = Value
  }

  /**
   * List of supported hash algorithms. Passed as parameter
   * to java.security.MessageDigest.getInstance()
   */
  object HashAlgorithms extends Enumeration {
    val SHA1 = Value("SHA-1")
    val SHA256 = Value("SHA-256")
  }

  sealed trait HawkHashAlgorithms {
    val hmacAlgo: MacAlgorithms.Value
    val hashAlgo: HashAlgorithms.Value
  }
  case object HawkSHA1 extends HawkHashAlgorithms { val hmacAlgo = MacAlgorithms.HmacSHA1; val hashAlgo = HashAlgorithms.SHA1 }
  case object HawkSHA256 extends HawkHashAlgorithms { val hmacAlgo = MacAlgorithms.HmacSHA256; val hashAlgo = HashAlgorithms.SHA256 }


  /**
   * Trait which represents a user entity with Hawk credentials. Modeled user entities
   * must implement this trait in order for authentication to work
   */
  trait HawkUser {
    val key: String
    val algorithm: HawkHashAlgorithms
  }

  /**
   * Class representing a principal's Hawk credentials
   *
   * @param id Key identifier
   * @param key Key that will be used for calculating the MAC
   * @param algorithm Specific algorithm for calculating the MAC and payload hash. Should be
   *                  one of [[com.ryanbrozo.spray.hawk.HawkHashAlgorithms]]
   */
  case class HawkCredentials(id: String, key: String, algorithm: HawkHashAlgorithms) extends HawkUser

  /**
   * List of parameters used for calculating MAC of a request
   */
  object HawkOptionKeys extends Enumeration {
    val Method, Uri, Host, Port, Ts, Nonce, Hash, Ext, App, Dlg = Value
  }

  /**
   * List of parameters used in Authorization header supplied in a client request
   */
  object HawkAuthKeys extends Enumeration {
    val Id = Value("id")
    val Ts = Value("ts")
    val Nonce = Value("nonce")
    val Ext = Value("ext")
    val App = Value("app")
    val Dlg = Value("dlg")
    val Mac = Value("mac")
    val Hash = Value("hash")
  }

  type HawkOptions = Map[HawkOptionKeys.Value, String]

  type HawkAuthParams = Map[HawkAuthKeys.Value, String]

  /**
   * Represents a function that retrieves a user object of type U
   * given an authenticated Hawk key identifier
   *
   * @tparam U Type of user to be retrieved. Should implement HawkUser trait
   */
  type UserRetriever[U <: HawkUser] = String ⇒ Future[Option[U]]

  /**
   * Timestamp type
   */
  type TimeStamp = Long

  /**
   * Cryptographic Nonce. See this Wikipedia [[http://en.wikipedia.org/wiki/Cryptographic_nonce article]]
   */
  type Nonce = String

  /**
   * App-specific data
   */
  type ExtData = String

  /**
   * Represents a function that retrieves the current time expressed in
   * Unix time
   */
  type TimeStampProvider = () => TimeStamp

  /**
   * Represents a function that generates a random cryptographic nonce
   */
  type NonceProvider = () => Nonce

}
