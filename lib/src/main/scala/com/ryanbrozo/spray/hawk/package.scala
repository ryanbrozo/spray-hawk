package com.ryanbrozo.spray

/**
 * package.scala
 *
 * Created by rye on 12/1/14 6:58 PM.
 */
package object hawk {

  /**
   * List of supported MAC algorithms. Passed as parameter
   * to javax.crypto.Mac.getInstance()
   */
  object Algorithms extends Enumeration {
    val HmacMD5, HmacSHA1, HmacSHA256 = Value
  }

  /**
   * Case class representing a principal's Hawk credentials
   *
   * @param key Key that will be used for calculating the MAC
   * @param algorithm Specific algorithm for calculating the MAC. Should be
   *                    one of [[com.ryanbrozo.spray.hawk.Algorithms]]
   */
  case class HawkCredentials(key: String, algorithm: Algorithms.Value)

  /**
   * List of parameters used for calculating MAC of a request
   */
  object HawkParameters extends Enumeration {
    val Method, Uri, Host, Port, Ts, Nonce, Hash, Ext, App, Dlg = Value
  }

  type HawkOptions = Map[HawkParameters.Value, String]

}
