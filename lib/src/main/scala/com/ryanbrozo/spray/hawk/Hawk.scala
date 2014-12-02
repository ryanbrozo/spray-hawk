package com.ryanbrozo.spray.hawk

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import org.parboiled.common.Base64

/**
 * Calculates MAC given the options passed to it
 * *
 * @param options List of parameters to be used for computing the MAC
 *                The following options are mandatory:
 *
 *                Method - HTTP request method (i.e. GET, POST, PUT, etc)
 *                Uri - Request URI
 *                Host - Host name
 *                Port - Port number
 *                Ts - Current timestamp
 *                Nonce - Arbitrary random text
 *
 *                Optional parameters
 *
 *                Ext - Application-specific data
 *                App - Application Id
 *                Dlg - Delegated by application id (Oz), requires App
 *
 *                If payload validation is used, the following options should be
 *                supplied:
 *
 *                Hash - Hash of payload as described [[https://github.com/hueniverse/hawk#payload-validation here]]
 *
 */
case class Hawk(credentials: HawkCredentials, options: HawkOptions) {
  val HEADER_VERSION = 1


  /**
   * Produces the normalized request string
   *
   * @return Normalized string that will be used for calculating the MAC
   */
  lazy val normalized: String = {
    import HawkParameters._

    val appDlg = for (app <- options.get(App); dlg <- options.get(Dlg)) yield s"$app\n$dlg\n"

    s"""hawk.$HEADER_VERSION.header
      |${options.getOrElse(Ts, "")}
      |${options.getOrElse(Nonce, "")}
      |${options.getOrElse(Method, "")}
      |${options.getOrElse(Uri, "")}
      |${options.getOrElse(Host, "")}
      |${options.getOrElse(Port, "")}
      |${options.getOrElse(Hash, "")}
      |${options.getOrElse(Ext, "")}
      |${appDlg.getOrElse("")}""".stripMargin
  }

  /**
   * Calculates the MAC
   *
   * @return MAC string
   */
  lazy val mac: String = {
    val mac = Mac.getInstance(credentials.algorithm.toString)
    mac.init(new SecretKeySpec(credentials.key.getBytes("UTF-8"), credentials.algorithm.toString))
    Base64.rfc2045().encodeToString(mac.doFinal(normalized.getBytes("UTF-8")), false)
  }
}
