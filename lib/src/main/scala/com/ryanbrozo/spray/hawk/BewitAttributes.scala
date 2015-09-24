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

import com.ryanbrozo.spray.hawk.HawkAuthenticator._
import org.parboiled.common.Base64
import spray.http.HttpRequest

import scala.util._

/**
 * Abstracts access to the bewit query parameter, if present. Given an HttpRequest, this class extracts the
 * bewit query parameter attributes
 *
 * @param request Spray HttpRequest to extract attributes from.
 */
private[hawk] case class BewitAttributes(request: HttpRequest) extends Util {

  private val BEWIT_PARAM = "bewit"

  private lazy val base64BewitOption: Option[String] = request.uri.query.get(BEWIT_PARAM)
  private lazy val bewitArray: Array[String] =
    base64BewitOption
      .map { base64Bewit => new String(Base64.rfc2045().decode(base64Bewit), "UTF-8").split('\\') }
      .getOrElse(Array())

  lazy val id: String = bewitArray(0)
  lazy val exp: Long = bewitArray(1).toLong
  lazy val mac: String = bewitArray(2)
  lazy val ext: String = bewitArray(3)

  /**
   * Determines whether a bewit query parameter is present in the request
   */
  lazy val isPresent: Boolean = base64BewitOption.isDefined

  /**
   * Determines whether request has a valid bewit. Unencrypted bewit should be in the form
   *
   *     0  1   2   3
   *     id\exp\mac\ext
   *
   * All fields should be present
   */
  lazy val isValid: Either[HawkRejection, Boolean] = {
    // Check if bewit can be Base64 decoded
    val t = Try { bewitArray }
    t match {
      case Failure(e) =>
        Left(InvalidBewitEncodingRejection)
      case Success(_) =>
        // Length of bewit array should be exactly 4
        if (bewitArray.length != 4)
          Left(InvalidBewitStructureRejection)
        // Make sure not any of the bewit components are missing
        else if (id.trim == "" || exp.toString.trim == "" || mac.trim == "" || ext.trim == "")
          Left(MissingBewitAttributesRejection)
        else Right(true)
    }
  }

  /**
   * Returns the request's uri without the bewit parameter
   */
  lazy val uriWithoutBewit: String = {
    // Remove bewit parameter
    val newQuery = request.uri.query.filterNot { case (key, _) => key == BEWIT_PARAM}
    extractUriString(request.uri.copy(query = newQuery))
  }
}
