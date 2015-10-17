spray-hawk
==========
[![Build Status](https://travis-ci.org/ryanbrozo/spray-hawk.svg)](https://travis-ci.org/ryanbrozo/spray-hawk)

**spray-hawk** is a library that adds [Hawk Authentication](https://github.com/hueniverse/hawk) to [Spray.io](http://spray.io/). 
It can be used for both server-side (via [spray-routing](http://spray.io/documentation/1.2.2/spray-routing/)) 
and client-side (via [spray-client](http://spray.io/documentation/1.2.2/spray-client/)).

Current version is **0.3**. 

### Prerequisites
* Scala 2.11.x
* Spray 1.3.x

### Getting spray-hawk
*spray-hawk* is published to Sonatype OSS and Maven Central. The following example shows how to add a dependency to the latest version to your sbt build definition:

``` scala
libraryDependencies += "com.ryanbrozo" %% "spray-hawk-lib" % "0.3"
```

###Server Usage Example:
``` scala

// Our User model. This needs to extend the HawkUser trait for our UserCredentialsRetriever
// to work
case class User(name: String, key: String, algorithm: HawkHashAlgorithms) extends HawkUser

// Our user credentials retriever. Currently it returns 'Bob' along with his hawk credentials
val userCredentialsRetriever: UserRetriever[User] = { id =>
    Future.successful {
      if (id == "dh37fgj492je") Some(User("Bob", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", HawkHashAlgorithms.HawkSHA256))
      else None
    }
}
  
val hawkAuthenticator = HawkAuthenticator("hawk-test", userCredentialsRetriever)

startServer(interface = "localhost", port = 8080) {
  // Add Server-Authorization header for response payload validation
  withHawkServerAuthHeader(userCredentialsRetriever) {
    path("secured") {
      authenticate(hawkAuthenticator) { user =>
        get {
          complete {
            s"Welcome to spray, ${user.name}!"
          }
        } ~
        post {
          entity(as[String]) { body =>
            complete {
              s"Welcome to spray, ${user.name}! Your post body was: $body"
            }
          }
        }
      }
    }
  }
}
```
###Client Usage Example:

#### GET Request
``` scala
val hawkCreds = HawkCredentials("dh37fgj492je", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", HawkHashAlgorithms.HawkSHA256)

val pipeline =
  addHawkCredentials("hawk-client")(hawkCreds) ~>
  sendReceive ~>
  unmarshal[String]

val responseFuture = pipeline {
  Get("http://localhost:8080/secured")
}

responseFuture onComplete {
  case Success(result) =>
    println(result)
    shutdown()
  case util.Failure(error) =>
    println(s"Cannot retrieve URL: $error")
    shutdown()
}
```

#### POST Request with payload validation
``` scala
val hawkCreds = HawkCredentials("dh37fgj492je", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", HawkHashAlgorithms.HawkSHA256)

val pipeline =
  addHawkCredentials("hawk-client")(hawkCreds, withPayloadValidation = true) ~>
  sendReceive ~>
  unmarshal[String]

val responseFuture = pipeline {
  Post("http://localhost:8080/secured", "Thank you for flying Hawk")
}

responseFuture onComplete {
  case Success(result) =>
    println(result)
    shutdown()
  case util.Failure(error) =>
    println(s"Cannot retrieve URL: $error")
    shutdown()
}
```

### Getting Started
Head towards the [Wiki](https://github.com/ryanbrozo/spray-hawk/wiki) to learn how to use the library inside your project.

### Changelog

#### 0.3
- Initial release

### License

This code is open source software licensed under the [MIT License](http://www.opensource.org/licenses/mit-license.php)


