spray-hawk
==========
[![Build Status](https://travis-ci.org/ryanbrozo/spray-hawk.svg)](https://travis-ci.org/ryanbrozo/spray-hawk)

**spray-hawk** is a library that adds [Hawk Authentication](https://github.com/hueniverse/hawk) to Spray. It can be used for both server (via [spray-routing](http://spray.io/documentation/1.2.2/spray-routing/)) and client side (via [spray-client](http://spray.io/documentation/1.2.2/spray-client/)).

Current Version is **0.2**. Library is considered to be in Alpha and the API is still unstable. However, it is usable, though the current implementation is still lacking some [features](https://github.com/ryanbrozo/spray-hawk#features-to-be-implemented) of the protocol.

####Server Usage Example:
``` scala

// Our User model. This needs to extend the HawkUser trait for our UserCredentialsRetriever
// to work
case class User(name: String, id: String, key: String, algorithm: HawkHashAlgorithms) extends HawkUser

// Our user credentials retriever. Currently it returns 'Bob' along with his hawk credentials
val userCredentialsRetriever: UserRetriever[User] = { id =>
    Future.successful {
      if (id == "dh37fgj492je") Some(User("Bob", id, "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", HawkSHA256))
      else None
    }
}
  
val hawkAuthenticator = HawkAuthenticator("hawk-test", userCredentialsRetriever)

startServer(interface = "localhost", port = 8080) {
    path("secured") {
      authenticate(hawkAuthenticator) { user =>
        get {
          complete {
            s"Welcome to spray, ${user.name}!"
          }
        }
      }
    }
}
```
####Client Usage Example:
``` scala
val hawkCreds = HawkCredentials("dh37fgj492je", "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn", HawkSHA256)

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

####Running the example code
To run the server, you need SBT 0.13.x. Open a terminal window and run the following:
```
$ sbt ";project spray-hawk-server;run"
```
A secured site will be run in `http://localhost:8080/secured`. Opening the link in a web browser should show a `The resource requires authentication, which was not supplied with the request` message, indicating a 401

To run the client, open another terminal window and run the following:
```
$ sbt ";project spray-hawk-client;run"
```
The client will connect to same URL, and you should get a `Welcome to spray, Bob!` message

####Using spray-hawk
(TODO)

####Features to be implemented
* [Replay Protection](https://github.com/ryanbrozo/spray-hawk/issues/1)
* [Response Payload Valdiation](https://github.com/ryanbrozo/spray-hawk/issues/3)
* [Single URI Authorization](https://github.com/ryanbrozo/spray-hawk/issues/4)




