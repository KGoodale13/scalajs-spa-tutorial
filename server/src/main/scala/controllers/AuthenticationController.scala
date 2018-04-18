package controllers

import java.util.UUID
import javax.inject.Inject

import com.mohiva.play.silhouette.api.util.{Clock, Credentials, PasswordHasher}
import play.api.mvc._
import com.mohiva.play.silhouette.api._
import com.mohiva.play.silhouette.impl.providers.CredentialsProvider
import play.api.mvc.ControllerComponents
import com.mohiva.play.silhouette.api.exceptions.ProviderException
import com.mohiva.play.silhouette.api.repositories.AuthInfoRepository
import com.mohiva.play.silhouette.impl.exceptions.IdentityNotFoundException
import forms.{SignInForm, SignUpForm}
import models.User
import models.services.UserService
import play.api.Configuration
import play.api.libs.json._
import play.api.libs.functional.syntax._
import utils.auth.DefaultEnv

import scala.concurrent.{ExecutionContext, Future}


class AuthenticationController @Inject() (
  cc: ControllerComponents,
  silhouette: SilhouetteProvider[DefaultEnv],
  userService: UserService,
  authInfoRepository: AuthInfoRepository,
  passwordHasher: PasswordHasher,
  credentialsProvider: CredentialsProvider,
  configuration: Configuration,
  clock: Clock
)( implicit ec: ExecutionContext )
  extends AbstractController(cc) {


  /**
    * Converts the JSON into a `SignInForm.Data` object.
    */
  implicit val dataReads = (
    (__ \ 'email).read[String] and
    (__ \ 'password).read[String] and
    (__ \ 'rememberMe).read[Boolean]
    )(SignInForm.Data.apply _)


  /**
    * Handles the submitted JSON data.
    *
    * @return The result to display.
    */
  def signIn = Action.async(parse.json) { implicit request =>
    request.body.validate[SignInForm.Data].map { data =>
      credentialsProvider.authenticate(Credentials(data.email, data.password)).flatMap { loginInfo =>
        userService.retrieve(loginInfo).flatMap {
          case Some(user) => silhouette.env.authenticatorService.create(loginInfo).flatMap { authenticator =>
              silhouette.env.authenticatorService.init(authenticator).flatMap { cookie =>
              silhouette.env.authenticatorService.embed( cookie, Ok("OK") )
            }
          }
          case None => Future.failed(new IdentityNotFoundException("Couldn't find user"))
        }
      }.recover {
        case e: ProviderException =>
          Unauthorized(Json.obj("message" -> "invalid credentials"))
      }
    }.recoverTotal {
      case error =>
        Future.successful(Unauthorized(Json.obj("message" -> "invalid credentials")))
    }
  }

  /**
    * Handles the submitted JSON data.
    *
    * @return The result to display.
    */
  def signUp = Action.async(parse.json) { implicit request =>
    request.body.validate[SignUpForm.Data].map { data =>
      val loginInfo = LoginInfo(CredentialsProvider.ID, data.email)
      userService.retrieve(loginInfo).flatMap {
        case Some(user) =>
          Future.successful(BadRequest(Json.obj("message" -> "user exists")))
        case None =>
          val authInfo = passwordHasher.hash(data.password)
          val user = User(
            userID = UUID.randomUUID(),
            loginInfo = loginInfo,
            firstName = Some(data.firstName),
            lastName = Some(data.lastName),
            fullName = Some(data.firstName + " " + data.lastName),
            email = Some(data.email),
            avatarURL = None
          )
          for {
            user <- userService.save(user)
            authInfo <- authInfoRepository.add(loginInfo, authInfo)
            authenticator <- silhouette.env.authenticatorService.create(loginInfo)
            cookie <- silhouette.env.authenticatorService.init(authenticator)
            result <- silhouette.env.authenticatorService.embed( cookie, Ok("OK") )
          } yield result
      }
    }.recoverTotal {
      case error =>
        Future.successful(Unauthorized(Json.obj("message" -> "invalid.data")))
    }
  }

  /**
    * Manages the sign out action.
    */
  def signOut = silhouette.SecuredAction.async { implicit request =>
    silhouette.env.authenticatorService.discard(request.authenticator, Ok)
  }

}
