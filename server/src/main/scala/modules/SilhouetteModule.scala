package modules


import javax.inject.Named

import com.google.inject.{AbstractModule, Provides}
import com.mohiva.play.silhouette.api._
import com.mohiva.play.silhouette.api.crypto.{Crypter, CrypterAuthenticatorEncoder}
import com.mohiva.play.silhouette.api.util._
import com.mohiva.play.silhouette.api.services.AuthenticatorService
import com.mohiva.play.silhouette.api.repositories.AuthInfoRepository
import com.mohiva.play.silhouette.crypto.{JcaCrypter, JcaCrypterSettings}
import com.mohiva.play.silhouette.persistence.repositories.DelegableAuthInfoRepository
import com.mohiva.play.silhouette.impl.authenticators._
import com.mohiva.play.silhouette.impl.util.{PlayCacheLayer, SecureRandomIDGenerator}
import com.mohiva.play.silhouette.password.BCryptSha256PasswordHasher
import com.mohiva.play.silhouette.persistence.daos.{DelegableAuthInfoDAO, InMemoryAuthInfoDAO}
import play.api.Configuration
import play.api.libs.ws.WSClient
import utils.auth.DefaultEnv
import models.daos._
import models.services._
import play.api.cache._

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.FiniteDuration


/**
  * This class is a Guice module that tells Guice how to bind several
  * different types. This Guice module is created when the Play
  * application starts.
  *
  * Play will automatically use any class called `modules.Module` that is in
  * the root package. You can create modules in other locations by
  * adding `play.modules.enabled` settings to the `application.conf`
  * configuration file.
  */
class SilhouetteModule extends AbstractModule {

  override def configure() = {
    // Create instances of our dependency injected classes
    bind(classOf[Clock]).toInstance(Clock())

    bind(classOf[UserDAO]).to(classOf[UserDAOImpl])
    bind(classOf[UserService]).to(classOf[UserServiceImpl])

    bind(classOf[PasswordHasher]).toInstance( new BCryptSha256PasswordHasher() )

    bind(classOf[IDGenerator]).toInstance(new SecureRandomIDGenerator(128))
    bind(classOf[EventBus]).toInstance(EventBus())

    bind(classOf[CacheLayer]).to(classOf[PlayCacheLayer])

    //bind(classOf[DelegableAuthInfoDAO[PasswordInfo]]).toInstance(new InMemoryAuthInfoDAO[PasswordInfo]())
  }

  /**
    * Provides the HTTP layer implementation.
    *
    * @param client Play's WS client.
    * @return The HTTP layer implementation.
    */
  @Provides
  def provideHTTPLayer(client: WSClient): HTTPLayer = new PlayHTTPLayer(client)

  /**
    * Provides the Password Hasher registry
    *
    * @return PasswordHasher Registry
    */
  @Provides
  def providePasswordHasherRegistry( currentPasswordHasher: PasswordHasher ): PasswordHasherRegistry = {
    PasswordHasherRegistry(
      current = currentPasswordHasher,
      deprecated = Seq()
    )
  }


  /**
    * Provides the Silhouette environment.
    *
    * @param userService The user service implementation.
    * @param authenticatorService The authentication service implementation.
    * @param eventBus The event bus instance.
    * @return The Silhouette environment.
    */
  @Provides
  def provideEnvironment(
    userService: UserService,
    authenticatorService: AuthenticatorService[JWTAuthenticator],
    eventBus: EventBus): Environment[DefaultEnv] = {

    Environment[DefaultEnv](
      userService,
      authenticatorService,
      Seq(),
      eventBus
    )
  }



  /**
    * Provides the authenticator service.
    *
    * @param idGenerator The ID generator implementation.
    * @param configuration The Play configuration.
    * @param clock The clock instance.
    * @return The authenticator service.
    */
  @Provides
  def provideAuthenticatorService(
    @Named("authenticator-crypter") crypter: Crypter,
    idGenerator: IDGenerator,
    configuration: Configuration,
    clock: Clock): AuthenticatorService[JWTAuthenticator] = {


    val configurationPath = "silhouette.authenticator"

    val config = JWTAuthenticatorSettings(
      fieldName = configuration.get[String](s"$configurationPath.headerName"),
      issuerClaim = configuration.get[String](s"$configurationPath.issuerClaim"),
      authenticatorExpiry = configuration.get[FiniteDuration](s"$configurationPath.authenticatorExpiry"),
      sharedSecret = configuration.get[String](s"$configurationPath.sharedSecret")
    )

    val encoder = new CrypterAuthenticatorEncoder(crypter)

    new JWTAuthenticatorService( config, None, encoder, idGenerator, clock)
  }

  /**
    * Provides the crypter for the authenticator.
    *
    * @param configuration The Play configuration.
    * @return The crypter for the authenticator.
    */
  @Provides @Named("authenticator-crypter")
  def provideAuthenticatorCrypter(configuration: Configuration): Crypter = {
    val key = configuration.get[String]("silhouette.authenticator.crypter.key")

    new JcaCrypter(JcaCrypterSettings(key))
  }

  /**
    * Provides the auth info repository.
    *
    * @param passwordInfoDAO The implementation of the delegable password auth info DAO.
    * @return The auth info repository instance.
    */
  @Provides
  def provideAuthInfoRepository(): AuthInfoRepository =
    new DelegableAuthInfoRepository( new InMemoryAuthInfoDAO[PasswordInfo]() )


}
