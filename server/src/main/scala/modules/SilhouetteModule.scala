package modules


import javax.inject.Named

import com.google.inject.{AbstractModule, Provides}
import com.mohiva.play.silhouette.api._
import com.mohiva.play.silhouette.api.crypto.{Crypter, CrypterAuthenticatorEncoder, Signer}
import com.mohiva.play.silhouette.api.util._
import com.mohiva.play.silhouette.api.services.AuthenticatorService
import com.mohiva.play.silhouette.api.repositories.AuthInfoRepository
import com.mohiva.play.silhouette.crypto.{JcaCrypter, JcaCrypterSettings, JcaSigner, JcaSignerSettings}
import com.mohiva.play.silhouette.persistence.repositories.DelegableAuthInfoRepository
import com.mohiva.play.silhouette.impl.authenticators._
import com.mohiva.play.silhouette.impl.util.{DefaultFingerprintGenerator, PlayCacheLayer, SecureRandomIDGenerator}
import com.mohiva.play.silhouette.password.BCryptSha256PasswordHasher
import com.mohiva.play.silhouette.persistence.daos.{DelegableAuthInfoDAO, InMemoryAuthInfoDAO}
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ArbitraryTypeReader._
import play.api.Configuration
import play.api.libs.ws.WSClient
import utils.auth.DefaultEnv
import models.daos._
import models.services._
import play.api.mvc.CookieHeaderEncoding

import scala.concurrent.ExecutionContext.Implicits.global



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
    bind(classOf[FingerprintGenerator]).toInstance(new DefaultFingerprintGenerator(false))
    bind(classOf[IDGenerator]).toInstance(new SecureRandomIDGenerator(128))
    bind(classOf[EventBus]).toInstance(EventBus())
    bind(classOf[CacheLayer]).to(classOf[PlayCacheLayer])

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
    authenticatorService: AuthenticatorService[CookieAuthenticator],
    eventBus: EventBus): Environment[DefaultEnv] = {

    Environment[DefaultEnv](
      userService,
      authenticatorService,
      Seq(),
      eventBus
    )
  }



  @Provides
  def provideAuthenticatorService(
   @Named("authenticator-signer") signer: Signer,
   @Named("authenticator-crypter") crypter: Crypter,
   cookieHeaderEncoding: CookieHeaderEncoding,
   fingerprintGenerator: FingerprintGenerator,
   idGenerator: IDGenerator,
   configuration: Configuration,
   clock: Clock) : AuthenticatorService[CookieAuthenticator] = {

    val config = CookieAuthenticatorSettings("silhouette.authenticator")
    val authenticatorEncoder = new CrypterAuthenticatorEncoder(crypter)

    new CookieAuthenticatorService(config, None, signer, cookieHeaderEncoding, authenticatorEncoder, fingerprintGenerator, idGenerator, clock)
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

  // Signer for our cookie authenticator
    @Provides @Named("authenticator-signer")
    def provideAuthenticatorSigner(configuration: Configuration): Signer = {
    val config = configuration.underlying.as[JcaSignerSettings]("silhouette.authenticator.signer")
    new JcaSigner(config)
  }

  /**
    * Provides the auth info repository.
    *
    * @return The auth info repository instance.
    */
  @Provides
  def provideAuthInfoRepository(): AuthInfoRepository =
    new DelegableAuthInfoRepository( new InMemoryAuthInfoDAO[PasswordInfo]() )


}
