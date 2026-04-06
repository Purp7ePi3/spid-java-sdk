package it.spid.spring.config;

import it.spid.core.model.SpidConfig;
import it.spid.core.saml.SpidService;
import it.spid.crypto.CertificateLoader;
import it.spid.crypto.XmlSigner;
import it.spid.metadata.IdpRegistry;
import it.spid.validator.RequestIdStore;
import it.spid.validator.SamlResponseValidator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.io.Resource;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@AutoConfiguration
@EnableConfigurationProperties(SpidProperties.class)
@ComponentScan("it.spid.spring.controller")
public class SpidAutoConfiguration {

  private final SpidProperties properties;
  private final ApplicationContext context;

  public SpidAutoConfiguration(SpidProperties properties, ApplicationContext context) {
    this.properties = properties;
    this.context = context;
  }

  @Bean
  @ConditionalOnMissingBean
  public SpidConfig spidConfig() {
    return SpidConfig.builder()
        .entityId(properties.getEntityId())
        .assertionConsumerServiceUrl(properties.getAssertionConsumerServiceUrl())
        .singleLogoutServiceUrl(properties.getSingleLogoutServiceUrl())
        .minimumSpidLevel(properties.getMinimumLevel())
        .certificatePath(properties.getCertificatePath())
        .privateKeyPath(properties.getPrivateKeyPath())
        .signRequests(properties.isSignRequests())
        .build();
  }

  @Bean
  @ConditionalOnMissingBean
  public SpidService spidService(SpidConfig spidConfig) {
    return new SpidService(spidConfig);
  }

  @Bean
  @ConditionalOnMissingBean
  public SamlResponseValidator samlResponseValidator(SpidConfig spidConfig) {
    return new SamlResponseValidator(
        new SamlResponseValidator.ValidationConfig(
            spidConfig.getEntityId(),
            spidConfig.getAssertionConsumerServiceUrl()));
  }

  @Bean
  @ConditionalOnMissingBean
  public RequestIdStore requestIdStore() {
    return new RequestIdStore();
  }

  @Bean
  @ConditionalOnMissingBean
  public IdpRegistry idpRegistry() {
    return new IdpRegistry();
  }

  @Bean
  @ConditionalOnMissingBean
  public XmlSigner xmlSigner() throws Exception {
    Resource certResource = context.getResource(properties.getCertificatePath());
    Resource keyResource = context.getResource(properties.getPrivateKeyPath());

    try (InputStream certStream = certResource.getInputStream();
        InputStream keyStream = keyResource.getInputStream()) {

      X509Certificate cert = CertificateLoader.loadCertificate(certStream);
      PrivateKey privateKey = CertificateLoader.loadPrivateKey(keyStream);

      return new XmlSigner(privateKey, cert);
    }
  }
}