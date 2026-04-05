package it.spid.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import java.security.Security;

@SpringBootApplication
public class ExampleApplication {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public static void main(String[] args) {
    SpringApplication.run(ExampleApplication.class, args);
  }
}