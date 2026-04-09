package it.spid.spring.config;

import it.spid.spring.RedisRequestIdStore;
import it.spid.validator.RequestIdStore;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;

@AutoConfiguration
@ConditionalOnClass(StringRedisTemplate.class)
public class SpidRedisAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean(RequestIdStore.class)
  public RequestIdStore requestIdStore(StringRedisTemplate redisTemplate) {
    return new RedisRequestIdStore(redisTemplate);
  }
}