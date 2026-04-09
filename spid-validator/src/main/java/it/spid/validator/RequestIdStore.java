package it.spid.validator;

public interface RequestIdStore {
  void register(String requestId);

  void consumeOrThrow(String requestId);

  boolean isValid(String requestId);

  int size();
}