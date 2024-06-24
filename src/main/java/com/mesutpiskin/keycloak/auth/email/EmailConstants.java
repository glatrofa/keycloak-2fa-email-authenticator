package com.mesutpiskin.keycloak.auth.email;

import lombok.experimental.UtilityClass;

@UtilityClass
public class EmailConstants {
	public String CODE = "otp";
	public String CODE_LENGTH = "length";
	public String CODE_TTL = "ttl";
	public int DEFAULT_LENGTH = 6;
	public int DEFAULT_TTL = 300;
  public String CREDENTIAL_TYPE = "Email Otp";
  public String CREDENTIAL_USER_LABEL = "Email OTP"; // credential name
}
