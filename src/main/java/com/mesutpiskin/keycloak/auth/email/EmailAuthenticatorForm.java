package com.mesutpiskin.keycloak.auth.email;

import lombok.extern.jbosslog.JBossLog;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Logger;

@JBossLog
public class EmailAuthenticatorForm extends AbstractDirectGrantAuthenticator {
  private final KeycloakSession session;
  private static final Logger logger = Logger.getLogger(EmailAuthenticatorForm.class.getName());
  // private static final String EMAIL_DIRECT_GRANT_CODE = "otp";
  private static final String PROVIDER_ID = "direct-grant-validate-email-otp";
  private String generatedOtp = ""; // TODO: remove

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = new AuthenticationExecutionModel.Requirement[] {
      AuthenticationExecutionModel.Requirement.REQUIRED
  };

  public EmailAuthenticatorForm(KeycloakSession session) {
    this.session = session;
  }

  private boolean isStringNull(String s) {
    if (s == null || s.isEmpty()) {
      return true;
    }

    return false;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    // TODO Auto-generated method stub
    // throw new UnsupportedOperationException("Unimplemented method
    // 'authenticate'");
    MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();

    String otp = inputData.getFirst(EmailConstants.CODE);

    if (this.isStringNull(otp)) {
      if (context.getUser() != null) {
        context.getEvent().user(context.getUser());
      } // TODO: else to discriminate user missing and otp missing
      context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
      Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant",
          "Invalid user credentials, missing email otp code.");
      context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);

      this.generateAndSendEmailCode(context);

      return;
    } else {
      this.authenticateUser(context, otp);
    }
    // MultivaluedMap<String, String> formData =
    // context.getHttpRequest().getDecodedFormParameters();
    // if (formData.containsKey("resend")) {
    // resetEmailCode(context);
    // // challenge(context, null);
    // return;
    // }

    // if (formData.containsKey("cancel")) {
    // resetEmailCode(context);
    // context.resetFlow();
    // return;
    // }
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
    // return getCredentialProvider(session).isConfiguredFor(realm, user);
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "Buffetti email OTP";
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getHelpText() {
    return "Validates the Buffetti one time password supplied as a 'otp' form parameter in direct grant request";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return new LinkedList<>();
  }

  public OTPCredentialProvider getCredentialProvider(KeycloakSession session) {
    return (OTPCredentialProvider) session.getProvider(CredentialProvider.class, "buffetti-email-otp");
  }

  private void generateAndSendEmailCode(AuthenticationFlowContext context) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    AuthenticationSessionModel session = context.getAuthenticationSession();

    if (session.getAuthNote(EmailConstants.CODE) != null) {
      // skip sending email code
      return;
    }

    int length = EmailConstants.DEFAULT_LENGTH;
    int ttl = EmailConstants.DEFAULT_TTL;
    if (config != null) {
      // get config values
      length = Integer.parseInt(config.getConfig().get(EmailConstants.CODE_LENGTH));
      ttl = Integer.parseInt(config.getConfig().get(EmailConstants.CODE_TTL));
    }

    String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
    sendEmailWithCode(context.getRealm(), context.getUser(), code, ttl);
    session.setAuthNote(EmailConstants.CODE, code);
    logger.info("Set authNote: " + code);
    session.setAuthNote(EmailConstants.CODE_TTL, Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

    CredentialModel otpCredential = new CredentialModel();
    otpCredential.setId(UUID.randomUUID().toString());
    // otpCredential.setId(context.getUser().getId() + "email_otp");
    otpCredential.setType(EmailConstants.CREDENTIAL_TYPE);
    otpCredential.setUserLabel(EmailConstants.CREDENTIAL_USER_LABEL);
    otpCredential.setCreatedDate(new java.util.Date().getTime());
    otpCredential.setSecretData(code);
    otpCredential.setCredentialData(Long.toString(System.currentTimeMillis() + (ttl * 1000L)));
    // otpCredential.setCredentialData(String.valueOf(ttl));
    context.getUser().credentialManager().createStoredCredential(otpCredential);

    this.generatedOtp = code;
  }

  private void authenticateUser(AuthenticationFlowContext context, String otp) {
    AuthenticationSessionModel session = context.getAuthenticationSession();
    String code = session.getAuthNote(EmailConstants.CODE);
    String ttl = session.getAuthNote(EmailConstants.CODE_TTL);
    logger.info("OTP sent by user: " + otp + " OTP generated by authenticator: " + code + " TTL saved in notes: " + ttl
        + " generatedOtp: " + this.generatedOtp);

    code = context.getUser().credentialManager()
        .getStoredCredentialByNameAndType(EmailConstants.CREDENTIAL_USER_LABEL, EmailConstants.CREDENTIAL_TYPE)
        .getSecretData();
    ttl = context.getUser().credentialManager()
        .getStoredCredentialByNameAndType(EmailConstants.CREDENTIAL_USER_LABEL, EmailConstants.CREDENTIAL_TYPE)
        .getCredentialData();
    logger.info("Saved credentials: " + code + " ttl: " + ttl);

    if (otp.equals(code)) {
      if (Long.parseLong(ttl) < System.currentTimeMillis()) {
        // expired
        context.getEvent().user(context.getUser());
        context.getEvent().error(Errors.EXPIRED_CODE);
        Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
            Messages.EXPIRED_ACTION_TOKEN_SESSION_EXISTS,
            "Expired otp code.");
        context.failure(AuthenticationFlowError.EXPIRED_CODE, challengeResponse);
      } else {
        // valid
        resetEmailCode(context);
        context.success();
      }
    } else {
      // invalid
      this.generatedOtp = "";
      AuthenticationExecutionModel execution = context.getExecution();
      if (execution.isRequired()) {
        context.getEvent().user(context.getUser());
        context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
        Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
            Messages.INVALID_ACCESS_CODE,
            "Invalid otp code.");
        context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, challengeResponse);
      } else if (execution.isConditional() || execution.isAlternative()) {
        context.attempted();
      }
    }
  }

  private void resetEmailCode(AuthenticationFlowContext context) {
    context.getAuthenticationSession().removeAuthNote(EmailConstants.CODE);
    this.generatedOtp = "";
  }

  private void sendEmailWithCode(RealmModel realm, UserModel user, String code, int ttl) {
    if (user.getEmail() == null) {
      log.warnf("Could not send access code email due to missing email. realm=%s user=%s", realm.getId(),
          user.getUsername());
      throw new AuthenticationFlowException(AuthenticationFlowError.INVALID_USER);
    }

    Map<String, Object> mailBodyAttributes = new HashMap<>();
    mailBodyAttributes.put("username", user.getUsername());
    mailBodyAttributes.put("code", code);
    mailBodyAttributes.put("ttl", ttl);

    String realmName = realm.getDisplayName() != null ? realm.getDisplayName() : realm.getName();
    List<Object> subjectParams = List.of(realmName);
    try {
      EmailTemplateProvider emailProvider = session.getProvider(EmailTemplateProvider.class);
      emailProvider.setRealm(realm);
      emailProvider.setUser(user);
      // Don't forget to add the welcome-email.ftl (html and text) template to your
      // theme.
      emailProvider.send("emailCodeSubject", subjectParams, "code-email.ftl", mailBodyAttributes);
    } catch (EmailException eex) {
      log.errorf(eex, "Failed to send access code email. realm=%s user=%s", realm.getId(), user.getUsername());
    }
  }
}
