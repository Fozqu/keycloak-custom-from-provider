package org.prsq.providers.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.NameValuePair;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.validation.Validation;

import javax.ws.rs.core.MultivaluedMap;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Serhii Morunov
 */
public class WebsiteRegistration implements FormAction, FormActionFactory {

    private static String TOKEN_URL = "https://sso.lab.competify.com/auth/realms/pstest/protocol/openid-connect/token";

    private static String FIELD_WEBSITE = "user.attributes.website";

    private static String ATTRIBUTE_WEBSITE = "website";

    private static final String PROVIDER_ID = "website-validator";

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOISES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };


    static {
        System.out.println("Website validator provider loaded...");
    }

    public String getDisplayType() {
        return "Website Validation";
    }

    public String getReferenceCategory() {
        return null;
    }

    public boolean isConfigurable() {
        return false;
    }

    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOISES;
    }

    public boolean isUserSetupAllowed() {
        return false;
    }

    public void buildPage(FormContext context, LoginFormsProvider form) {

    }

    public void validate(ValidationContext context) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<FormMessage>();
        String website = formData.getFirst(FIELD_WEBSITE);
        List<UserModel> users = context.getSession().users().searchForUserByUserAttribute(ATTRIBUTE_WEBSITE, cleanURL(website), context.getRealm());
        if (users.size() > 0) {
            errors.add(new FormMessage(FIELD_WEBSITE, "User with such website address already exists"));
        }
        try {
            if (isShopExist(cleanURL(website))) {
                errors.add(new FormMessage(FIELD_WEBSITE, "User with such website address already exists"));
            }
        } catch (IOException e) {
            errors.add(new FormMessage(FIELD_WEBSITE, "Error during registration process Please contact support"));
            e.printStackTrace();
        }


        if (errors.size() > 0) {
            context.validationError(formData, errors);
        } else {
            context.success();
        }
    }

    public void success(FormContext context) {
        UserModel user = context.getUser();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String website = cleanURL(formData.getFirst(FIELD_WEBSITE));
        user.setSingleAttribute("website", website);
    }

    public boolean requiresUser() {
        return false;
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    public String getHelpText() {
        return "Validates website field and stores it in user data";
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    public void close() {

    }

    public FormAction create(KeycloakSession session) {
        return this;
    }

    public void init(Config.Scope config) {

    }

    public void postInit(KeycloakSessionFactory factory) {

    }

    public String getId() {
        return PROVIDER_ID;
    }

    private String cleanURL(String dirty) {
        return dirty.replaceAll("((https|http):\\/\\/)|www\\.", "").replaceAll("(\\/(.+))$", "");
    }

    private boolean isShopExist(String website) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        CloseableHttpClient httpclient = HttpClients.createDefault();
        ResponseHandler<String> handler = new BasicResponseHandler();

        HttpPost httpPost = new HttpPost("https://sso.lab.competify.com/auth/realms/pstest/protocol/openid-connect/token");
        List<NameValuePair> pairs = new ArrayList<>();
        pairs.add(new BasicNameValuePair("username", "WEBAPI"));
        pairs.add(new BasicNameValuePair("password", "WEBAPI25"));
        pairs.add(new BasicNameValuePair("grant_type", "password"));
        pairs.add(new BasicNameValuePair("client_id", "curl"));
        httpPost.setEntity(new UrlEncodedFormEntity(pairs));
        CloseableHttpResponse response = httpclient.execute(httpPost);
        String body = handler.handleResponse(response);
        JsonNode responceNode = mapper.readTree(body);
        String acssess_token = responceNode.get("access_token").asText();

        ArrayNode filter = mapper.createArrayNode();
        ObjectNode webshopFilter = mapper.createObjectNode();
        webshopFilter.put("field", "webshop");
        webshopFilter.put("op", "EQ");
        webshopFilter.put("value", website);
        filter.add(webshopFilter);

        ObjectNode request = mapper.createObjectNode();
        request.put("filter", filter);

        HttpPost webshopPost = new HttpPost("http://localhost:8080/prsq-app-admin/rest/1.0/scanProject/list");
        StringEntity entity = new StringEntity(request.toString());
        webshopPost.setEntity(entity);
        webshopPost.setHeader("Accept", "application/json");
        webshopPost.setHeader("Content-type", "application/json");
        webshopPost.setHeader("Authorization", "Bearer " + acssess_token);
        CloseableHttpResponse webshopResponce = httpclient.execute(webshopPost);
        String webshopBody = handler.handleResponse(webshopResponce);
        ArrayNode webshops = (ArrayNode) mapper.readTree(webshopBody).get("items");
        return webshops.size() > 0;
    }
}
