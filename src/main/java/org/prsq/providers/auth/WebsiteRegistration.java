package org.prsq.providers.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.lang.StringUtils;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import javax.ws.rs.core.MultivaluedMap;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;


/**
 * @author Serhii Morunov
 */
public class WebsiteRegistration implements FormAction, FormActionFactory {
    private static final String FIELD_SELLER_NAME = "user.attribute.seller_name";
    private static final String FIELD_MARKETPLACE = "user.attribute.marketplace";
    private static String TOKEN_URL = "https://sso.lab.competify.com/auth/realms/pstest/protocol/openid-connect/token";
    private static String FIELD_WEBSITE = "user.attributes.website";
    private static String PRICEDB_HOST = "http://test.pricesquid.com:8080";
    private static String ATTRIBUTE_WEBSITE = "website";
    private static final String PROVIDER_ID = "website-validator";
    private static Requirement[] REQUIREMENT_CHOISES;

    public WebsiteRegistration() {
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

    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOISES;
    }

    public boolean isUserSetupAllowed() {
        return false;
    }

    public void buildPage(FormContext context, LoginFormsProvider form) {
    }

    public void validate(ValidationContext context) {
        MultivaluedMap formData = context.getHttpRequest().getDecodedFormParameters();
        ArrayList errors = new ArrayList();
        String website = (String) formData.getFirst(FIELD_WEBSITE);
        List users = context.getSession().users().searchForUserByUserAttribute(ATTRIBUTE_WEBSITE, this.cleanURL(website), context.getRealm());
        if (errors.size() > 0) {
            context.validationError(formData, errors);
        } else {
            context.success();
        }

    }

    public void success(FormContext context) {
        Random random = new Random();
        int low = 1000;
        int high = 9999;

        UserModel user = context.getUser();
        MultivaluedMap formData = context.getHttpRequest().getDecodedFormParameters();
        String website = this.cleanURL((String) formData.getFirst(FIELD_WEBSITE));

        String sellerName = this.cleanURL((String) formData.getFirst(FIELD_SELLER_NAME));

        String marketplace = this.cleanURL((String) formData.getFirst(FIELD_MARKETPLACE));


        if (!StringUtils.isBlank(website)) {
            user.setSingleAttribute("website", website);
        } else if (!StringUtils.isBlank(sellerName)) {
            user.setSingleAttribute("website", sellerName + "@" + marketplace);
        }

        user.setSingleAttribute("activationCode", Integer.toString(random.nextInt(high - low) + low));
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

    public void init(Scope config) {
    }

    public void postInit(KeycloakSessionFactory factory) {
    }

    public String getId() {
        return "website-validator";
    }

    private String cleanURL(String dirty) {
        return dirty.replaceAll("((https|http):\\/\\/)|www\\.", "").replaceAll("(\\/(.+))$", "");
    }

    public boolean isShopExist(String website) throws IOException {
        System.out.println(website);
        ObjectMapper mapper = new ObjectMapper();
        CloseableHttpClient httpclient = HttpClients.createDefault();
        BasicResponseHandler handler = new BasicResponseHandler();

        ArrayNode filter = mapper.createArrayNode();
        ObjectNode webshopFilter = mapper.createObjectNode();
        webshopFilter.put("field", "webshop");
        webshopFilter.put("op", "EQ");
        webshopFilter.put("value", website);
        filter.add(webshopFilter);
        ObjectNode request = mapper.createObjectNode();
        request.put("filter", filter);
        HttpPost webshopPost = new HttpPost("http://test.pricesquid.com:8080/prsq-app-admin-1.0/rest/1.0/scanProject/list");
        StringEntity entity = new StringEntity(request.toString());
        webshopPost.setEntity(entity);
        webshopPost.setHeader("Accept", "application/json");
        webshopPost.setHeader("Content-type", "application/json");
        webshopPost.setHeader("Authorization", "Bearer " + accessTokenGeneration());
        CloseableHttpResponse webshopResponce = httpclient.execute(webshopPost);
        String webshopBody = (String) handler.handleResponse(webshopResponce);
        ArrayNode webshops = (ArrayNode) mapper.readTree(webshopBody).get("items");
        return webshops.size() > 0;
    }

    static {
        REQUIREMENT_CHOISES = new Requirement[]{Requirement.REQUIRED, Requirement.DISABLED};
        System.out.println("Website validator provider loaded...");
    }

    public String accessTokenGeneration() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        CloseableHttpClient httpclient = HttpClients.createDefault();
        BasicResponseHandler handler = new BasicResponseHandler();
        HttpPost httpPost = new HttpPost("https://sso.lab.competify.com/auth/realms/pstest/protocol/openid-connect/token");
        ArrayList pairs = new ArrayList();
        pairs.add(new BasicNameValuePair("username", "WEBAPI"));
        pairs.add(new BasicNameValuePair("password", "WEBAPI25"));
        pairs.add(new BasicNameValuePair("grant_type", "password"));
        pairs.add(new BasicNameValuePair("client_id", "curl"));
        httpPost.setEntity(new UrlEncodedFormEntity(pairs));
        CloseableHttpResponse response = httpclient.execute(httpPost);
        String body = (String) handler.handleResponse(response);
        JsonNode responceNode = mapper.readTree(body);

        return responceNode.get("access_token").asText();
    }

    /**
     * SellerName validation
     *
     * @param sellerName
     * @return if seller name is unique return true
     */
    public boolean isSellerNameUnique(String sellerName) throws IOException {

        HttpPost httpPost = new HttpPost(PRICEDB_HOST + "/prsq-app-dashboard-2.0/rest/1.0/dashboard/user/seller_name_validation");

        httpPost.setEntity(new StringEntity(sellerName));

        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("Content-type", "application/json");
        httpPost.setHeader("Authorization", "Bearer " + accessTokenGeneration());

        return Boolean.parseBoolean(new BasicResponseHandler().handleResponse(HttpClientBuilder.create().build().execute(httpPost)));
    }

    /**
     * Get all marketplaces
     *
     * @param sellerName
     * @return if seller name is unique return true
     */
    public List<String> getAllMarketplaces(String sellerName) throws IOException {

        HttpGet httpGet = new HttpGet(PRICEDB_HOST + "/prsq-app-dashboard-2.0/rest/1.0/dashboard/marketplaces");

        httpGet.setHeader("Accept", "application/json");
        httpGet.setHeader("Content-type", "application/json");
        httpGet.setHeader("Authorization", "Bearer " + accessTokenGeneration());

        return null;
    }
}
