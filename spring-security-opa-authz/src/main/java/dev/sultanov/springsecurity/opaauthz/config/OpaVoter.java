package dev.sultanov.springsecurity.opaauthz.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.web.client.RestTemplate;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class OpaVoter implements AccessDecisionVoter<FilterInvocation> {

    private static final String URI = "http://13.212.21.169:8181/v1/data/authz/allow";

    private static final Logger LOG = LoggerFactory.getLogger(OpaVoter.class);

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RestTemplate restTemplate = new RestTemplate();

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    @Override
    public int vote(Authentication authentication, FilterInvocation filterInvocation, Collection<ConfigAttribute> collection) {
        String name = authentication.getName();
        List<String> authorities = getAuthorities(authentication);
        String method = filterInvocation.getRequest().getMethod();
        String[] path = extractPath(filterInvocation);

        Map<String, Object> input = Map.of(
                "name", name,
                "authorities", authorities,
                "method", method,
                "path", path
        );

        JsonNode responseNode = getOPAServerResult(input);

        if (accessGranted(responseNode)) {
            return ACCESS_GRANTED;
        } else {
            return ACCESS_DENIED;
        }
    }

    private String[] extractPath(FilterInvocation filterInvocation) {
        return filterInvocation.getRequest().getRequestURI().replaceAll("^/|/$", "").split("/");
    }

    private List<String> getAuthorities(Authentication authentication) {
        return authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toUnmodifiableList());
    }

    private boolean accessGranted(JsonNode responseNode) {
        return responseNode.has("result") && responseNode.get("result").asBoolean();
    }

    private JsonNode getOPAServerResult(Map<String, Object> input) {
        ObjectNode requestNode = createOpaJson(input);

        LOG.info("Authorization request:\n" + requestNode.toPrettyString());
        JsonNode responseNode = Objects.requireNonNull(restTemplate.postForObject(URI, requestNode, JsonNode.class));
        LOG.info("Authorization response:\n" + responseNode.toPrettyString());
        return responseNode;
    }

    private ObjectNode createOpaJson(Map<String, Object> input) {
        ObjectNode requestNode = objectMapper.createObjectNode();
        requestNode.set("input", objectMapper.valueToTree(input));
        return requestNode;
    }
}
