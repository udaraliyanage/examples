##### Configure OPA

###### Start OPA

```shell
./opa start --server
```

This will start OPA on port 8181

###### Add OPA policy
```shell
curl -X PUT --data-binary @resources/policies/salary.rego  localhost:8181/v1/policies/authz
```

##### Start Rest API Micro Server

```shell
 mvn spring-boot:run
```

### Test

Alice can access his own salary
```shell
curl alice:pass@localhost:8080/salary/alice
```

Alice can not access Bob's salary

```shell
curl alice:pass@localhost:8080/salary/bob
```

John who is HR can access bob's salary
```shell
curl john:pass@localhost:8080/salary/bob
```

**Relevant article:**  
[Externalized Authorization using Open Policy Agent and Spring Security](https://sultanov.dev/blog/externalized-authorization-using-opa-and-spring-security/)
