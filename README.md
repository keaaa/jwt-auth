# jwt-auth

Simple service that validates and authorize jwt tokens passed in Authorization header. 

Built for Azure AD, and available at docker hub. Contribution to extend to other vendors or provide additional claim validations is encouraged

```
docker run -e API_RESOURCE_ID=c54b474d-8cee-40df-a5c2-b2a4ede61ae7 -p 8080:8080 keaaa/jwt-auth
curl localhost:8080 -i -H "Authorization: Bearer some-valid-jwt-token"

returns HTTP STATUS NOCONTENT if valid
```

Can be used together with nginx and `auth_request`. See [example](example/README.md) 
