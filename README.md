# jwt-auth

Simple service that validates and authorize jwt tokens passed in Authorization header. 

Built for Azure AD, and available at docker hub

```
docker run -p 8080:8080 keaaa/jwt-auth
curl localhost:8080

```