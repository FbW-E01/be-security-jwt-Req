# Sign me up!

Your task is to improve on our example app

1. Improve the /token endpoint to a /login endpoint
  - get a username and password from the request
  - compare to an existing array of user objects (array in app memory, no need for database)
  - return token only if user details are correct
2. Add registration
  - add an endpoint to create a new user
  - username must be unique
  - hash the passwords!!
3. Add environment variables
  - make sure not to commit .env
  - make sure to commit an example .env
  - make the secret, port and token expiration time come from env
4. **BONUS** Create a VERY simple frontend that uses our example app. Use only a single file with basic html+css+javascript and save the JWT to localstorage.
5. **XTRA BONUS** Add a database connection for the users :)