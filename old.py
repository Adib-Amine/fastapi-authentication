

def fake_hash_password(password: str):
    # This doesn't provide any security at all
    return "fakehashed" + password


def fake_decode_token(token):
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(fake_users_db, token)
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        #Any HTTP (error) status code 401 "UNAUTHORIZED" is supposed to also return a WWW-Authenticate header.
    return user


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    #OAuth2 specifies that when using the "password flow" (that we are using) 
    #the client/user must send a username and password fields as form data ( usrename/password : have to be named like that.)
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    #You should never save plaintext passwords, so, we'll use the password hashing system.
    #If the passwords don't match, we return the same error
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    #The response of the token endpoint must be a JSON object.
    #It should have a token_type. In our case, as we are using "Bearer" tokens.
    return {"access_token": user.username, "token_type": "bearer"}
    #For this simple example, we are going to just be completely insecure and return 
    #the same username as the token