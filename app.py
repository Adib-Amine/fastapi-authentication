from fastapi import Depends, FastAPI , HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import uvicorn
from pydantic import BaseModel
from typing import Optional

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },
}

app = FastAPI()


#the OAuth2PasswordBearer class
#When we create an instance of the OAuth2PasswordBearer class we pass in the tokenUrl parameter
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def fake_hash_password(password: str):
    # This doesn't provide any security at all
    return "fakehashed" + password

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def fake_decode_token(token):
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(fake_users_db, token)
    return user

# get_current_user will receive a token as a str from the sub-dependency oauth2_scheme
# will use a utility function we created,
# that takes a token as a str and returns our Pydantic User model:
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

#get_current_active_user that in turn uses get_current_user as a dependency,
# to get the current_user only if this user is active
async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


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



@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    #We want to get the current_user .
    return current_user










@app.get("/items/")
async def read_items(token: str = Depends(oauth2_scheme)):
    return {"token": token}

if __name__ == '__main__':
    uvicorn.run(app,host='127.0.0.1',port='8000')