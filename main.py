import uuid
from fastapi import Depends,FastAPI, HTTPException
from pydantic import BaseModel
from sqlmodel import Field, Session, SQLModel, create_engine, select
from typing import Any, Optional
from datetime import datetime, timedelta, timezone
from fastapi.middleware.cors import CORSMiddleware
from jose import ExpiredSignatureError, JWTError, jwt ## for JWT
import json
#from typing import Union    
####from uuid import uuid4



class Users(SQLModel, table=True):
    userid: str | None = Field(primary_key=True, index=True, unique=True)
    username: str = Field(max_length=50, index=True)
    useremail: Optional[str] = Field(default=None)
    userpass_hashed: Optional[str] = Field(default=None)
    user_createDatetime: Optional[datetime] = Field(default=None)
    user_isActive: int | None = Field(default=1)
    def to_dict(self) -> dict:
        return {
            "userid": self.userid,
            "username": self.username,
            "useremail": self.useremail,
            "userpass_hashed": self.userpass_hashed,
            #"user_createDatetime": self.user_createDatetime.format() if self.user_createDatetime else None,
            "user_createDatetime": self.user_createDatetime.strftime("%Y-%m-%d %H:%M:%S") if self.user_createDatetime else None,
            "user_isActive": self.user_isActive,
        }

class Userrelation(SQLModel, table=True):
    primaryuserid: str | None = Field( index=True)
    relationuserid: str | None = Field( index=True)
    userrelationtype: int | None = Field(default=-1)
    isactive: int | None = Field(default=-1)
    uniqueidentifyer: str | None = Field(primary_key=True, index=True, unique=True)
    relationuserid_ack: int | None = Field(default=-1)



class UserrelationParamsWrapper(BaseModel):
    Userrelation: Userrelation
    name: str| None

class UserrelationWrapperOuter(BaseModel):
    key: str| None
    value: UserrelationParamsWrapper


class MainTasks(SQLModel, table = True):
    userid: str | None = Field(index=True)
    tasktext: str = Field(max_length=300)
    addtocal: int | None = Field(default=-1)
    priority: int | None = Field(default=-1)
    startdatetime: Optional[datetime] = Field(default=None)
    enddatetime: Optional[datetime] = Field(default=None)
    donestatus: int | None = Field(default=-1)
    donestatus_datetime: Optional[datetime] = Field(default=None)
    remarks: Optional[str] = Field(default=None)
    addedby_userid: str | None = Field(max_length = 300, index=True)
    addedby_datetime: Optional[datetime] = Field(default=None)
    uniqueidentifyer: str | None = Field(primary_key=True, index=True, unique=True)
    taskack: int | None = Field(default=-1)
    taskack_datetime: Optional[datetime] = Field(default=None)
    def to_dict(self) -> dict:
        return{
            "userid": self.userid,
            "tasktext": self.tasktext,
            "addtocal": self.addtocal,
            "priority": self.priority,
            "startdatetime":self.startdatetime,
            "enddatetime":self.enddatetime,
            "donestatus":self.donestatus,
            "donestatus_datetime":self.donestatus_datetime,
            "remarks": self.remarks,
            "addedby_userid": self.addedby_userid,
            "addedby_datetime":self.addedby_datetime,
            "uniqueidentifyer": self.uniqueidentifyer,
            "taskack": self.taskack,
            "taskack_datetime": self.taskack_datetime
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MainTasks":
        return cls(
            userid=data.get("userid"),
            tasktext=data.get("tasktext", ""),
            addtocal=data.get("addtocal", -1),
            priority=data.get("priority", -1),
            startdatetime=data.get("startdatetime",None),
            enddatetime=data.get("enddatetime",None),
            donestatus=data.get("donestatus", -1),
            donestatus_datetime=data.get("donestatus_datetime",None),
            remarks=data.get("remarks",""),
            addedby_userid=data.get("addedby_userid",""),
            addedby_datetime=data.get("addedby_datetime",None),
            uniqueidentifyer=data.get("uniqueidentifyer"),
            taskack=data.get("taskack", -1),
            taskack_datetime=data.get("taskack_datetime",None)
        )

class MainTaskParamsWrapper(BaseModel):
    params :MainTasks

class Token(BaseModel): ## for JWT token
    access_token: str
    token_type: str
    tokenCreateDateTime: Optional[datetime] = Field(default=datetime.now())
    username: Optional[str] = Field(default=None)  ## this will be used to store the username in the token
    username_loggedin: Optional[str] = Field(default=None)  ## this is user to verify token , as logged in user name will be here 
    def to_dict(self) -> dict:
        return{
           "access_token" :  self.access_token,
           "token_type" : self.token_type,
           "tokenCreateDateTime" : self.tokenCreateDateTime,
           "username" : self.username,
           "username_loggedin": self.username_loggedin
        }
    
    # def __init__(self,access_token,token_type,tokenCreateDateTime,username,username_loggedin):
    #     self.access_token = access_token            # Instance Variable
    #     self.token_type = token_type  
    #     self.tokenCreateDateTime = tokenCreateDateTime  
    #     self.username = username  
    #     self.username_loggedin = username_loggedin  

     
class UserNToken(BaseModel):
    user : Users
    token: Token
    def to_dict(self) -> dict:
        return {
            "user": self.user.to_dict(),
            "token": self.token.dict()
        }

DATABASE_URL = "mysql+pymysql://admin:RishonAWS50@todolistdbinstance.ctwe626o4i63.us-east-2.rds.amazonaws.com:3306/ToDoListDB"
SECRET_KEY = "your-secret" ## for JWT
ALGORITHM = "HS256" ## for JWT
ACCESS_TOKEN_EXPIRE_MINUTES = 1000 ## for JWT
engine = create_engine(DATABASE_URL, echo=True)
########SQLModel.metadata.create_all(engine)

app = FastAPI()

origins = ["http://127.0.0.1:8000",
           "http://localhost:8000",
           "http://192.168.0.113:8000",
           "http://0.0.0.0:8000",
           "http://frontend:8000"
           ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # Allows all headers
)

@app.get("/hello/")
def read_root(gotIT: str):
    print("inside helopp" )
    print(gotIT )
    return {"message": "Hello, World!"}

## for JWT token
def create_token(username: dict, expires_delta=None): ## we will  use username for token
    print ("creat token called ")
    createdOn = datetime.utcnow()
    to_encode = username.copy()
    expire = createdOn + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    tkn = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    print ("final token ",tkn)
    token =  Token(access_token= tkn,token_type= "bearer",tokenCreateDateTime= createdOn,username= username['sub'],username_loggedin=username['sub'])
    return  token



def verify_token(token: Token):
    try:
        payload = jwt.decode(token.access_token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")  # this is the expiration time of the token
        username = payload.get("sub")  # this is the username for which the token was made
        if exp is None:  # this is unusual, but we will handle it
            print("Missing expiration in token")
            return "Error: Missing expiration in token"
        if datetime.now(timezone.utc).timestamp() > exp:
            print("Token has expired")
            return "Error: Token has expired"
        if (token.username_loggedin != username):
            print("Token username does not match logged in username")
            return "Error: Token username does not match logged in username"
        return "OK"  
    except JWTError:
        print("JWT Error: Invalid token")
        return "Error: JWT error sorry "

@app.get("/isTokenValid/", response_model=Token)
def is_token_valid(token: Token):
    print("isTokenValid called")
    print("passed is ")
    print(token)
    print(token.access_token)
    username = verify_token(token.access_token)
    if not username:
        print("isTokenValid token failed")
        raise HTTPException(401, "Invalid token given")
    else:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")
        if exp is None:
            raise HTTPException(status_code=400, detail="Token missing expiration")
        if datetime.utcnow().timestamp() > exp:
            raise HTTPException(status_code=401, detail="Token has expired")
        return True
        

@app.post("/refreshToken/",response_model=Token)
def refresh(token: Token):
    print("refreshing token")
    print("passed is ")
    print(token)
    print(token.access_token)
    username = verify_token(token.access_token)
    if not username:
        print("refreshToken  token failed")
        raise HTTPException(401, "Invalid token given")
    else:
        new_token = create_token({"sub": username})
        tmpToken = Token(access_token=new_token, token_type="bearer", tokenCreateDateTime=datetime.now(), username=username)
        print(tmpToken)
        print(tmpToken.access_token)
        print("refreshToken  token passed")
        return tmpToken

@app.post("/logInUser/", response_model=Users)
async def logInUser(user: Users):
    if not user.username or not user.userpass_hashed:
        raise HTTPException(status_code=400, detail="Username and password are required")
    else:
        # fetch this record from the database and check if the user name and Password are correct else raise error
        user_exists = await checkifuseridexists(user.username)
        if not user_exists:
            raise HTTPException(status_code=400, detail="User does not exist")
        else:
            isUserAndPasswordMatch = await checkifuserandPasswordmatch(user)
            if not isUserAndPasswordMatch:
                raise HTTPException(status_code=400, detail="Username and password do not match")
            else:
                token_data = {"sub": user.username }
                access_token = create_token(token_data)
                return Token(access_token=access_token, token_type="bearer")



def get_uuid4_as_string():
    return str(uuid.uuid4())


@app.post("/SignUpUser/",response_model=dict)
async def my_root(userNTokenDict : dict[str,Any]):
    print("received")
    print(userNTokenDict )
    user_data = userNTokenDict['params']['user']
    token_data = userNTokenDict['params']['token']
    user1 = Users(**user_data)
    token1 = Token(**token_data)
    usrNtkn = UserNToken(user=user1, token=token1)
    print("after conversion")
    print(usrNtkn )
    #Block 1
    # check if user already exists stating with username
    with Session(engine) as session:
        statement = select(Users).where(Users.username == usrNtkn.user.username)
        results = session.exec(statement).all()
    if len(results) != 0:
        print("user already exists")
        raise HTTPException(401,'User already exists in database')
    #Block 2
    #  add the user to the database
    usrNtkn.user.userid = get_uuid4_as_string()  # generate a new UUID for the user
    with Session(engine) as session:
        session.add(usrNtkn.user)
        session.commit()
        session.refresh(usrNtkn.user)
    #Block 3
    #  generate and store token
    token_data = {"sub": usrNtkn.user.username }
    createDateTime = datetime.now()
    access_token1 = create_token(token_data)
    print("GENERATED TOKEN IS....")
    print(access_token1)
    print("GENERATED TOKEN IS....ABOVE")
    tknn =  Token(access_token=access_token1.access_token, token_type="bearer", tokenCreateDateTime=createDateTime, username=usrNtkn.user.username,username_loggedin=usrNtkn.user.username)       
    usrTkn = UserNToken(user=usrNtkn.user,token=tknn)
    print("all good ")
    print("finally returning ........good")
    print("this is dict ")    
    print("Just beforfe to Dict........................")
    print ( "user is ")
    print(usrNtkn.user)
    print ( "and token is ")
    print(tknn)
    print(usrTkn.to_dict())    
    return usrTkn.to_dict()
   



@app.post("/LogInUserNew1/",response_model=dict)
async def my_root(userNTokenDict : dict[str,Any]):
    print("received")
    print(userNTokenDict )
    user_data = userNTokenDict['params']['user']
    token_data = userNTokenDict['params']['token']
    user1 = Users(**user_data)
    token1 = Token(**token_data)
    usrNtkn = UserNToken(user=user1, token=token1)
    print("after conversion")
    print(usrNtkn )

    with Session(engine) as session:
        statement = select(Users).where(Users.username == usrNtkn.user.username)
        results = session.exec(statement).all()
    if results is None or len(results) == 0:
        print("returnin not found user")
        print(results)
        raise HTTPException(401,'User not found in database')
    ## means user is found in DB
    returnUser = results[0]
    if returnUser.userpass_hashed != usrNtkn.user.userpass_hashed:
        print("password not OK")
        raise HTTPException(status_code=400, detail='password not OK')
        return {"password IS not OK"}
    #3 here i need to verify the token , but insted i simply generate a new token as user has just now logged in 
    token_data = {"sub": usrNtkn.user.username }
    createDateTime = datetime.now()
    access_token1 = create_token(token_data)
    print("GENERATED TOKEN IS....")
    print(access_token1)
    print("GENERATED TOKEN IS....ABOVE")
    tknn =  Token(access_token=access_token1.access_token, token_type="bearer", tokenCreateDateTime=createDateTime, username=returnUser.username,username_loggedin=returnUser.username)       
    usrTkn = UserNToken(user=returnUser,token=tknn)
    print("all good ")
    print("finally returning ........good")
    print("this is dict ")    
    print("Just beforfe to Dict........................")
    print ( "user is ")
    print(usrNtkn.user)
    print ( "and token is ")
    print(tknn)
    print(usrTkn.to_dict())    
    return usrTkn.to_dict()
   



##### Rishon code start here #####
@app.post("/UpdateUserRelations/",response_model=dict)
async def my_root(listToUpdate : list[dict[str, Any]]):
    #print("received")
    for item in listToUpdate:
        print(item)
        #print("item is ", item)
        #print("item['uniqueidentifyer'] is ", item['uniqueidentifyer'])
        #print("item['relationuserid_ack'] is ", item['relationuserid_ack'])
        with Session(engine) as session:
            statement = select(Userrelation).where(Userrelation.uniqueidentifyer == item['uniqueidentifyer'])
            results = session.exec(statement).all()
            if results is None or len(results) == 0:
                print("No record found for unique identifyer", item['uniqueidentifyer'])
                #raise HTTPException(status_code=404, detail="Record not found")
            else:
                toUpdateUserRelation = results[0]
                toUpdateUserRelation.relationuserid_ack = item['relationuserid_ack']
                session.add(toUpdateUserRelation)
                session.commit()
                session.refresh(toUpdateUserRelation)


    #print(listToUpdate[0]['uniqueidentifyer'] )
    #print(listToUpdate[0]['relationuserid_ack'] )
    return {"status": "success", "message": "User relations updated successfully"}




@app.get("/GetRelationsofUserWhoAcnowleged/", response_model=list[UserrelationParamsWrapper])
async def my_root(inputData: str = None):
    print("First line of GetRelationsofUser.................... ")
    print("inputData is ......", inputData)
    receivedDict = json.loads(inputData)
    #print("receivedUserName is ", receivedDict['loggedInUserID'])
    # tempUserRelation  =Userrelation(primaryuserid="rishonqqqqq", relationuserid="empty", userrelationtype=-1, isactive=-1, uniqueidentifyer="empty")
    # arrayOfUserRelations = []
    # arrayOfUserRelations.append(tempUserRelation)
    # return arrayOfUserRelations
    with Session(engine) as session:
        statement = select(Userrelation).where(Userrelation.primaryuserid == receivedDict["loggedInUserID"] and Userrelation.relationuserid_ack == 1)
        results = session.exec(statement).all()
        if results is None or len(results) == 0:
            print("GetRelationsofUser returned no records")
            #raise HTTPException(status_code=404, detail="no relations found")
            return []
        else:
            print("Hurray !!!!")
            print("GetRelationsofUser returned records")
            arrayOfUserRelations = []
            for relation in results:
                #print(relation)
                tempUserRelation  =Userrelation(primaryuserid=relation.primaryuserid, relationuserid=relation.relationuserid, userrelationtype=relation.userrelationtype, isactive=relation.isactive, uniqueidentifyer=relation.uniqueidentifyer, relationuserid_ack=relation.relationuserid_ack)
                arrayOfUserRelations.append(tempUserRelation)
            # code to fill name starts here
            arrURWrapper = []
            for relation in arrayOfUserRelations:
                tempUserRelation  =Userrelation(primaryuserid=relation.primaryuserid, relationuserid=relation.relationuserid, userrelationtype=relation.userrelationtype, isactive=relation.isactive, uniqueidentifyer=relation.uniqueidentifyer, relationuserid_ack=relation.relationuserid_ack)
                tempWrapper = UserrelationParamsWrapper(Userrelation=tempUserRelation, name="")
                usr = await getusergivenID(relation.relationuserid)
                tempWrapper.name = usr.username
                arrURWrapper.append(tempWrapper)
            # code to fill name starts ends here
            # final wrapper
            # arrURWrapper = UserrelationWrapperOuter(key="UserRelations", value=Userrelation
            # outerWrapperArray = []
            # for outerWrapper in arrURWrapper:
            #     outerWrapperObj = UserrelationWrapperOuter(key=get_uuid4_as_string(), value=outerWrapper)
            #     outerWrapperArray.append(outerWrapperObj)
            return arrURWrapper
            



@app.get("/GetRelationsofUser/", response_model=list[UserrelationParamsWrapper])
async def my_root(inputData: str = None):
    print("First line of GetRelationsofUser.................... ")
    print("inputData is ......", inputData)
    receivedDict = json.loads(inputData)
    #print("receivedUserName is ", receivedDict['loggedInUserID'])
    # tempUserRelation  =Userrelation(primaryuserid="rishonqqqqq", relationuserid="empty", userrelationtype=-1, isactive=-1, uniqueidentifyer="empty")
    # arrayOfUserRelations = []
    # arrayOfUserRelations.append(tempUserRelation)
    # return arrayOfUserRelations
    with Session(engine) as session:
        statement = select(Userrelation).where(Userrelation.primaryuserid == receivedDict["loggedInUserID"])
        results = session.exec(statement).all()
        if results is None or len(results) == 0:
            print("GetRelationsofUser returned no records")
            raise HTTPException(status_code=404, detail="no relations found")
        else:
            print("Hurray !!!!")
            print("GetRelationsofUser returned records")
            arrayOfUserRelations = []
            for relation in results:
                #print(relation)
                tempUserRelation  =Userrelation(primaryuserid=relation.primaryuserid, relationuserid=relation.relationuserid, userrelationtype=relation.userrelationtype, isactive=relation.isactive, uniqueidentifyer=relation.uniqueidentifyer, relationuserid_ack=relation.relationuserid_ack)
                arrayOfUserRelations.append(tempUserRelation)
            # code to fill name starts here
            arrURWrapper = []
            for relation in arrayOfUserRelations:
                tempUserRelation  =Userrelation(primaryuserid=relation.primaryuserid, relationuserid=relation.relationuserid, userrelationtype=relation.userrelationtype, isactive=relation.isactive, uniqueidentifyer=relation.uniqueidentifyer, relationuserid_ack=relation.relationuserid_ack)
                tempWrapper = UserrelationParamsWrapper(Userrelation=tempUserRelation, name="")
                usr = await getusergivenID(relation.relationuserid)
                tempWrapper.name = usr.username
                arrURWrapper.append(tempWrapper)
            # code to fill name starts ends here
            # final wrapper
            # arrURWrapper = UserrelationWrapperOuter(key="UserRelations", value=Userrelation
            # outerWrapperArray = []
            # for outerWrapper in arrURWrapper:
            #     outerWrapperObj = UserrelationWrapperOuter(key=get_uuid4_as_string(), value=outerWrapper)
            #     outerWrapperArray.append(outerWrapperObj)
            return arrURWrapper
            
            
            
        

@app.get("/GetUserIDgivenUserName/",response_model= dict[str, Any])
async def my_root( inputData : str = None ):
    #print("inside the function GetUserIDgivenUserName ..........")
    #print("inputData is ......", inputData)
    receivedDict =    json.loads(inputData)
    ##print("receivedDict is ", receivedDict)
    print("receivedUserName is ", receivedDict['relationUserName'])    

    with Session(engine) as session:
        statement = select(Users).where(Users.username == receivedDict["relationUserName"])
        results = session.exec(statement).all()
        if results is None or len(results) == 0:
            print("GetUserIDgivenUserName returned no records")
            raise HTTPException(status_code=404, detail="User not found")
            # return {"userid": "empty", "username": "empty", "useremail": "empty"}
        else:
            print("Hurray !!!!")
            #return {"userid": results[0].userid, "username": results[0].username, "useremail": results[0].useremail}
            with Session(engine) as session:
                statement = select(Userrelation).where(
                    (Userrelation.primaryuserid == receivedDict["loggedInUserID"]) & 
                    (Userrelation.relationuserid == results[0].userid) 
                )
                existing_relations = session.exec(statement).all()
                if existing_relations is None or len(existing_relations) == 0:
                    userRel = Userrelation(
                        primaryuserid=receivedDict["loggedInUserID"], relationuserid=results[0].userid,
                        userrelationtype=3, isactive=1, uniqueidentifyer=get_uuid4_as_string(), relationuserid_ack=-1
                    )
                    with Session(engine) as session:
                        session.add(userRel)
                        session.commit()
                        session.refresh(userRel)
                    print("User relation created successfully")
                    return {"userid": results[0].userid, "username": results[0].username, "useremail": results[0].useremail}
                else:
                    print("User relation already exists")
                    raise HTTPException(status_code=404, detail="User already exists in relation table")



@app.post("/AddTask/", response_model=None)
async def my_root(taskIn: MainTaskParamsWrapper):
    task = taskIn.params
    #print("received task is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", task)
    newRecord =  MainTasks(
        userid=task.userid,
        tasktext=task.tasktext,
        addtocal=task.addtocal,
        priority=task.priority,
        startdatetime=task.startdatetime,
        enddatetime=task.enddatetime,
        donestatus=task.donestatus,
        donestatus_datetime= task.donestatus_datetime,
        remarks=task.remarks,
        addedby_userid=task.addedby_userid,
        addedby_datetime= task.addedby_datetime,
        uniqueidentifyer=get_uuid4_as_string(),
        taskack=task.taskack,
        taskack_datetime= task.taskack_datetime,
    )
    with Session(engine) as session:
        session.add(newRecord)
        session.commit()
        session.refresh(newRecord)
    return None
    # with Session(engine) as session:
    #     findTheRowOfTask = session.exec(select(MainTasks).where(MainTasks.uniqueidentifyer == task.uniqueidentifyer)).first()
    #     if findTheRowOfTask:
    #         findTheRowOfTask.taskack = task.taskack
    #         if task.taskack == 1:   # if task is acknowledged, set the taskack_datetime to now
    #             findTheRowOfTask.taskack_datetime = datetime.now()
    #         else:  # if task is not acknowledged, set the taskack_datetime to None
    #             findTheRowOfTask.taskack_datetime = None
    #         findTheRowOfTask.priority = task.priority
    #         findTheRowOfTask.donestatus = task.donestatus
    #         findTheRowOfTask.startdatetime = task.startdatetime
    #         findTheRowOfTask.enddatetime = task.enddatetime
    #         findTheRowOfTask.remarks = task.remarks
    #         findTheRowOfTask.tasktext = task.tasktext
    #         session.add(findTheRowOfTask)
    #         session.commit()
    #         session.refresh(findTheRowOfTask)
    #         return findTheRowOfTask
    #     else:
    #         raise HTTPException(status_code=404, detail="Task not found")



## RISHOn Method to get ALL TASK Start
@app.post("/UpdateTask/", response_model=MainTasks)
async def my_root(taskIn: MainTaskParamsWrapper):
    task = taskIn.params
    with Session(engine) as session:
        findTheRowOfTask = session.exec(select(MainTasks).where(MainTasks.uniqueidentifyer == task.uniqueidentifyer)).first()
        if findTheRowOfTask:
            findTheRowOfTask.taskack = task.taskack
            if task.taskack == 1:   # if task is acknowledged, set the taskack_datetime to now
                findTheRowOfTask.taskack_datetime = datetime.now()
            else:  # if task is not acknowledged, set the taskack_datetime to None
                findTheRowOfTask.taskack_datetime = None
            findTheRowOfTask.priority = task.priority
            findTheRowOfTask.donestatus = task.donestatus
            findTheRowOfTask.startdatetime = task.startdatetime
            findTheRowOfTask.enddatetime = task.enddatetime
            findTheRowOfTask.remarks = task.remarks
            findTheRowOfTask.tasktext = task.tasktext
            session.add(findTheRowOfTask)
            session.commit()
            session.refresh(findTheRowOfTask)
            return findTheRowOfTask
        else:
            raise HTTPException(status_code=404, detail="Task not found")


@app.post("/markATaskAsDone/",response_model= MainTasks)
async def my_root(taskIn: MainTaskParamsWrapper):
    #print("inside the function markATaskAsDone..........")
    # print("Original inputData dict  ......", type(taskIn))
    #print("Original inputData dict  ......", taskIn.params)
    #print("Original inputData dict  ......", taskIn["params"])
    task = taskIn.params
    #print("formatted task is ", task)
    #print("task.uniqueidentifyer is ", task.uniqueidentifyer)
    with Session(engine) as session:
        findTheRowOfTask = session.exec(select(MainTasks).where(MainTasks.uniqueidentifyer == task.uniqueidentifyer)).first()
        if findTheRowOfTask:
            print("found the task in DB", task.uniqueidentifyer)
            findTheRowOfTask.donestatus = 1
            findTheRowOfTask.donestatus_datetime = datetime.now()
            session.add(findTheRowOfTask)
            session.commit()
            session.refresh(findTheRowOfTask)
            print(f"Task {task.uniqueidentifyer} marked as done.")
            return findTheRowOfTask
        else:
            print(f"Task {task.uniqueidentifyer} not found.")
            raise HTTPException(status_code=404, detail="Task not found")


@app.get("/getalltasksforuser/",response_model=list[MainTasks])
async def my_root( inputData : str = None ):
    print("inside the function ..........")
    print("inputData is ......", inputData)
    parts = inputData.split("||||")
    whichUser = parts[0]
    whichDate = parts[1]
    print("whichUser" , whichUser)
    print("whichDate" , whichDate)
    with Session(engine) as session:
        statement = select(MainTasks).where(
            (MainTasks.userid == whichUser) & 
            (MainTasks.donestatus == 0) & 
            (
                (MainTasks.startdatetime < whichDate) |
                (MainTasks.enddatetime < whichDate)
            )
        ).order_by(MainTasks.priority)
        results = session.exec(statement).all()
        if results is None or len(results) == 0:
            print("getalltasksforuser returned no records")
            return []
        else:
            print("Hurray !!!!")
            return results


# RISHOn Method to get ALL TASK ends
#


@app.get("/getuserdemo/", response_model=Users)
async def my_root(username: str = None):
    with Session(engine) as session:
        statement = select(Users).where(Users.username == username)
        results = session.exec(statement).all()
        if results is None or len(results) == 0:
            print("User not found.........")
            return Users(userid="empty", username="empty", useremail="empty")
        else:
            print("User found.........")
            print(results[0])
            return results[0]

## retuern empty user if not found or filled user if found
@app.get("/CheckifUserExists/")
async def CheckifUserExists(username: str):
     returnUser = Users(userid="", username="", useremail="", userpass_hashed="", user_createDatetime=None, user_isActive=0)
     with Session(engine) as session:
        statement = select(Users).where(Users.username == username)
        results = session.exec(statement).all()
        #print("results are ")
        #print(results)
        if results is None or len(results) == 0:
            print("returnin not found user")
            print(results)
            print(returnUser)
            return returnUser
        else:
            print("returnin found user!!!")
            print(results[0])
            returnUser = results[0]
            print(returnUser)
            return returnUser

##### Rishon end  start here #####


async def checkifuserandPasswordmatch(user: Users):
    # first check if user exists
    user_exists = await checkifuseridexists(user.username)
    if not user_exists:
        return False
    else:
        with Session(engine) as session:
            statement = select(Users).where(Users.username == user.username, Users.userpass_hashed == user.userpass_hashed)
            results = session.exec(statement).all()
            if results is None or len(results) == 0:
                return False
            else:
                return True
            
async def checkifuseridexists(username: str):
    with Session(engine) as session:
        statement = select(Users).where(Users.username == username)
        results = session.exec(statement).all()
        if results is None or len(results) == 0:
            return False
        else:
            return True

async def checkifuseridexists(userid: str):
    with Session(engine) as session:
        statement = select(Users).where(Users.userid == userid)
        results = session.exec(statement).all()
        if results is None or len(results) == 0:
            return False
        else:
            return True

async def getusergivenName(username: str):
    with Session(engine) as session:
        statement = select(Users).where(Users.username == username)
        results = session.exec(statement).all()
        if results is None or len(results) == 0:
            return  Users(userid="empty", username="empty", useremail="empty")
        else:
            return  results[0]

async def getusergivenID(userid: str):
    with Session(engine) as session:
        statement = select(Users).where(Users.userid == userid)
        results = session.exec(statement).all()
        if results is None or len(results) == 0:
            return  Users(userid="empty", username="empty", useremail="empty")
        else:
            return  results[0]


# check if userrelation exists
async def checkifuserrelationexists(ul: Userrelation):
    with Session(engine) as session:
        statement = select(Userrelation).where(
            (Userrelation.primaryuserid == ul.primaryuserid) & 
            (Userrelation.relationuserid == ul.relationuserid)
        )
        results = session.exec(statement).all()
        if results is None or len(results) == 0:
            return False
        else:
            return True

async def checkiftaskexists(task: MainTasks):
    with Session(engine) as session:
        statement = select(MainTasks).where(
            (MainTasks.userid == task.userid) & 
            (MainTasks.priority == task.priority) &
            (MainTasks.startdatetime == task.startdatetime) &
            (MainTasks.enddatetime == task.enddatetime) 
        )
        results = session.exec(statement).all()
        if results is None or len(results) == 0:
            return MainTasks(userid="empty", tasktext="empty", addtocal=-1, priority=-1, startdatetime=None, enddatetime=None, donestatus=-1, donestatus_datetime=None, remarks=None, addedby_userid="empty", addedby_datetime=None, uniqueidentifyer="empty", taskack=-1, taskack_datetime=None)
        else:
            return results[0]

# Create user if not exists
@app.post("/adduser/", response_model=UserNToken)
async def my_root(dbuser:Users):
     print("Add user is executing ")
     # first find is a username already exists
     print("received user is ")
     print(dbuser)
     with Session(engine) as session:
        statement = select(Users).where(Users.username == dbuser.username)
        results = session.exec(statement).all()
        if results is None or  len(results) > 0:
            print("User already exists")
            raise HTTPException(status_code=400, detail="Username already exists")
            ##emptyUser = Users(userid="empty", username="empty", useremail="empty")
            ##return emptyUser
        else:
            print("User does not exist, adding user")
            dbuser.userid = get_uuid4_as_string()
            dbuser.user_createDatetime = datetime.now()
            dbuser.user_isActive = 1
            token_data = {"sub": dbuser.username }
            access_token1 = create_token(token_data)
            with Session(engine) as session:
                    session.add(dbuser)
                    session.commit()
                    session.refresh(dbuser)
            
            tknn =  Token(access_token=access_token1, token_type="bearer", tokenCreateDateTime=dbuser.user_createDatetime , username=dbuser.username,username_loggedin=dbuser.username)       
            urkTkn = UserNToken(dbuser,tknn)
            return urkTkn  
            


@app.post("/getuser/", response_model=Users)
async def my_root(dbuser:Users):
     with Session(engine) as session:
        print("running method with  username as ===" + dbuser.username)
        statement = select(Users).where(Users.username == dbuser.username)
        results = session.exec(statement).all()
        if results is None or  len(results) > 0:
            print("User already exists")
            print(results)
            print(results[0])
            return results[0]
        else:
            raise HTTPException(status_code=400, detail="Username not found")
            emptyUser = Users(userid="empty", username="empty", useremail="empty")
            return emptyUser


# add relation between users
@app.post("/addrelation/", response_model=Userrelation)
async def my_root(listofUser:list[Users], relationType:int):
     # check if the user1 exists
     isUser1Exists = await checkifuseridexists(listofUser[0].userid)
     isUser2Exists = await checkifuseridexists(listofUser[1].userid)
     if isUser1Exists is False or isUser2Exists is False:
        raise HTTPException(status_code=400, detail="One or both users do not exist")
        emptyUserRelation = Userrelation(primaryuserid="empty", relationuserid="empty", userrelationtype=-1, isactive=-1, uniqueidentifyer="empty", relationuserid_ack=-1)
        return emptyUserRelation
     else:
        tempUUID = get_uuid4_as_string()
        toaddUserRelation = Userrelation(
            primaryuserid=listofUser[0].userid, 
            relationuserid=listofUser[1].userid, 
            userrelationtype=relationType, 
            isactive=1, 
            uniqueidentifyer=tempUUID,
            relationuserid_ack=-1
        )
        alreadyExist = await checkifuserrelationexists(toaddUserRelation)
        if alreadyExist is True:
            raise HTTPException(status_code=400, detail="record already exists")
            return toaddUserRelation
        else:
            print("Relation does not exist, adding relation")
            with Session(engine) as session:
                session.add(toaddUserRelation)
                session.commit()
                session.refresh(toaddUserRelation)
                return toaddUserRelation

@app.post("/addtask/", response_model=MainTasks)
async def my_root(task:MainTasks):
        task.uniqueidentifyer = get_uuid4_as_string()
        task.addedby_datetime = datetime.now()
        if task.userid == task.addedby_userid:
            task.ack = 1
            task.taskack_datetime = datetime.now()
        with Session(engine) as session:
            session.add(task)
            session.commit()
            session.refresh(task)
            return task
        
@app.get("/gettask/", response_model=MainTasks)
async def my_root(userid:str):
    with Session(engine) as session:
        statement = select(MainTasks).where(MainTasks.userid == userid)
        results = session.exec(statement).all()
        if results is None or len(results) == 0:
            return MainTasks(userid="empty", tasktext="empty", addtocal=-1, priority=-1, startdatetime=None, enddatetime=None, donestatus=-1, donestatus_datetime=None, remarks=None, addedby_userid="empty", addedby_datetime=None, uniqueidentifyer="empty", taskack=-1, taskack_datetime=None)
        else:
            return results


@app.post("/marktaskasdone/", response_model=MainTasks)
async def my_root(uniqueidentifyer:str):
    with Session(engine) as session:
        statement = select(MainTasks).where(MainTasks.uniqueidentifyer == uniqueidentifyer)
        results = session.exec(statement)
        if results is None or len(results) == 0:
            return  ""
        else:
            toUpdateTask = results.first()
            toUpdateTask.donestatus = 1 
            toUpdateTask.donestatus_datetime = datetime.now()
            session.add(toUpdateTask)
            session.commit()
            session.refresh(toUpdateTask)   
